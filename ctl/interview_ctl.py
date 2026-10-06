#!/usr/bin/env python3
"""Interview stack controller — the only process on the host with Docker access.

Runs as root under systemd (interview-ctl.service) and listens on the unix socket
/run/interview-ctl/ctl.sock (root:ivadmin 0660). The admin web app runs in an unprivileged
container without the Docker socket; this socket is its only way to touch the host, and it
accepts exactly these requests (one JSON object per connection):

  {"verb": "up", "site_url": "https://<host>/m/<token>/",
   "ch_loader_password": "<32 hex>", "ch_metabase_password": "<32 hex>"}
  {"verb": "down", "wipe": false}
  {"verb": "ps"}
  {"verb": "stats"}
  {"verb": "logs", "service": "clickhouse" | "metabase" | "metabase-db"}

Everything else is refused. Parameters are validated by regex; nothing from a request reaches a
shell. Before every start the controller makes sure the stack network exists and that its
firewall rules are in place: containers on br-interview can talk to each other and answer
connections, but cannot open new connections anywhere else (no internet, no host services,
no cloud metadata endpoint).
"""
import grp
import json
import os
import re
import secrets
import socket
import socketserver
import subprocess
import threading

HOME = "/opt/interview"
CTL = f"{HOME}/ctl"
SOCK_DIR = "/run/interview-ctl"
SOCK = f"{SOCK_DIR}/ctl.sock"
ADMIN_GROUP = "ivadmin"
PROJECT = "interview"
NETWORK = "interview_net"
BRIDGE = "br-interview"
SUBNET = "172.30.77.0/24"
SERVICES = ("clickhouse", "metabase", "metabase-db")
SITE_URL = re.compile(r"^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/m/[A-Za-z0-9_-]{16,64}/$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")
MAX_REQUEST = 4096
LOCK = threading.Lock()


def run(cmd, timeout=900, check=True):
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and res.returncode:
        raise RuntimeError((res.stderr or res.stdout).strip()[-2000:])
    return res


def pg_password():
    path = f"{CTL}/pg_password"
    if not os.path.exists(path):
        old = os.umask(0o077)
        with open(path, "w") as f:
            f.write(secrets.token_hex(16))
        os.umask(old)
    return open(path).read().strip()


def write_env(site_url="https://localhost/m/stopped-stopped-stopped/", loader="0" * 32, metabase="0" * 32):
    old = os.umask(0o077)
    with open(f"{CTL}/stack.env", "w") as f:
        f.write(f"PG_PASSWORD={pg_password()}\nCH_LOADER_PASSWORD={loader}\n"
                f"CH_METABASE_PASSWORD={metabase}\nMB_SITE_URL={site_url}\n")
    os.umask(old)


def compose(*args, timeout=900):
    if not os.path.exists(f"{CTL}/stack.env"):
        write_env()
    return run(["docker", "compose", "-p", PROJECT, "-f", f"{HOME}/compose.yml",
                "--env-file", f"{CTL}/stack.env", *args], timeout=timeout).stdout


def ensure_network():
    if not run(["docker", "network", "ls", "-q", "--filter", f"name=^{NETWORK}$"]).stdout.strip():
        run(["docker", "network", "create", "--driver", "bridge", "--subnet", SUBNET,
             "-o", f"com.docker.network.bridge.name={BRIDGE}", NETWORK])


FIREWALL = [
    # (chain, rule) — listed top to bottom as they must end up in the chain
    ("DOCKER-USER", ["-i", BRIDGE, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "RETURN"]),
    ("DOCKER-USER", ["-i", BRIDGE, "!", "-o", BRIDGE, "-j", "DROP"]),
    ("INPUT", ["-i", BRIDGE, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]),
    ("INPUT", ["-i", BRIDGE, "-j", "DROP"]),
]


def ensure_firewall():
    for chain in ("DOCKER-USER", "INPUT"):
        rules = [r for c, r in FIREWALL if c == chain]
        present = all(run(["iptables", "-C", chain, *r], check=False).returncode == 0 for r in rules)
        if present:
            continue
        for r in rules:
            while run(["iptables", "-C", chain, *r], check=False).returncode == 0:
                run(["iptables", "-D", chain, *r])
        for r in reversed(rules):
            run(["iptables", "-I", chain, "1", *r])


def ps():
    out = compose("ps", "-a", "--format", "json", timeout=30).strip()
    if not out:
        return []
    items = json.loads(out) if out.startswith("[") else [json.loads(l) for l in out.splitlines() if l.strip()]
    return [{"name": i.get("Name"), "service": i.get("Service"), "state": i.get("State"),
             "status": i.get("Status")} for i in items]


def handle(req):
    verb = req.get("verb")
    if verb == "up":
        site, loader, mbpw = req.get("site_url", ""), req.get("ch_loader_password", ""), req.get("ch_metabase_password", "")
        if not (isinstance(site, str) and SITE_URL.match(site) and HEX32.match(str(loader)) and HEX32.match(str(mbpw))):
            raise ValueError("bad parameters")
        with LOCK:
            write_env(site, loader, mbpw)
            ensure_network()
            ensure_firewall()
            compose("up", "-d", "--remove-orphans")
        return {}
    if verb == "down":
        with LOCK:
            compose("down", "--remove-orphans", *(["-v"] if req.get("wipe") is True else []), timeout=300)
        return {}
    if verb == "ps":
        return {"containers": ps()}
    if verb == "stats":
        names = [c["name"] for c in ps() if c["state"] == "running"]
        data = []
        if names:
            out = run(["docker", "stats", "--no-stream", "--format", "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}", *names],
                      timeout=30, check=False).stdout
            for line in out.splitlines():
                parts = line.split("\t")
                if len(parts) == 3:
                    data.append({"name": parts[0], "cpu": parts[1], "mem": parts[2]})
        return {"stats": data}
    if verb == "logs":
        service = req.get("service")
        if service not in SERVICES:
            raise ValueError("bad service")
        res = run(["docker", "logs", "--tail", "15", f"{PROJECT}-{service}-1"], timeout=30, check=False)
        return {"logs": (res.stdout + res.stderr)[-4000:]}
    raise ValueError("unknown verb")


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        raw = self.rfile.readline(MAX_REQUEST + 1)
        try:
            if len(raw) > MAX_REQUEST:
                raise ValueError("request too large")
            req = json.loads(raw)
            if not isinstance(req, dict):
                raise ValueError("bad request")
            reply = {"ok": True, **handle(req)}
        except Exception as exc:  # the message goes back to the admin UI
            reply = {"ok": False, "error": str(exc)[:2000]}
        self.wfile.write(json.dumps(reply).encode() + b"\n")


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main():
    os.makedirs(CTL, mode=0o700, exist_ok=True)
    gid = grp.getgrnam(ADMIN_GROUP).gr_gid
    os.chown(SOCK_DIR, 0, gid)
    os.chmod(SOCK_DIR, 0o750)
    if os.path.exists(SOCK):
        os.unlink(SOCK)
    try:
        ensure_network()
        ensure_firewall()
    except Exception as exc:
        print(f"startup network/firewall setup failed: {exc}", flush=True)
    server = Server(SOCK, Handler)
    os.chown(SOCK, 0, gid)
    os.chmod(SOCK, 0o660)
    server.serve_forever()


if __name__ == "__main__":
    main()
