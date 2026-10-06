"""Interview stack admin.

One small web app behind nginx at /iv-admin/ (own login) that
  * starts / stops the ClickHouse + Metabase stack (`docker compose -p interview`),
    with a fresh random Metabase URL /m/<token>/ on every start and an auto-stop timer;
  * loads CSV/TSV files (upload or URL) into ClickHouse tables, schema inferred by
    ClickHouse or given explicitly;
  * issues Metabase users with random login/password for candidates;
  * keeps interview samples (tables + candidate task + interviewer readme) on disk and loads
    them on start; the active sample's task is a public page /iv-task/<token>/.

Metabase is set up automatically on first start (admin user + the ClickHouse connection),
so a fresh user can query the `interview` database right away.

nginx asks GET /_internal/mbcheck (not proxied from outside) whether /m/<token>/ is current.
State lives in $IV_HOME/state (root-only); nothing is logged to files.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import shutil
import string
import subprocess
import threading
import time
from pathlib import Path
from urllib.parse import quote, urlsplit

import httpx
from fastapi import FastAPI, File, Form, Request, UploadFile
import markdown
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.concurrency import run_in_threadpool

HOME = Path(os.environ.get("IV_HOME", "/opt/interview"))
STATE = HOME / "state"
UPLOADS = HOME / "uploads"
SAMPLES = HOME / "samples"
PUBLIC_BASE = os.environ.get("IV_PUBLIC_BASE", "").rstrip("/")
ADMIN_USER = os.environ.get("IV_ADMIN_USER", "admin")
ADMIN_HASH = os.environ["IV_ADMIN_HASH"]

P = "/iv-admin"
PROJECT = "interview"
CH_URL = "http://127.0.0.1:18123"
MB_URL = "http://127.0.0.1:13000"
CH_DB = "interview"
MB_DB_NAME = "Interview ClickHouse"
USER_DOMAIN = "interview.local"
SESSION_TTL = 12 * 3600
MAX_URL_DOWNLOAD = 2 * 1024**3
UPLOAD_KEEP_S = 24 * 3600
AUTO_STOP_CHOICES = {"2": "2 h", "4": "4 h", "8": "8 h", "24": "24 h", "0": "never"}
FORMATS = {
    "CSVWithNames": "CSV, first row is the header",
    "CSV": "CSV, no header",
    "TSVWithNames": "TSV, first row is the header",
    "TSV": "TSV, no header",
}
DELIMS = {",": "comma  ,", ";": "semicolon  ;", "|": "pipe  |"}
IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
UID = re.compile(r"^[0-9a-f]{32}$")
KEEP_SUFFIXES = (".gz", ".zst", ".bz2", ".xz", ".lz4")

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
LOCK = threading.RLock()
SESSIONS: dict[str, float] = {}
FAILS: dict[str, list[float]] = {}
MB_SESSION: dict[str, str] = {}
STATS_CACHE: dict[str, object] = {"at": 0.0, "data": []}


# ---------------------------------------------------------------- state files

def jload(name: str, default):
    try:
        return json.loads((STATE / name).read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def jsave(name: str, data) -> None:
    path = STATE / name
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1))
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def secrets_cfg() -> dict:
    with LOCK:
        cfg = jload("secrets.json", None)
        if not cfg:
            cfg = {k: secrets.token_hex(16) for k in ("pg_password", "ch_loader_password", "ch_metabase_password")}
            jsave("secrets.json", cfg)
        return cfg


STACK: dict = jload("stack.json", {"phase": "stopped", "message": "", "token": None, "auto_stop_at": None})


def set_stack(**kw) -> None:
    with LOCK:
        STACK.update(kw)
        STACK["updated"] = time.time()
        jsave("stack.json", STACK)


def gen_password(n: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(n))
        if any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw):
            return pw


def metabase_url() -> str | None:
    tok = STACK.get("token")
    return f"{PUBLIC_BASE}/m/{tok}/" if tok else None


# ---------------------------------------------------------------- docker compose

def write_env(token: str | None) -> None:
    cfg = secrets_cfg()
    site = f"{PUBLIC_BASE}/m/{token}/" if token else f"{PUBLIC_BASE}/m/stopped/"
    path = STATE / "stack.env"
    path.write_text(
        f"PG_PASSWORD={cfg['pg_password']}\n"
        f"CH_LOADER_PASSWORD={cfg['ch_loader_password']}\n"
        f"CH_METABASE_PASSWORD={cfg['ch_metabase_password']}\n"
        f"MB_SITE_URL={site}\n"
    )
    os.chmod(path, 0o600)


def compose(*args: str, timeout: int = 900) -> str:
    if not (STATE / "stack.env").exists():
        write_env(STACK.get("token"))
    cmd = ["docker", "compose", "-p", PROJECT, "-f", str(HOME / "compose.yml"),
           "--env-file", str(STATE / "stack.env"), *args]
    res = subprocess.run(cmd, cwd=HOME, capture_output=True, text=True, timeout=timeout)
    if res.returncode:
        raise RuntimeError((res.stderr or res.stdout).strip()[-2000:])
    return res.stdout


def containers() -> list[dict]:
    try:
        out = compose("ps", "-a", "--format", "json", timeout=30).strip()
    except Exception:
        return []
    if not out:
        return []
    items = json.loads(out) if out.startswith("[") else [json.loads(l) for l in out.splitlines() if l.strip()]
    return [{"name": i.get("Name"), "service": i.get("Service"), "state": i.get("State"),
             "status": i.get("Status")} for i in items]


def container_stats() -> list[dict]:
    if time.time() - STATS_CACHE["at"] < 10:
        return STATS_CACHE["data"]
    names = [c["name"] for c in containers() if c["state"] == "running"]
    data = []
    if names:
        res = subprocess.run(["docker", "stats", "--no-stream", "--format",
                              "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}", *names],
                             capture_output=True, text=True, timeout=30)
        for line in res.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) == 3:
                data.append({"name": parts[0], "cpu": parts[1], "mem": parts[2]})
    STATS_CACHE.update(at=time.time(), data=data)
    return data


def host_memory() -> str:
    info = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, val = line.split(":", 1)
        info[key] = int(val.split()[0]) * 1024
    return f"{fmt_bytes(info['MemAvailable'])} available of {fmt_bytes(info['MemTotal'])}"


def fmt_bytes(n) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def dead_container_error() -> str | None:
    for c in containers():
        if c["state"] in ("exited", "dead"):
            res = subprocess.run(["docker", "logs", "--tail", "15", c["name"]], capture_output=True, text=True, timeout=30)
            tail = "\n".join(l for l in (res.stdout + res.stderr).splitlines() if not re.match(r"^\d+\. ", l))
            return f"container {c['service']} stopped: {c['status']}\n{tail[-1500:]}"
    return None


def wait_for(check, timeout: int, what: str) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if STACK.get("phase") not in ("starting",):
            raise RuntimeError("start cancelled")
        if (dead := dead_container_error()):
            raise RuntimeError(dead)
        try:
            if check():
                return
        except Exception:
            pass
        time.sleep(3)
    raise RuntimeError(f"{what} did not become ready in {timeout} s")


def do_up(hours: int, resume: bool = False, sample: str | None = None) -> None:
    try:
        if not resume:
            token = secrets.token_urlsafe(24)
            set_stack(phase="starting", message="starting containers", token=token,
                      task_token=secrets.token_urlsafe(24), active_sample=None,
                      auto_stop_at=(time.time() + hours * 3600) if hours else None)
            write_env(token)
            compose("up", "-d", "--remove-orphans")
        set_stack(message="waiting for ClickHouse")
        wait_for(lambda: httpx.get(CH_URL + "/ping", timeout=3).text.strip() == "Ok.", 180, "ClickHouse")
        ch(f"CREATE DATABASE IF NOT EXISTS `{CH_DB}`")
        set_stack(message="waiting for Metabase (the very first start takes several minutes)")
        wait_for(lambda: httpx.get(MB_URL + "/api/health", timeout=5).json().get("status") == "ok", 900, "Metabase")
        set_stack(message="configuring Metabase")
        mb_bootstrap()
        note = ""
        if sample:
            set_stack(message=f"loading sample {sample}")
            try:
                note = "sample loaded: " + ", ".join(load_sample(sample))
            except Exception as exc:
                note = f"sample load failed: {exc}"
        set_stack(phase="ready", message=note[:2000])
    except Exception as exc:  # shown in the UI
        if STACK.get("phase") == "starting":
            set_stack(phase="error", message=str(exc)[:2000])


def do_down(wipe: bool) -> None:
    try:
        set_stack(phase="stopping", message="stopping containers", token=None, auto_stop_at=None,
                  task_token=None, active_sample=None)
        compose("down", "--remove-orphans", *(["-v"] if wipe else []), timeout=300)
        if wipe:
            for name in ("metabase.json", "candidates.json"):
                (STATE / name).unlink(missing_ok=True)
            MB_SESSION.clear()
            for item in UPLOADS.iterdir():
                if item.is_file():
                    item.unlink()
        write_env(None)
        set_stack(phase="stopped", message="data wiped" if wipe else "")
    except Exception as exc:
        set_stack(phase="error", message=f"stop failed: {exc}"[:2000])


def start_thread(target, *args) -> None:
    threading.Thread(target=target, args=args, daemon=True).start()


def reconcile_on_boot() -> None:
    running = [c for c in containers() if c["state"] == "running"]
    if not running:
        if STACK.get("phase") != "stopped":
            set_stack(phase="stopped", message="", token=None, auto_stop_at=None)
        return
    if STACK.get("token") and STACK.get("phase") in ("starting", "ready"):
        set_stack(phase="starting", message="admin restarted, re-checking the stack")
        start_thread(do_up, 0, True)
    elif STACK.get("phase") != "error":
        start_thread(do_down, False)


def auto_stop_loop() -> None:
    while True:
        time.sleep(30)
        at = STACK.get("auto_stop_at")
        if at and time.time() > at and STACK.get("phase") in ("ready", "error", "starting"):
            do_down(False)
            set_stack(message="stopped automatically by the timer")
        cutoff = time.time() - UPLOAD_KEEP_S
        for item in UPLOADS.glob("*"):
            if item.is_file() and item.stat().st_mtime < cutoff:
                item.unlink(missing_ok=True)


@app.on_event("startup")
def on_startup() -> None:
    UPLOADS.mkdir(exist_ok=True)
    secrets_cfg()
    reconcile_on_boot()
    start_thread(auto_stop_loop)


# ---------------------------------------------------------------- ClickHouse

class CHError(Exception):
    pass


def ch(sql: str, settings: dict | None = None, timeout: int = 120) -> str:
    cfg = secrets_cfg()
    res = httpx.post(CH_URL + "/", params=settings or {}, content=sql.encode(),
                     auth=("loader", cfg["ch_loader_password"]), timeout=timeout)
    if res.status_code != 200:
        raise CHError(res.text.strip()[:3000])
    return res.text


def ch_json(sql: str, settings: dict | None = None) -> dict:
    return json.loads(ch(sql + " FORMAT JSON", settings))


def lit(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def qident(name: str) -> str:
    return name if IDENT.match(name) else "`" + name.replace("\\", "\\\\").replace("`", "\\`") + "`"


def ch_up() -> bool:
    try:
        return httpx.get(CH_URL + "/ping", timeout=2).text.strip() == "Ok."
    except Exception:
        return False


def list_tables() -> list[dict]:
    tables = ch_json(f"SELECT name, total_rows, total_bytes FROM system.tables "
                     f"WHERE database = {lit(CH_DB)} AND NOT startsWith(name, '__loading_') ORDER BY name")["data"]
    cols = ch_json(f"SELECT table, name, type FROM system.columns WHERE database = {lit(CH_DB)} "
                   f"ORDER BY table, position")["data"]
    by_table: dict[str, list] = {}
    for col in cols:
        by_table.setdefault(col["table"], []).append(f"{col['name']} {col['type']}")
    for tbl in tables:
        tbl["columns"] = by_table.get(tbl["name"], [])
    return tables


def read_settings(fmt: str, delim: str, nullable: bool) -> dict:
    settings = {"schema_inference_make_columns_nullable": "1" if nullable else "0"}
    if fmt.startswith("CSV"):
        settings["format_csv_delimiter"] = delim
    return settings


def upload_meta(uid: str) -> dict | None:
    if not UID.match(uid):
        return None
    meta = UPLOADS / f"{uid}.json"
    if not meta.exists():
        return None
    data = json.loads(meta.read_text())
    data["uid"] = uid
    return data


def infer_schema(meta: dict, fmt: str, delim: str, nullable: bool) -> list[tuple[str, str]]:
    path = f"uploads/{meta['file']}"
    rows = ch_json(f"DESCRIBE TABLE file({lit(path)}, {lit(fmt)})", read_settings(fmt, delim, nullable))["data"]
    return [(r["name"], r["type"]) for r in rows]


def parse_schema(text: str) -> str:
    cols = []
    for line in text.splitlines():
        line = line.strip().rstrip(",").strip()
        if line and not line.startswith("--"):
            cols.append(line)
    if not cols:
        raise ValueError("the schema is empty")
    if any(";" in c for c in cols):
        raise ValueError("';' is not allowed in the schema")
    return ", ".join(cols)


def suggest_table_name(filename: str) -> str:
    base = filename.rsplit("/", 1)[-1]
    for suf in KEEP_SUFFIXES + (".csv", ".tsv", ".txt"):
        if base.lower().endswith(suf):
            base = base[: -len(suf)]
    name = re.sub(r"[^A-Za-z0-9_]+", "_", base).strip("_").lower() or "data"
    if not re.match(r"^[A-Za-z_]", name):
        name = "t_" + name
    return name[:60]


def load_table(meta: dict, table: str, fmt: str, delim: str, nullable: bool, structure: str,
               order_by: str, replace: bool, errors_num: int) -> int:
    target = f"`{CH_DB}`.`{table}`"
    loading = f"`{CH_DB}`.`__loading_{table}`"
    exists = ch(f"EXISTS TABLE {target}").strip() == "1"
    if exists and not replace:
        raise ValueError(f"table {table} already exists (tick 'replace' to overwrite it)")
    ch(f"DROP TABLE IF EXISTS {loading}")
    ch(f"CREATE TABLE {loading} ({structure}) ENGINE = MergeTree ORDER BY {order_by}")
    settings = read_settings(fmt, delim, nullable)
    settings.update(input_format_with_names_use_header="0", input_format_allow_errors_num=str(errors_num))
    try:
        ch(f"INSERT INTO {loading} SELECT * FROM file({lit('uploads/' + meta['file'])}, {lit(fmt)}, {lit(structure)})",
           settings, timeout=3600)
        if exists:
            ch(f"EXCHANGE TABLES {loading} AND {target}")
            ch(f"DROP TABLE {loading}")
        else:
            ch(f"RENAME TABLE {loading} TO {target}")
    except Exception:
        ch(f"DROP TABLE IF EXISTS {loading}")
        raise
    return int(ch(f"SELECT count() FROM {target}").strip())


def drop_upload(uid: str) -> None:
    meta = upload_meta(uid)
    if meta:
        (UPLOADS / meta["file"]).unlink(missing_ok=True)
    (UPLOADS / f"{uid}.json").unlink(missing_ok=True)


def pending_uploads() -> list[dict]:
    out = []
    for meta_path in sorted(UPLOADS.glob("*.json"), key=lambda p: p.stat().st_mtime):
        meta = upload_meta(meta_path.stem)
        if meta:
            out.append(meta)
    return out


# ---------------------------------------------------------------- Metabase

def mb_session(force: bool = False) -> str:
    if force or "id" not in MB_SESSION:
        creds = jload("metabase.json", {})
        if not creds.get("admin_email"):
            raise RuntimeError("Metabase admin credentials are unknown; use 'Stop and wipe' to reset Metabase")
        res = httpx.post(MB_URL + "/api/session", json={"username": creds["admin_email"],
                                                         "password": creds["admin_password"]}, timeout=60)
        res.raise_for_status()
        MB_SESSION["id"] = res.json()["id"]
    return MB_SESSION["id"]


def mb_api(method: str, path: str, **kw):
    for attempt in (0, 1):
        res = httpx.request(method, MB_URL + path, headers={"X-Metabase-Session": mb_session(force=attempt == 1)},
                            timeout=120, **kw)
        if res.status_code == 401 and attempt == 0:
            continue
        if res.status_code >= 400:
            raise RuntimeError(f"Metabase {method} {path}: {res.status_code} {res.text[:500]}")
        return res.json() if res.content else None


def mb_bootstrap() -> None:
    props = httpx.get(MB_URL + "/api/session/properties", timeout=60).json()
    creds = jload("metabase.json", {})
    if not props.get("has-user-setup"):
        email, password = f"admin@{USER_DOMAIN}", gen_password(20)
        res = httpx.post(MB_URL + "/api/setup", timeout=300, json={
            "token": props["setup-token"],
            "user": {"first_name": "Interview", "last_name": "Admin", "email": email,
                     "password": password, "site_name": "Interview"},
            "prefs": {"site_name": "Interview", "site_locale": "en", "allow_tracking": False},
        })
        if res.status_code >= 400:
            raise RuntimeError(f"Metabase setup failed: {res.status_code} {res.text[:500]}")
        creds = {"admin_email": email, "admin_password": password}
        jsave("metabase.json", creds)
        MB_SESSION.clear()

    dbs = mb_api("GET", "/api/database")
    items = dbs["data"] if isinstance(dbs, dict) else dbs
    for db in items:
        if db.get("is_sample"):
            mb_api("DELETE", f"/api/database/{db['id']}")
    details = {"host": "clickhouse", "port": 8123, "user": "metabase",
               "password": secrets_cfg()["ch_metabase_password"], "dbname": CH_DB, "ssl": False}
    existing = next((d for d in items if d.get("engine") == "clickhouse" and d.get("name") == MB_DB_NAME), None)
    if existing:
        db_id = existing["id"]
        mb_api("PUT", f"/api/database/{db_id}", json={"engine": "clickhouse", "name": MB_DB_NAME, "details": details})
    else:
        db_id = mb_api("POST", "/api/database", json={"engine": "clickhouse", "name": MB_DB_NAME,
                                                       "details": details, "is_full_sync": True})["id"]
    creds["db_id"] = db_id
    jsave("metabase.json", creds)
    mb_grant_all_users(db_id)
    mb_sync()


def mb_grant_all_users(db_id: int) -> None:
    """Every Metabase user (the 'All Users' group) may browse the data and write SQL."""
    groups = mb_api("GET", "/api/permissions/group")
    all_users = next(g for g in groups if g.get("name") == "All Users")
    graph = mb_api("GET", "/api/permissions/graph")
    current = graph.get("groups", {}).get(str(all_users["id"]), {}).get(str(db_id), {})
    want = {"view-data": "unrestricted", "create-queries": "query-builder-and-native"}
    if all(current.get(k) == v for k, v in want.items()):
        return
    mb_api("PUT", "/api/permissions/graph", json={
        "revision": graph["revision"],
        "groups": {str(all_users["id"]): {str(db_id): {**current, **want}}},
    })


def mb_sync() -> None:
    db_id = jload("metabase.json", {}).get("db_id")
    if db_id and STACK.get("phase") in ("ready", "starting"):
        mb_api("POST", f"/api/database/{db_id}/sync_schema")


def create_candidate(note: str) -> dict:
    tag = secrets.token_hex(3)
    email, password = f"candidate-{tag}@{USER_DOMAIN}", gen_password(14)
    user = mb_api("POST", "/api/user", json={"first_name": "Candidate", "last_name": tag,
                                             "email": email, "password": password})
    mb_api("PUT", f"/api/user/{user['id']}/password", json={"password": password})
    check = httpx.post(MB_URL + "/api/session", json={"username": email, "password": password}, timeout=60)
    if check.status_code != 200:
        raise RuntimeError(f"user created but its login fails: {check.status_code} {check.text[:300]}")
    entry = {"id": user["id"], "email": email, "password": password, "note": note[:100],
             "created": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()), "active": True}
    with LOCK:
        users = jload("candidates.json", [])
        users.append(entry)
        jsave("candidates.json", users)
    return entry


def deactivate_candidate(user_id: int) -> None:
    mb_api("DELETE", f"/api/user/{user_id}")
    with LOCK:
        users = jload("candidates.json", [])
        for u in users:
            if u["id"] == user_id:
                u["active"] = False
        jsave("candidates.json", users)


# ---------------------------------------------------------------- auth

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())


def verify_password(password: str) -> bool:
    _, n, r, p, salt, digest = ADMIN_HASH.split(":")
    expected = b64d(digest)
    got = hashlib.scrypt(password.encode(), salt=b64d(salt), n=int(n), r=int(r), p=int(p), dklen=len(expected))
    return hmac.compare_digest(got, expected)


def client_ip(request: Request) -> str:
    return request.headers.get("x-real-ip") or (request.client.host if request.client else "?")


def authed(request: Request) -> bool:
    exp = SESSIONS.get(request.cookies.get("iv_session", ""))
    return bool(exp and exp > time.time())


def same_origin(request: Request) -> bool:
    src = request.headers.get("origin") or request.headers.get("referer") or ""
    return bool(src) and urlsplit(src).netloc == request.headers.get("host", "")


def guard(request: Request, post: bool = False) -> Response | None:
    if not authed(request):
        return RedirectResponse(P + "/login", status_code=303)
    if post and not same_origin(request):
        return Response("cross-origin request refused", status_code=403)
    return None


def back(msg: str = "", err: str = "", anchor: str = "") -> RedirectResponse:
    query = f"?msg={quote(msg)}" if msg else (f"?err={quote(err)}" if err else "")
    return RedirectResponse(f"{P}/{query}{anchor}", status_code=303)


# ---------------------------------------------------------------- HTML

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--muted:#6b7280;--line:#e3e6eb;--acc:#2563eb;--ok:#15803d;--warn:#b45309;--bad:#b91c1c;--code:#f1f3f6}
@media (prefers-color-scheme: dark){:root{--bg:#111418;--card:#1a1f26;--fg:#e6e9ee;--muted:#9aa3af;--line:#2a313b;--acc:#60a5fa;--ok:#4ade80;--warn:#fbbf24;--bad:#f87171;--code:#232a33}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:980px;margin:0 auto;padding:16px}h1{font-size:20px;margin:8px 0 16px}h2{font-size:16px;margin:0 0 12px}
section{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px}
table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:500}
input[type=text],input[type=password],input[type=url],input[type=number],select,textarea{background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:6px 8px;font:inherit}
textarea{width:100%;font-family:ui-monospace,Menlo,monospace;font-size:13px}
button{background:var(--acc);color:#fff;border:0;border-radius:6px;padding:7px 14px;font:inherit;cursor:pointer}button.sec{background:transparent;color:var(--fg);border:1px solid var(--line)}button.bad{background:var(--bad)}
button:disabled{opacity:.5;cursor:default}form.inline{display:inline}
code,.mono{font-family:ui-monospace,Menlo,monospace;font-size:13px;background:var(--code);padding:1px 5px;border-radius:4px;word-break:break-all}
.muted{color:var(--muted)}.row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}.flash{padding:10px 12px;border-radius:8px;margin-bottom:16px;border:1px solid var(--line);white-space:pre-wrap}
.flash.ok{border-color:var(--ok)}.flash.err{border-color:var(--bad);color:var(--bad)}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-weight:600;border:1px solid currentColor}
.ready{color:var(--ok)}.starting,.stopping{color:var(--warn)}.error{color:var(--bad)}.stopped{color:var(--muted)}
.scroll{overflow-x:auto}label{display:inline-flex;gap:6px;align-items:center}
"""

COPY_JS = """
function copyText(id){const t=document.getElementById(id).innerText;navigator.clipboard.writeText(t).then(()=>{const b=document.querySelector('[data-copy="'+id+'"]');if(b){const o=b.innerText;b.innerText='copied';setTimeout(()=>b.innerText=o,1200)}})}
"""


def e(value) -> str:
    return html.escape("" if value is None else str(value))


def page(title: str, body: str, refresh_js: str = "", extra_css: str = "") -> HTMLResponse:
    return HTMLResponse(
        f"<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<meta name='robots' content='noindex'><title>{e(title)}</title><style>{CSS}{extra_css}</style></head>"
        f"<body><main>{body}</main><script>{COPY_JS}{refresh_js}</script></body></html>"
    )


def flash(request: Request) -> str:
    msg, err = request.query_params.get("msg"), request.query_params.get("err")
    if msg:
        return f"<div class='flash ok'>{e(msg)}</div>"
    if err:
        return f"<div class='flash err'>{e(err)}</div>"
    return ""


def copy_block(block_id: str, text: str) -> str:
    return (f"<div class='row'><pre id='{block_id}' class='mono' style='margin:0;padding:8px'>{e(text)}</pre>"
            f"<button type='button' class='sec' data-copy='{block_id}' onclick=\"copyText('{block_id}')\">copy</button></div>")


# ---------------------------------------------------------------- routes: auth

@app.get(P + "/login")
def login_form(request: Request):
    err = request.query_params.get("err")
    return page("Interview admin — login", f"""
<h1>Interview admin</h1>
<section style="max-width:360px">
{f"<div class='flash err'>{e(err)}</div>" if err else ""}
<form method="post" action="{P}/login">
<p><input type="text" name="username" placeholder="login" autocomplete="username" required style="width:100%"></p>
<p><input type="password" name="password" placeholder="password" autocomplete="current-password" required style="width:100%"></p>
<button>Sign in</button></form></section>""")


@app.post(P + "/login")
def login(request: Request, username: str = Form(""), password: str = Form("")):
    ip = client_ip(request)
    now = time.time()
    recent = [t for t in FAILS.get(ip, []) if now - t < 900]
    if len(recent) >= 5:
        return RedirectResponse(f"{P}/login?err={quote('Too many attempts, try again in 15 minutes')}", status_code=303)
    if not same_origin(request) or not (hmac.compare_digest(username.encode(), ADMIN_USER.encode()) & verify_password(password)):
        recent.append(now)
        FAILS[ip] = recent
        time.sleep(1)
        return RedirectResponse(f"{P}/login?err={quote('Wrong login or password')}", status_code=303)
    FAILS.pop(ip, None)
    token = secrets.token_urlsafe(32)
    for tok, exp in list(SESSIONS.items()):
        if exp < now:
            SESSIONS.pop(tok, None)
    SESSIONS[token] = now + SESSION_TTL
    resp = RedirectResponse(P + "/", status_code=303)
    resp.set_cookie("iv_session", token, max_age=SESSION_TTL, path=P, secure=True, httponly=True, samesite="strict")
    return resp


@app.post(P + "/logout")
def logout(request: Request):
    SESSIONS.pop(request.cookies.get("iv_session", ""), None)
    resp = RedirectResponse(P + "/login", status_code=303)
    resp.delete_cookie("iv_session", path=P)
    return resp


@app.get("/_internal/mbcheck")
def mbcheck(request: Request):
    match = re.match(r"^/m/([A-Za-z0-9_-]{16,64})/", request.headers.get("x-original-uri", ""))
    token = STACK.get("token")
    # "starting" too: an admin restart re-checks a running stack without changing its URL
    ok = bool(match and token and STACK.get("phase") in ("ready", "starting") and hmac.compare_digest(match.group(1), token))
    return Response(status_code=204 if ok else 403)


# ---------------------------------------------------------------- routes: dashboard

def status_payload() -> dict:
    at = STACK.get("auto_stop_at")
    return {
        "phase": STACK.get("phase"),
        "message": STACK.get("message"),
        "url": metabase_url() if STACK.get("phase") == "ready" else None,
        "auto_stop": time.strftime("%H:%M UTC", time.gmtime(at)) if at else None,
        "task_url": task_url() if STACK.get("phase") == "ready" else None,
        "sample": (sample_meta(STACK.get("active_sample") or "") or {}).get("name"),
    }


@app.get(P + "/api/status")
def api_status(request: Request):
    if not authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return status_payload()


@app.get(P + "/")
def index(request: Request):
    if (r := guard(request)):
        return r
    st = status_payload()
    phase = st["phase"]
    busy = phase in ("starting", "stopping")
    stats = container_stats() if phase != "stopped" else []
    stats_rows = "".join(f"<tr><td>{e(s['name'])}</td><td>{e(s['cpu'])}</td><td>{e(s['mem'])}</td></tr>" for s in stats)
    creds = jload("metabase.json", {})

    stack_html = f"""
<section id="stack"><h2>Stack</h2>
<div class="row"><span class="badge {e(phase)}" id="phase">{e(phase)}</span><span class="muted" id="message">{e(st['message'])}</span></div>
"""
    if st["url"]:
        stack_html += f"<p>Metabase URL (new on every start):</p>{copy_block('mburl', st['url'])}"
    if st["task_url"]:
        stack_html += (f"<p>Task page for the candidate — <b>{e(st['sample'])}</b> "
                       f"(<a href='{e(st['task_url'])}' target='_blank'>open</a>):</p>{copy_block('taskurl', st['task_url'])}")
    if st["auto_stop"]:
        stack_html += f"<p class='muted'>Auto-stop at {e(st['auto_stop'])}.</p>"
    stack_html += "<div class='row' style='margin-top:12px'>"
    if phase in ("stopped", "error"):
        options = "".join(f"<option value='{k}' {'selected' if k == '4' else ''}>{v}</option>" for k, v in AUTO_STOP_CHOICES.items())
        sample_opts = "<option value=''>empty (no sample)</option>" + "".join(
            f"<option value='{e(m['slug'])}'>{e(m['name'])}</option>" for m in list_samples())
        stack_html += (f"<form class='inline' method='post' action='{P}/stack/up'>"
                       f"<label>sample <select name='sample'>{sample_opts}</select></label> "
                       f"<label>auto-stop after <select name='hours'>{options}</select></label> "
                       f"<button {'disabled' if busy else ''}>Start</button></form>")
    if phase in ("ready", "starting", "error"):
        stack_html += (f"<form class='inline' method='post' action='{P}/stack/extend'><button class='sec'>+2 h to the timer</button></form>"
                       f"<form class='inline' method='post' action='{P}/stack/down'><button class='sec'>Stop</button></form>")
    stack_html += (f"<form class='inline' method='post' action='{P}/stack/wipe' "
                   f"onsubmit=\"return confirm('Stop and delete ALL tables, Metabase users and questions?')\">"
                   f"<button class='bad' {'disabled' if busy else ''}>Stop and wipe data</button></form></div>")
    if stats_rows:
        stack_html += f"<table style='margin-top:12px'><tr><th>container</th><th>CPU</th><th>memory</th></tr>{stats_rows}</table>"
    stack_html += f"<p class='muted'>Server memory: {e(host_memory())}.</p>"
    if creds.get("admin_email"):
        stack_html += ("<details><summary>Metabase admin login</summary>"
                       + copy_block("mbadmin", f"{creds['admin_email']}\n{creds['admin_password']}") + "</details>")
    stack_html += "</section>"

    tables_html = "<section id='tables'><h2>ClickHouse tables <span class='muted'>(database <code>interview</code>)</span></h2>"
    if ch_up():
        try:
            tables = list_tables()
        except Exception as exc:
            tables = []
            tables_html += f"<div class='flash err'>{e(exc)}</div>"
        if tables:
            tables_html += "<div class='scroll'><table><tr><th>table</th><th>rows</th><th>size</th><th>columns</th><th></th></tr>"
            for t in tables:
                cols = "<br>".join(e(c) for c in t["columns"])
                tables_html += (f"<tr><td><code>{e(t['name'])}</code></td><td>{int(t['total_rows'] or 0):,}</td>"
                                f"<td>{fmt_bytes(t['total_bytes'])}</td>"
                                f"<td><details><summary>{len(t['columns'])}</summary><span class='mono'>{cols}</span></details></td>"
                                f"<td><form class='inline' method='post' action='{P}/tables/drop' "
                                f"onsubmit=\"return confirm('Drop table {e(t['name'])}?')\">"
                                f"<input type='hidden' name='table' value='{e(t['name'])}'><button class='sec'>drop</button></form></td></tr>")
            tables_html += "</table></div>"
        else:
            tables_html += "<p class='muted'>No tables yet.</p>"
        pend = pending_uploads()
        if pend:
            tables_html += "<p>Uploaded, not loaded yet:</p><ul>"
            for m in pend:
                tables_html += (f"<li><a href='{P}/tables/prepare/{m['uid']}'>{e(m['name'])}</a> "
                                f"<span class='muted'>{fmt_bytes(m['size'])}</span> "
                                f"<form class='inline' method='post' action='{P}/tables/discard/{m['uid']}'>"
                                f"<button class='sec'>discard</button></form></li>")
            tables_html += "</ul>"
        tables_html += f"""
<h2 style="margin-top:16px">Load a CSV / TSV</h2>
<form method="post" action="{P}/tables/upload" enctype="multipart/form-data">
<div class="row"><input type="file" name="file"> <span class="muted">or</span>
<input type="url" name="url" placeholder="https://… link to the file" style="flex:1;min-width:240px"></div>
<p class="muted">.gz / .zst / .xz / .bz2 / .lz4 are decompressed on the fly. Next step: format, schema and table name.</p>
<button>Upload</button></form>"""
    else:
        tables_html += "<p class='muted'>ClickHouse is not running — start the stack first.</p>"
    tables_html += "</section>"

    users_html = "<section id='users'><h2>Metabase users for candidates</h2>"
    if phase == "ready":
        users_html += (f"<form method='post' action='{P}/users/create' class='row'>"
                       f"<input type='text' name='note' placeholder='note (candidate name), optional' style='flex:1;min-width:200px'>"
                       f"<button>Create user</button></form>")
    else:
        users_html += "<p class='muted'>Available when the stack is ready.</p>"
    users = jload("candidates.json", [])
    if users:
        users_html += "<div class='scroll'><table style='margin-top:12px'><tr><th>note</th><th>credentials</th><th>created</th><th></th></tr>"
        for u in reversed(users):
            block_id = f"u{u['id']}"
            text = f"URL: {st['url'] or '(start the stack)'}\nlogin: {u['email']}\npassword: {u['password']}"
            if st["task_url"]:
                text += f"\ntask: {st['task_url']}"
            action = ""
            if u.get("active") and phase == "ready":
                action = (f"<form class='inline' method='post' action='{P}/users/deactivate'>"
                          f"<input type='hidden' name='user_id' value='{u['id']}'><button class='sec'>deactivate</button></form>")
            elif not u.get("active"):
                action = "<span class='muted'>deactivated</span>"
            users_html += (f"<tr><td>{e(u.get('note'))}</td><td>{copy_block(block_id, text) if u.get('active') else e(u['email'])}</td>"
                           f"<td class='muted'>{e(u['created'])}</td><td>{action}</td></tr>")
        users_html += "</table></div>"
    users_html += "</section>"

    header = (f"<div class='row' style='justify-content:space-between'><h1>Interview admin</h1>"
              f"<form method='post' action='{P}/logout'><button class='sec'>Log out</button></form></div>")
    poll = f"""
const initialPhase={json.dumps(phase)};
async function poll(){{try{{const r=await fetch('{P}/api/status',{{credentials:'same-origin'}});
if(r.status===401){{location.href='{P}/login';return}}const s=await r.json();
if(s.phase!==initialPhase){{location.href='{P}/';return}}
document.getElementById('message').innerText=s.message||'';}}catch(e){{}}}}
setInterval(poll, {3000 if busy else 15000});
"""
    samples_html = "<section id='samples'><h2>Samples</h2>"
    samples = list_samples()
    if samples:
        samples_html += "<div class='scroll'><table><tr><th>sample</th><th>tables</th><th>size</th><th>saved</th><th></th></tr>"
        for m in samples:
            tbls = ", ".join(f"{t['name']} ({int(t.get('rows', 0)):,})" for t in m["tables"])
            active = " <span class='badge ready'>active</span>" if STACK.get("active_sample") == m["slug"] else ""
            load_btn = ""
            if phase == "ready":
                load_btn = (f"<form class='inline' method='post' action='{P}/samples/{m['slug']}/load' "
                            f"onsubmit=\"return confirm('Recreate the tables of this sample?')\"><button class='sec'>load</button></form>")
            samples_html += (f"<tr><td><a href='{P}/samples/{m['slug']}/'>{e(m['name'])}</a>{active}</td>"
                             f"<td class='mono'>{e(tbls)}</td><td>{fmt_bytes(m['size'])}</td>"
                             f"<td class='muted'>{e(m.get('created'))}</td>"
                             f"<td><a href='{P}/samples/{m['slug']}/'><button type='button' class='sec'>readme</button></a> {load_btn}</td></tr>")
        samples_html += "</table></div>"
    else:
        samples_html += "<p class='muted'>No samples yet.</p>"
    if ch_up():
        samples_html += f"<p><a href='{P}/samples/new'>Save the current tables as a sample →</a></p>"
    samples_html += "</section>"
    return page("Interview admin", header + flash(request) + stack_html + samples_html + tables_html + users_html, poll)


# ---------------------------------------------------------------- routes: stack

@app.post(P + "/stack/up")
def stack_up(request: Request, hours: str = Form("4"), sample: str = Form("")):
    if (r := guard(request, post=True)):
        return r
    with LOCK:
        if STACK.get("phase") in ("starting", "stopping", "ready"):
            return back(err="The stack is already " + STACK.get("phase"))
        set_stack(phase="starting", message="queued")
    start_thread(do_up, int(hours) if hours in AUTO_STOP_CHOICES else 4, False, sample if sample_dir(sample) else None)
    return back()


@app.post(P + "/stack/down")
def stack_down(request: Request):
    if (r := guard(request, post=True)):
        return r
    start_thread(do_down, False)
    time.sleep(0.3)
    return back()


@app.post(P + "/stack/wipe")
def stack_wipe(request: Request):
    if (r := guard(request, post=True)):
        return r
    start_thread(do_down, True)
    time.sleep(0.3)
    return back()


@app.post(P + "/stack/extend")
def stack_extend(request: Request):
    if (r := guard(request, post=True)):
        return r
    base = max(STACK.get("auto_stop_at") or time.time(), time.time())
    set_stack(auto_stop_at=base + 2 * 3600)
    return back(msg="Timer extended by 2 hours")


# ---------------------------------------------------------------- routes: tables

def _save_upload_file(src, uid: str, filename: str) -> dict:
    suffix = next((s for s in KEEP_SUFFIXES if filename.lower().endswith(s)), "")
    target = UPLOADS / f"{uid}{suffix}"
    with open(target, "wb") as out:
        shutil.copyfileobj(src, out, 1024 * 1024)
    os.chmod(target, 0o644)
    meta = {"name": filename, "file": target.name, "size": target.stat().st_size, "created": time.time()}
    (UPLOADS / f"{uid}.json").write_text(json.dumps(meta))
    return meta


def _download(url: str, uid: str) -> dict:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError("only http(s) links are supported")
    filename = parts.path.rsplit("/", 1)[-1] or "download.csv"
    suffix = next((s for s in KEEP_SUFFIXES if filename.lower().endswith(s)), "")
    target = UPLOADS / f"{uid}{suffix}"
    size = 0
    with httpx.stream("GET", url, follow_redirects=True, timeout=httpx.Timeout(60, read=600)) as res:
        res.raise_for_status()
        with open(target, "wb") as out:
            for chunk in res.iter_bytes(1024 * 1024):
                size += len(chunk)
                if size > MAX_URL_DOWNLOAD:
                    out.close()
                    target.unlink(missing_ok=True)
                    raise ValueError("file is larger than 2 GB")
                out.write(chunk)
    os.chmod(target, 0o644)
    meta = {"name": filename, "file": target.name, "size": size, "created": time.time()}
    (UPLOADS / f"{uid}.json").write_text(json.dumps(meta))
    return meta


@app.post(P + "/tables/upload")
async def tables_upload(request: Request, file: UploadFile | None = File(None), url: str = Form("")):
    if (r := guard(request, post=True)):
        return r
    uid = secrets.token_hex(16)
    try:
        if file is not None and file.filename:
            await run_in_threadpool(_save_upload_file, file.file, uid, file.filename)
        elif url.strip():
            await run_in_threadpool(_download, url.strip(), uid)
        else:
            return back(err="Choose a file or paste a link", anchor="#tables")
    except Exception as exc:
        drop_upload(uid)
        return back(err=f"Upload failed: {exc}", anchor="#tables")
    return RedirectResponse(f"{P}/tables/prepare/{uid}", status_code=303)


@app.post(P + "/tables/discard/{uid}")
def tables_discard(request: Request, uid: str):
    if (r := guard(request, post=True)):
        return r
    drop_upload(uid)
    return back(msg="Upload discarded", anchor="#tables")


@app.get(P + "/tables/prepare/{uid}")
def tables_prepare(request: Request, uid: str):
    if (r := guard(request)):
        return r
    meta = upload_meta(uid)
    if not meta:
        return back(err="Upload not found (uploads are kept for 24 hours)", anchor="#tables")
    q = request.query_params
    guess = "TSVWithNames" if re.search(r"\.(tsv|tab)(\.|$)", meta["name"].lower()) else "CSVWithNames"
    fmt = q.get("fmt") if q.get("fmt") in FORMATS else guess
    delim = q.get("delim") if q.get("delim") in DELIMS else ","
    nullable = q.get("nullable") == "1" if "nullable_set" in q else True
    err = q.get("err")

    infer_err, schema, preview_html = "", [], ""
    try:
        schema = infer_schema(meta, fmt, delim, nullable)
        structure = ", ".join(f"{qident(n)} {t}" for n, t in schema)
        prev = json.loads(ch(f"SELECT * FROM file({lit('uploads/' + meta['file'])}, {lit(fmt)}, {lit(structure)}) "
                             f"LIMIT 10 FORMAT JSONCompact", {**read_settings(fmt, delim, nullable),
                                                              "input_format_with_names_use_header": "0"}))
        head = "".join(f"<th>{e(c['name'])}<br><span class='muted'>{e(c['type'])}</span></th>" for c in prev["meta"])
        body = "".join("<tr>" + "".join(f"<td>{e(v)}</td>" for v in row) + "</tr>" for row in prev["data"])
        preview_html = f"<div class='scroll'><table><tr>{head}</tr>{body}</table></div>"
    except Exception as exc:
        infer_err = str(exc)

    infer_block = (f"<div class='flash err' style='margin-top:12px'>Schema detection failed: {e(infer_err)}</div>"
                   if infer_err else "")
    schema_text = "\n".join(f"{qident(n)} {t}" for n, t in schema)
    fmt_opts = "".join(f"<option value='{k}' {'selected' if k == fmt else ''}>{e(v)}</option>" for k, v in FORMATS.items())
    delim_opts = "".join(f"<option value='{e(k)}' {'selected' if k == delim else ''}>{e(v)}</option>" for k, v in DELIMS.items())
    body = f"""
<div class='row' style='justify-content:space-between'><h1>Load <code>{e(meta['name'])}</code> <span class='muted'>{fmt_bytes(meta['size'])}</span></h1>
<a href="{P}/">← back</a></div>
{f"<div class='flash err'>{e(err)}</div>" if err else ""}
<section><h2>1. How to read the file</h2>
<form method="get" class="row">
<label>format <select name="fmt">{fmt_opts}</select></label>
<label>CSV delimiter <select name="delim">{delim_opts}</select></label>
<label><input type="checkbox" name="nullable" value="1" {'checked' if nullable else ''}> inferred columns Nullable</label>
<input type="hidden" name="nullable_set" value="1">
<button class="sec">Re-detect</button></form>
{infer_block}
{f"<p class='muted'>First 10 rows as ClickHouse reads them:</p>{preview_html}" if preview_html else ""}
</section>
<section><h2>2. Create the table</h2>
<form method="post" action="{P}/tables/create/{uid}">
<input type="hidden" name="fmt" value="{e(fmt)}"><input type="hidden" name="delim" value="{e(delim)}">
<input type="hidden" name="nullable" value="{'1' if nullable else '0'}">
<p><label>table name <input type="text" name="table" value="{e(suggest_table_name(meta['name']))}" pattern="[A-Za-z_][A-Za-z0-9_]*" required></label></p>
<p><label><input type="radio" name="mode" value="auto" {'checked' if schema else 'disabled'}> detected schema (as in the preview)</label><br>
<label><input type="radio" name="mode" value="manual" {'' if schema else 'checked'}> my schema below — one <code>column Type</code> per line, in file column order;
names may differ from the header</label></p>
<textarea name="schema" rows="{max(6, min(len(schema) + 1, 30))}" placeholder="user_id UInt64&#10;event_date Date&#10;amount Nullable(Float64)">{e(schema_text)}</textarea>
<div class="row" style="margin-top:8px">
<label>ORDER BY <input type="text" name="order_by" value="tuple()" style="width:220px"></label>
<label>tolerate bad rows <input type="number" name="errors_num" value="0" min="0" style="width:90px"></label>
<label><input type="checkbox" name="replace" value="1"> replace the table if it exists</label></div>
<p><button>Create table and load</button></p></form></section>"""
    return page("Load table", body)


@app.post(P + "/tables/create/{uid}")
def tables_create(request: Request, uid: str, table: str = Form(...), fmt: str = Form(...), delim: str = Form(","),
                  nullable: str = Form("1"), mode: str = Form("auto"), schema: str = Form(""),
                  order_by: str = Form("tuple()"), replace: str = Form(""), errors_num: int = Form(0)):
    if (r := guard(request, post=True)):
        return r
    meta = upload_meta(uid)
    if not meta:
        return back(err="Upload not found", anchor="#tables")
    params = f"fmt={quote(fmt)}&delim={quote(delim)}&nullable={'1' if nullable == '1' else '0'}"
    try:
        if not IDENT.match(table) or table.startswith("__"):
            raise ValueError("table name: latin letters, digits and _, not starting with a digit or __")
        if fmt not in FORMATS or delim not in DELIMS:
            raise ValueError("unknown format or delimiter")
        order_by = order_by.strip() or "tuple()"
        if ";" in order_by:
            raise ValueError("';' is not allowed in ORDER BY")
        if mode == "manual":
            structure = parse_schema(schema)
        else:
            structure = ", ".join(f"{qident(n)} {t}" for n, t in infer_schema(meta, fmt, delim, nullable == "1"))
        rows = load_table(meta, table, fmt, delim, nullable == "1", structure, order_by, replace == "1", max(0, errors_num))
    except Exception as exc:
        return RedirectResponse(f"{P}/tables/prepare/{uid}?{params}&err={quote(str(exc)[:3000])}", status_code=303)
    drop_upload(uid)
    note = ""
    try:
        mb_sync()
    except Exception as exc:
        note = f" (Metabase sync failed: {exc})"
    return back(msg=f"Table {table} loaded: {rows:,} rows{note}", anchor="#tables")


@app.post(P + "/tables/drop")
def tables_drop(request: Request, table: str = Form(...)):
    if (r := guard(request, post=True)):
        return r
    if not IDENT.match(table):
        return back(err="bad table name", anchor="#tables")
    try:
        ch(f"DROP TABLE IF EXISTS `{CH_DB}`.`{table}`")
        mb_sync()
    except Exception as exc:
        return back(err=str(exc), anchor="#tables")
    return back(msg=f"Table {table} dropped", anchor="#tables")


# ---------------------------------------------------------------- routes: users

@app.post(P + "/users/create")
def users_create(request: Request, note: str = Form("")):
    if (r := guard(request, post=True)):
        return r
    if STACK.get("phase") != "ready":
        return back(err="Start the stack first", anchor="#users")
    try:
        user = create_candidate(note.strip())
    except Exception as exc:
        return back(err=f"Could not create the user: {exc}", anchor="#users")
    return back(msg=f"User {user['email']} created", anchor="#users")


@app.post(P + "/users/deactivate")
def users_deactivate(request: Request, user_id: int = Form(...)):
    if (r := guard(request, post=True)):
        return r
    try:
        deactivate_candidate(user_id)
    except Exception as exc:
        return back(err=str(exc), anchor="#users")
    return back(msg="User deactivated", anchor="#users")


# ---------------------------------------------------------------- samples
#
# A sample = a saved interview case in $IV_HOME/samples/<slug>/:
#   sample.json   {"name", "created", "tables": [{"name", "structure", "order_by", "file", "rows"}]}
#   task.md       shown to the candidate at the public /iv-task/<token>/ page (token new on every start)
#   readme.md     interviewer notes, rendered only inside the admin
#   data/*.csv.gz the table data (CSVWithNames, exported from ClickHouse)
#   assets/*      files the readme links to (images, csv), admin-only
# Loading a sample (on start or into a running stack) recreates its tables, makes it the active
# sample (its task becomes the /iv-task/ page) and saves a Metabase question that links to the task.

SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,59}$")
ASSET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$")

MD_CSS = """
.md{line-height:1.6;max-width:860px}.md h1{font-size:24px}.md h2{font-size:19px;margin-top:28px}.md h3{font-size:16px}
.md table{border-collapse:collapse;margin:12px 0;width:auto}.md th,.md td{border:1px solid var(--line);padding:6px 10px;text-align:left}
.md th{background:var(--code);color:var(--fg);font-weight:600}.md pre{background:var(--code);padding:12px;border-radius:8px;overflow-x:auto}
.md pre code{background:none;padding:0}.md img{max-width:100%;height:auto;border:1px solid var(--line);border-radius:6px}
.md code{word-break:normal;overflow-wrap:anywhere}.md td code,.md th code{white-space:nowrap;overflow-wrap:normal}
.md blockquote{border-left:3px solid var(--line);margin:0;padding-left:12px;color:var(--muted)}
"""


def render_md(text: str) -> str:
    return markdown.markdown(text or "", extensions=["tables", "fenced_code", "sane_lists"])


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:60]
    return slug or f"sample-{secrets.token_hex(3)}"


def sample_dir(slug: str) -> Path | None:
    if not SLUG.match(slug or ""):
        return None
    path = SAMPLES / slug
    return path if (path / "sample.json").exists() else None


def sample_meta(slug: str) -> dict | None:
    path = sample_dir(slug)
    if not path:
        return None
    meta = json.loads((path / "sample.json").read_text())
    meta["slug"] = slug
    meta["task"] = (path / "task.md").read_text() if (path / "task.md").exists() else ""
    meta["readme"] = (path / "readme.md").read_text() if (path / "readme.md").exists() else ""
    meta["size"] = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
    assets = path / "assets"
    meta["assets"] = sorted(f.name for f in assets.iterdir() if f.is_file()) if assets.exists() else []
    return meta


def list_samples() -> list[dict]:
    if not SAMPLES.exists():
        return []
    out = [sample_meta(p.name) for p in sorted(SAMPLES.iterdir()) if p.is_dir() and not p.name.startswith(".")]
    return [m for m in out if m]


def export_table(table: str, dest: Path) -> int:
    cfg = secrets_cfg()
    sql = f"SELECT * FROM `{CH_DB}`.`{table}` FORMAT CSVWithNames"
    with httpx.stream("POST", CH_URL + "/", content=sql.encode(), auth=("loader", cfg["ch_loader_password"]),
                      timeout=httpx.Timeout(60, read=1800)) as res:
        if res.status_code != 200:
            raise CHError(res.read().decode(errors="replace")[:2000])
        with gzip.open(dest, "wb", compresslevel=6) as out:
            for chunk in res.iter_bytes(1024 * 1024):
                out.write(chunk)
    return int(ch(f"SELECT count() FROM `{CH_DB}`.`{table}`").strip())


def table_definition(table: str) -> tuple[str, str]:
    cols = ch_json(f"SELECT name, type FROM system.columns WHERE database = {lit(CH_DB)} "
                   f"AND table = {lit(table)} ORDER BY position")["data"]
    if not cols:
        raise ValueError(f"table {table} not found")
    key = ch_json(f"SELECT sorting_key FROM system.tables WHERE database = {lit(CH_DB)} "
                  f"AND name = {lit(table)}")["data"][0]["sorting_key"]
    return ", ".join(f"{qident(c['name'])} {c['type']}" for c in cols), (f"({key})" if key else "tuple()")


def save_sample(name: str, tables: list[str], task: str, readme: str, assets: list[tuple[str, bytes]],
                overwrite: bool) -> str:
    slug = slugify(name)
    final = SAMPLES / slug
    if final.exists() and not overwrite:
        raise ValueError(f"a sample '{slug}' already exists (tick 'overwrite' to replace it)")
    for t in tables:
        if not IDENT.match(t):
            raise ValueError(f"bad table name {t}")
    SAMPLES.mkdir(exist_ok=True)
    tmp = SAMPLES / f".tmp-{slug}-{secrets.token_hex(3)}"
    (tmp / "data").mkdir(parents=True)
    (tmp / "assets").mkdir()
    try:
        defs = []
        for t in tables:
            structure, order_by = table_definition(t)
            rows = export_table(t, tmp / "data" / f"{t}.csv.gz")
            defs.append({"name": t, "structure": structure, "order_by": order_by, "file": f"{t}.csv.gz", "rows": rows})
        (tmp / "task.md").write_text(task)
        (tmp / "readme.md").write_text(readme)
        if final.exists() and (final / "assets").exists():
            for f in (final / "assets").iterdir():
                shutil.copy2(f, tmp / "assets" / f.name)
        for fname, content in assets:
            if ASSET.match(fname):
                (tmp / "assets" / fname).write_bytes(content)
        (tmp / "sample.json").write_text(json.dumps({
            "name": name, "created": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()), "tables": defs}, indent=1))
        if final.exists():
            shutil.rmtree(final)
        tmp.rename(final)
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return slug


def load_sample(slug: str) -> list[str]:
    meta = sample_meta(slug)
    if not meta:
        raise ValueError(f"sample {slug} not found")
    loaded = []
    for t in meta["tables"]:
        uid = secrets.token_hex(16)
        copy = UPLOADS / f"{uid}.csv.gz"
        shutil.copyfile(SAMPLES / slug / "data" / t["file"], copy)
        os.chmod(copy, 0o644)
        try:
            rows = load_table({"file": copy.name}, t["name"], "CSVWithNames", ",", True, t["structure"],
                              t["order_by"], True, 0)
        finally:
            copy.unlink(missing_ok=True)
        loaded.append(f"{t['name']} ({rows:,} rows)")
    if not STACK.get("task_token"):
        set_stack(task_token=secrets.token_urlsafe(24))
    set_stack(active_sample=slug)
    mb_sync()
    mb_task_card(meta)
    return loaded


def task_url() -> str | None:
    tok, slug = STACK.get("task_token"), STACK.get("active_sample")
    return f"{PUBLIC_BASE}/iv-task/{tok}/" if tok and slug and sample_dir(slug) else None


def mb_task_card(meta: dict) -> None:
    """A saved SQL question pinned in 'Our analytics' that points the candidate to the task page."""
    creds = jload("metabase.json", {})
    db_id = creds.get("db_id")
    if not db_id:
        return
    first = meta["tables"][0]["name"] if meta["tables"] else "users"
    tables = ", ".join(t["name"] for t in meta["tables"])
    sql = (f"-- {meta['name']}\n"
           f"-- Task description: {task_url()}\n"
           f"-- Tables in the database: {tables}\n\n"
           f"select\n    *\nfrom\n    `{first}`\nlimit 10\n")
    body = {
        "name": f"{meta['name']} — start here",
        "description": f"Task description: {task_url()}",
        "type": "question",
        "display": "table",
        "visualization_settings": {},
        "dataset_query": {"type": "native", "database": db_id, "native": {"query": sql}},
        "collection_id": None,
        "collection_position": 1,
    }
    cards = creds.setdefault("task_cards", {})
    card_id = cards.get(meta["slug"])
    if card_id:
        try:
            mb_api("PUT", f"/api/card/{card_id}", json={**body, "archived": False})
            return
        except RuntimeError:
            pass
    card = mb_api("POST", "/api/card", json=body)
    cards[meta["slug"]] = card["id"]
    jsave("metabase.json", creds)


def md_page(title: str, inner: str) -> HTMLResponse:
    return HTMLResponse(
        f"<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<meta name='robots' content='noindex'><title>{e(title)}</title><style>{CSS}{MD_CSS}</style></head>"
        f"<body><main><div class='md'>{inner}</div></main></body></html>"
    )


@app.get("/iv-task/{token}")
def task_page_noslash(token: str):
    return RedirectResponse(f"/iv-task/{token}/", status_code=302)


@app.get("/iv-task/{token}/")
def task_page(token: str):
    cur, slug = STACK.get("task_token"), STACK.get("active_sample")
    if not (cur and slug and STACK.get("phase") == "ready" and hmac.compare_digest(token, cur)):
        return Response("Not found\n", status_code=404, media_type="text/plain")
    meta = sample_meta(slug)
    if not meta:
        return Response("Not found\n", status_code=404, media_type="text/plain")
    return md_page(meta["name"], render_md(meta["task"]))


@app.get(P + "/samples/new")
def sample_new_form(request: Request):
    if (r := guard(request)):
        return r
    if not ch_up():
        return back(err="Start the stack first: a sample is saved from the tables loaded now", anchor="#samples")
    tables = list_tables()
    src = sample_meta(request.query_params.get("from", "")) or {}
    picked = {t["name"] for t in src.get("tables", [])} or {t["name"] for t in tables}
    checks = "".join(
        f"<label><input type='checkbox' name='tables' value='{e(t['name'])}' {'checked' if t['name'] in picked else ''}> "
        f"<code>{e(t['name'])}</code> <span class='muted'>{int(t['total_rows'] or 0):,} rows</span></label><br>" for t in tables)
    body = f"""
<div class='row' style='justify-content:space-between'><h1>Save tables as a sample</h1><a href="{P}/#samples">← back</a></div>
{flash(request)}
<section><form method="post" action="{P}/samples/new" enctype="multipart/form-data">
<p><label>name <input type="text" name="name" value="{e(src.get('name', ''))}" required style="width:420px"></label></p>
<p>tables to include:<br>{checks or "<span class='muted'>no tables loaded</span>"}</p>
<p>task.md — shown to the candidate (Markdown):</p>
<textarea name="task" rows="16">{e(src.get('task', ''))}</textarea>
<p>readme.md — interviewer notes, admin only (Markdown; images from attachments as <code>![](assets/file.png)</code>):</p>
<textarea name="readme" rows="16">{e(src.get('readme', ''))}</textarea>
<p>attachments for the readme: <input type="file" name="assets" multiple></p>
<p><label><input type="checkbox" name="overwrite" value="1" {'checked' if src else ''}> overwrite a sample with the same name</label></p>
<button>Save sample</button></form></section>"""
    return page("Save sample", body)


@app.post(P + "/samples/new")
async def sample_new(request: Request):
    if (r := guard(request, post=True)):
        return r
    form = await request.form()
    name = str(form.get("name", "")).strip()
    tables = [str(t) for t in form.getlist("tables")]
    assets = []
    for item in form.getlist("assets"):
        if getattr(item, "filename", ""):
            assets.append((Path(item.filename).name, await item.read()))
    if not name or not tables:
        return RedirectResponse(f"{P}/samples/new?err={quote('Give a name and pick at least one table')}", status_code=303)
    try:
        slug = await run_in_threadpool(save_sample, name, tables, str(form.get("task", "")), str(form.get("readme", "")),
                                       assets, form.get("overwrite") == "1")
    except Exception as exc:
        return RedirectResponse(f"{P}/samples/new?err={quote(str(exc)[:2000])}", status_code=303)
    return RedirectResponse(f"{P}/samples/{slug}/?msg={quote('Sample saved')}", status_code=303)


@app.get(P + "/samples/{slug}")
def sample_view_noslash(slug: str):
    return RedirectResponse(f"{P}/samples/{slug}/", status_code=302)


@app.get(P + "/samples/{slug}/")
def sample_view(request: Request, slug: str):
    if (r := guard(request)):
        return r
    meta = sample_meta(slug)
    if not meta:
        return back(err="Sample not found", anchor="#samples")
    tables = "".join(f"<tr><td><code>{e(t['name'])}</code></td><td>{int(t.get('rows', 0)):,}</td>"
                     f"<td class='mono'>{e(t['structure'])}</td><td class='mono'>{e(t['order_by'])}</td></tr>"
                     for t in meta["tables"])
    assets = " ".join(f"<a href='assets/{quote(a)}'>{e(a)}</a>" for a in meta["assets"]) or "<span class='muted'>none</span>"
    actions = ""
    if STACK.get("phase") == "ready":
        actions = (f"<form class='inline' method='post' action='{P}/samples/{slug}/load' "
                   f"onsubmit=\"return confirm('Recreate this sample\\'s tables in the running stack?')\">"
                   f"<button>Load into the running stack</button></form>")
    actions += (f"<a href='{P}/samples/new?from={slug}'><button type='button' class='sec'>Edit / re-save from current tables</button></a>"
                f"<form class='inline' method='post' action='{P}/samples/{slug}/delete' "
                f"onsubmit=\"return confirm('Delete the sample {e(meta['name'])} with its data?')\"><button class='bad'>Delete</button></form>")
    body = f"""
<div class='row' style='justify-content:space-between'><h1>{e(meta['name'])}</h1><a href="{P}/#samples">← back</a></div>
{flash(request)}
<section><div class='row'>{actions}</div>
<p class='muted'>saved {e(meta.get('created'))} · {fmt_bytes(meta['size'])} on disk · attachments: {assets}</p>
<div class='scroll'><table><tr><th>table</th><th>rows</th><th>columns</th><th>ORDER BY</th></tr>{tables}</table></div></section>
<section><h2>Interviewer readme</h2><div class='md'>{render_md(meta['readme'])}</div></section>
<section><h2>Candidate task (preview)</h2><div class='md'>{render_md(meta['task'])}</div></section>
<section><h2>Edit texts</h2><form method="post" action="{P}/samples/{slug}/texts">
<p>task.md</p><textarea name="task" rows="14">{e(meta['task'])}</textarea>
<p>readme.md</p><textarea name="readme" rows="14">{e(meta['readme'])}</textarea>
<p><button>Save texts</button></p></form></section>"""
    return page(meta["name"], body, extra_css=MD_CSS)


@app.get(P + "/samples/{slug}/assets/{fname}")
def sample_asset(request: Request, slug: str, fname: str):
    if (r := guard(request)):
        return r
    path = sample_dir(slug)
    if not path or not ASSET.match(fname) or not (path / "assets" / fname).is_file():
        return Response("Not found", status_code=404)
    return FileResponse(path / "assets" / fname)


@app.post(P + "/samples/{slug}/texts")
def sample_texts(request: Request, slug: str, task: str = Form(""), readme: str = Form("")):
    if (r := guard(request, post=True)):
        return r
    path = sample_dir(slug)
    if not path:
        return back(err="Sample not found", anchor="#samples")
    (path / "task.md").write_text(task)
    (path / "readme.md").write_text(readme)
    return RedirectResponse(f"{P}/samples/{slug}/?msg={quote('Texts saved')}", status_code=303)


@app.post(P + "/samples/{slug}/delete")
def sample_delete(request: Request, slug: str):
    if (r := guard(request, post=True)):
        return r
    path = sample_dir(slug)
    if path:
        shutil.rmtree(path)
        if STACK.get("active_sample") == slug:
            set_stack(active_sample=None)
    return back(msg="Sample deleted", anchor="#samples")


@app.post(P + "/samples/{slug}/load")
def sample_load(request: Request, slug: str):
    if (r := guard(request, post=True)):
        return r
    if STACK.get("phase") != "ready":
        return back(err="Start the stack first", anchor="#samples")
    try:
        loaded = load_sample(slug)
    except Exception as exc:
        return back(err=f"Could not load the sample: {exc}", anchor="#samples")
    return back(msg="Loaded: " + ", ".join(loaded), anchor="#samples")
