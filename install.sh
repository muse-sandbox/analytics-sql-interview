#!/usr/bin/env bash
# Install / update the interview stack on the server. Run as root from a copy of this repository:
#   ./install.sh https://<server address>
# (deploy.sh does the copy + this call from a laptop over ssh).
# Idempotent: re-running updates the code and configs and keeps credentials, data, volumes and
# samples. Samples committed under samples/<slug>/ are copied to the server only if the server
# does not have a sample with that slug yet.
# The nginx site is SITE (default: the muse_slop site); the include line is inserted before its
# "# ---- SFTPGo ----" section marker.
#
# Layout on the server:
#   /opt/interview/                 root 755   compose.yml, clickhouse/, metabase/ (read-only configs)
#   /opt/interview/ctl/             root 700   controller code + its secrets (Postgres password, stack.env)
#   /opt/interview/admin/           root 755   admin image sources + its compose.yml
#   /opt/interview/admin.env        root 600   admin login hash + public address (container env)
#   /opt/interview/admin_credentials.txt  root 600   the admin password in plain text
#   /opt/interview/{state,samples}  ivadmin 700   admin data (mounted into the admin container)
#   /opt/interview/uploads          ivadmin 711   CSV uploads (also mounted read-only into ClickHouse)
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
DEST=/opt/interview
PUBLIC_BASE="${1:?usage: install.sh https://<server address>}"
PUBLIC_BASE="${PUBLIC_BASE%/}"
SITE="${SITE:-/etc/nginx/sites-available/muse-slop}"
SNIPPET=/etc/nginx/snippets/muse-slop-interview.conf
UID_ADMIN=10001

# --- unprivileged identity of the admin container
getent group ivadmin >/dev/null || groupadd -g "$UID_ADMIN" ivadmin
getent passwd ivadmin >/dev/null || useradd -r -u "$UID_ADMIN" -g "$UID_ADMIN" -M -d /nonexistent -s /usr/sbin/nologin ivadmin

# --- the pre-container version ran the admin as root on the host: retire it
if systemctl list-unit-files interview-admin.service >/dev/null 2>&1 && [ -f /etc/systemd/system/interview-admin.service ]; then
    systemctl disable --now interview-admin.service 2>/dev/null || true
    rm -f /etc/systemd/system/interview-admin.service
    systemctl daemon-reload
fi
rm -rf "$DEST/admin/.venv"
for f in admin.env admin_credentials.txt; do
    [ -f "$DEST/state/$f" ] && [ ! -f "$DEST/$f" ] && mv "$DEST/state/$f" "$DEST/$f"
done
rm -f "$DEST/state/stack.env"

# --- files
install -d -m 755 "$DEST" "$DEST/clickhouse" "$DEST/metabase" "$DEST/admin"
install -d -m 700 "$DEST/ctl" "$DEST/ctl/docker"
install -d -m 700 -o "$UID_ADMIN" -g "$UID_ADMIN" "$DEST/state" "$DEST/samples"
install -d -m 711 -o "$UID_ADMIN" -g "$UID_ADMIN" "$DEST/uploads"
chown -R "$UID_ADMIN:$UID_ADMIN" "$DEST/state" "$DEST/samples" "$DEST/uploads"
install -m 644 "$SRC/compose.yml" "$DEST/compose.yml"
install -m 644 "$SRC/clickhouse/config.xml" "$SRC/clickhouse/users.xml" "$DEST/clickhouse/"
install -m 644 "$SRC/metabase/log4j2.xml" "$DEST/metabase/"
install -m 644 "$SRC/admin/app.py" "$SRC/admin/requirements.txt" "$SRC/admin/Dockerfile" "$SRC/admin/compose.yml" "$DEST/admin/"
install -m 700 "$SRC/ctl/interview_ctl.py" "$DEST/ctl/interview_ctl.py"

for sample in "$SRC"/samples/*/; do
    [ -f "$sample/sample.json" ] || continue
    slug="$(basename "$sample")"
    if [ ! -e "$DEST/samples/$slug" ]; then
        cp -R "$sample" "$DEST/samples/$slug"
        chown -R "$UID_ADMIN:$UID_ADMIN" "$DEST/samples/$slug"
        chmod -R go-rwx "$DEST/samples/$slug"
    fi
done

# --- admin login: generated once, the plain password is kept only in a root-only file
if [ ! -f "$DEST/admin.env" ]; then
    python3 - "$DEST" "$PUBLIC_BASE" <<'PY'
import base64, hashlib, os, secrets, sys
dest, public_base = sys.argv[1], sys.argv[2]
password = secrets.token_urlsafe(18)
salt = secrets.token_bytes(16)
digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
hash_str = "scrypt:16384:8:1:%s:%s" % (base64.b64encode(salt).decode(), base64.b64encode(digest).decode())
old = os.umask(0o077)
with open(os.path.join(dest, "admin.env"), "w") as f:
    f.write("IV_PUBLIC_BASE=%s\nIV_ADMIN_USER=admin\nIV_ADMIN_HASH=%s\n" % (public_base, hash_str))
with open(os.path.join(dest, "admin_credentials.txt"), "w") as f:
    f.write("url: %s/iv-admin/\nlogin: admin\npassword: %s\n" % (public_base, password))
os.umask(old)
PY
else
    sed -i "s#^IV_PUBLIC_BASE=.*#IV_PUBLIC_BASE=${PUBLIC_BASE}#; /^IV_HOME=/d" "$DEST/admin.env"
fi
chmod 600 "$DEST/admin.env" "$DEST/admin_credentials.txt"

# --- controller (root, the only Docker-facing process)
install -m 644 "$SRC/ctl/interview-ctl.service" /etc/systemd/system/interview-ctl.service
systemctl daemon-reload
systemctl enable -q interview-ctl.service
systemctl restart interview-ctl.service
for _ in $(seq 1 30); do [ -S /run/interview-ctl/ctl.sock ] && break; sleep 1; done
[ -S /run/interview-ctl/ctl.sock ] || { echo "controller socket did not appear" >&2; exit 1; }
docker network inspect interview_net >/dev/null

# --- admin container
docker compose -f "$DEST/admin/compose.yml" up -d --build --remove-orphans --quiet-pull 2>&1 | tail -3
docker network rm interview_default >/dev/null 2>&1 || true

# --- nginx: snippet + one include line in the :443 server, validated before reload
install -m 644 "$SRC/nginx-interview.conf" "$SNIPPET"
if ! grep -q "muse-slop-interview.conf" "$SITE"; then
    cp -p "$SITE" "$SITE.bak-interview"
    sed -i "s|^    # ---- SFTPGo ----.*|    include $SNIPPET;\n\n&|" "$SITE"
fi
if ! nginx -t; then
    [ -f "$SITE.bak-interview" ] && cp -p "$SITE.bak-interview" "$SITE"
    nginx -t
    echo "nginx config invalid, site restored" >&2
    exit 1
fi
systemctl reload nginx

docker compose -p interview -f "$DEST/compose.yml" --env-file /dev/null pull -q 2>/dev/null || true
echo "installed; admin credentials: $DEST/admin_credentials.txt"
