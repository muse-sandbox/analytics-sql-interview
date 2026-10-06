#!/usr/bin/env bash
# Install / update the interview stack on the server. Run as root from a copy of this repository:
#   ./install.sh https://<server address>
# (deploy.sh does the copy + this call from a laptop over ssh).
# Idempotent: re-running updates the code and configs and keeps credentials, data, volumes and
# samples. Samples committed under samples/<slug>/ are copied to the server only if the server
# does not have a sample with that slug yet.
# The nginx site is SITE (default: the muse_slop site); the include line is inserted before its
# "# ---- SFTPGo ----" section marker.
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
DEST=/opt/interview
PUBLIC_BASE="${1:?usage: install.sh https://<server address>}"
PUBLIC_BASE="${PUBLIC_BASE%/}"
SITE="${SITE:-/etc/nginx/sites-available/muse-slop}"
SNIPPET=/etc/nginx/snippets/muse-slop-interview.conf

install -d -m 755 "$DEST" "$DEST/admin" "$DEST/clickhouse" "$DEST/metabase" "$DEST/uploads"
install -d -m 700 "$DEST/state" "$DEST/samples"
install -m 644 "$SRC/compose.yml" "$DEST/compose.yml"
install -m 644 "$SRC/clickhouse/config.xml" "$SRC/clickhouse/users.xml" "$DEST/clickhouse/"
install -m 644 "$SRC/metabase/log4j2.xml" "$DEST/metabase/"
install -m 644 "$SRC/admin/app.py" "$SRC/admin/requirements.txt" "$DEST/admin/"

for sample in "$SRC"/samples/*/; do
    [ -f "$sample/sample.json" ] || continue
    slug="$(basename "$sample")"
    if [ ! -e "$DEST/samples/$slug" ]; then
        cp -R "$sample" "$DEST/samples/$slug"
        chmod -R go-rwx "$DEST/samples/$slug"
    fi
done

if [ ! -x "$DEST/admin/.venv/bin/python" ]; then
    python3 -m venv "$DEST/admin/.venv"
fi
"$DEST/admin/.venv/bin/pip" install -q --upgrade pip
"$DEST/admin/.venv/bin/pip" install -q -r "$DEST/admin/requirements.txt"

# Admin login: generated once, the plain password is kept only in a root-only file.
if [ ! -f "$DEST/state/admin.env" ]; then
    "$DEST/admin/.venv/bin/python" - "$DEST/state" "$PUBLIC_BASE" <<'PY'
import base64, hashlib, os, secrets, sys
state, public_base = sys.argv[1], sys.argv[2]
password = secrets.token_urlsafe(18)
salt = secrets.token_bytes(16)
digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
hash_str = "scrypt:16384:8:1:%s:%s" % (base64.b64encode(salt).decode(), base64.b64encode(digest).decode())
old = os.umask(0o077)
with open(os.path.join(state, "admin.env"), "w") as f:
    f.write("IV_HOME=/opt/interview\n")
    f.write("IV_PUBLIC_BASE=%s\n" % public_base)
    f.write("IV_ADMIN_USER=admin\n")
    f.write("IV_ADMIN_HASH=%s\n" % hash_str)
with open(os.path.join(state, "admin_credentials.txt"), "w") as f:
    f.write("url: %s/iv-admin/\nlogin: admin\npassword: %s\n" % (public_base, password))
os.umask(old)
PY
else
    sed -i "s#^IV_PUBLIC_BASE=.*#IV_PUBLIC_BASE=${PUBLIC_BASE}#" "$DEST/state/admin.env"
fi
chmod 600 "$DEST/state/"*

# nginx: snippet + one include line in the :443 server, validated before reload.
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

install -m 644 "$SRC/interview-admin.service" /etc/systemd/system/interview-admin.service
systemctl daemon-reload
systemctl enable -q interview-admin.service
systemctl restart interview-admin.service

docker compose -p interview -f "$DEST/compose.yml" --env-file /dev/null pull -q 2>/dev/null || true
echo "installed; admin credentials: $DEST/state/admin_credentials.txt"
