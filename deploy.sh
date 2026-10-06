#!/usr/bin/env bash
# Deploy this repository to the interview server from a laptop.
#   ./deploy.sh <ssh host> https://<server address>
# Copies the tree to /root/analytics-sql-interview on the server and runs install.sh there as root.
set -euo pipefail

HOST="${1:?usage: deploy.sh <ssh host> https://<server address>}"
PUBLIC_BASE="${2:?usage: deploy.sh <ssh host> https://<server address>}"
HERE="$(cd "$(dirname "$0")" && pwd)"

COPYFILE_DISABLE=1 tar czf - -C "$HERE" --exclude=.git --exclude=__pycache__ --exclude=.DS_Store . \
    | ssh "$HOST" 'rm -rf /root/analytics-sql-interview && mkdir -p /root/analytics-sql-interview && tar xzf - -C /root/analytics-sql-interview'
ssh "$HOST" "/root/analytics-sql-interview/install.sh '$PUBLIC_BASE'"
