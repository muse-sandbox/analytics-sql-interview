# analytics-sql-interview

An on-demand ClickHouse + Metabase stack for SQL / data-analyst interviews. It runs on a small
server next to other services, is started only for an interview, and is managed from a small
admin page:

```
https://<server>/iv-admin/          admin (own login; credentials: /opt/interview/admin_credentials.txt, root only)
https://<server>/m/<token>/         Metabase for the candidate; <token> is new on every start
https://<server>/iv-task/<token>/   the active sample's task for the candidate
```

## Interviewer flow

1. Open `/iv-admin/`, sign in, press **Start** and pick an auto-stop timer (2/4/8/24 h or never).
   It is ready in ~1–2 minutes; the very first start, or the first one after a wipe, takes longer
   because it sets up Metabase. Metabase is configured automatically: an admin user, the
   ClickHouse connection (`Interview ClickHouse` → database `interview`) and SQL access for all users.
2. **Load a CSV / TSV**: upload a file, up to 1 GB (`.gz/.zst/.xz/.bz2/.lz4` are read as is).
   On the next page choose the format and delimiter, check the preview, then either keep the
   schema ClickHouse detected or write your own (one `column Type` per line, in the file's column
   order — names do not have to match the header). Set `ORDER BY` if you want, the number of
   tolerated bad rows, and whether to replace an existing table. The table is loaded into a
   temporary table first and swapped in, so a failed load never damages the existing table.
   Metabase re-syncs the schema afterwards.
3. **Create user**: this generates `candidate-xxxxxx@interview.local` with a random password and
   checks that it can log in. The copy block holds the URL, login and password to send.
4. After the interview: **Stop** removes the containers and keeps tables, users and questions on
   disk for the next start. **Stop and wipe data** also deletes the volumes, so the next start is a
   fresh install. Stopped, the stack takes no RAM or CPU. Only two small processes keep running:
   the admin container (~80 MB) and the controller (~10 MB).

## Samples (saved interview cases)

A sample is stored on the server in `/opt/interview/samples/<slug>/` and is never touched by a wipe.
**This repository is public, so sample data, interviewer readmes and attachments stay on the
server** (they are git-ignored here). A sample committed under `samples/<slug>/` is copied to the
server by `install.sh` only if the server does not have that slug yet.

| file | what it holds |
| --- | --- |
| `sample.json` | name and, per table, its schema, ORDER BY and row count |
| `data/*.csv.gz` | the table data |
| `task.md` | the task for the candidate |
| `readme.md` | interviewer notes, rendered only in the admin |
| `assets/` | files the readme links to, e.g. `![](assets/chart.png)` |

Using samples:

- **Start with a sample.** On Start, pick a sample. Its tables are recreated after Metabase is ready.
  You can also press **load** on a sample while the stack is already running.
- **What loading does:**
  - recreates the sample's tables;
  - makes it the *active* sample;
  - shows the public task page `/iv-task/<token>/` in the admin and adds its link to each
    candidate's credentials block. The token is new on every start, and the page answers 404 while
    the stack is stopped;
  - saves the Metabase SQL question "<name> — start here", pinned in Our analytics. It carries the
    task link in its comments and a starter `select`.
- **Save current tables as a sample:** choose the tables, write task.md and readme.md, and attach files.
  Re-saving with "overwrite" replaces the data and keeps the existing attachments. On a sample's page
  you can read the readme, preview the task, edit both texts and delete the sample.

## What the candidate can do

ClickHouse user `metabase`: `readonly=2`, `SELECT, SHOW ON interview.*` only (no DDL, no `file()` /
`url()`, no `system.users`), 800 MB per query, 120 s timeout, 2 threads. In Metabase the user is a
normal user (not an admin) with the query builder and native SQL.

## Resources and logs

| container | memory limit | CPU limit |
| --- | --- | --- |
| clickhouse | 1.5 GB | 2 |
| metabase (JVM `-Xmx1g`) | 1.75 GB | 1.5 |
| metabase-db (Postgres) | 256 MB | 0.5 |

All three have `oom_score_adj=500`: under memory pressure the kernel kills them before
sftpgo/nginx. Measured while ready: ~1.5 GB in total (Metabase 1.3 GB, ClickHouse 116 MB, Postgres 62 MB).

Logs are kept to a minimum. Docker keeps at most 1 MB per container (`local` driver, one file).
ClickHouse has no log files (console, `warning` level, `/var/log/clickhouse-server` on a 16 MB
tmpfs) and none of its `system.*_log` tables. Metabase logs at `WARN` level to the console only.
Postgres has no log collector. nginx `access_log off` covers `/iv-admin/` and `/m/`. The admin logs
nothing (`--no-access-log`, journald warnings only). Pending uploads are deleted after 24 h.

## Security model

The goal: someone who gets into the admin can do no more than what the admin offers inside this
project. They cannot run commands on the host, read files outside the project, or reach the
network beyond the stack.

- **No Docker access in the admin.** The admin web app runs in its own container:
  - user `10001` (`ivadmin`), read-only root filesystem, all capabilities dropped,
    `no-new-privileges`, 256 MB / 0.5 CPU / 128 pids;
  - no Docker socket;
  - it sees only `/opt/interview/{state,uploads,samples}`, nothing else from the host.
- **The controller is the only way to act on the host.** `ctl/interview_ctl.py` runs as root under
  systemd and is the only process that talks to Docker.
  - It listens on `/run/interview-ctl/ctl.sock` (`root:ivadmin 0660`).
  - It accepts five requests: `up`, `down`, `ps`, `stats`, `logs`. Their parameters are checked
    against regexes (site URL, 32-hex passwords, service name from a list), requests are capped
    at 4 KB, and nothing reaches a shell.
  - The systemd unit is hardened: `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
    `NoNewPrivileges`.
- **Stack containers.** ClickHouse, Metabase and Postgres run as non-root users (101, 2000, 70)
  with a read-only root filesystem, no capabilities and `no-new-privileges`. They mount only
  their own config files and volumes; ClickHouse also gets the uploads directory read-only.
  ClickHouse has no published port.
- **Network.** Every container sits on `interview_net` (bridge `br-interview`, `172.30.77.0/24`).
  The controller keeps four iptables rules in `DOCKER-USER` and `INPUT`. Containers can talk to
  each other and answer incoming connections. They cannot open new connections anywhere else:
  the internet, the host's own services (ssh, SFTPGo, nginx) and the cloud metadata endpoint are
  all closed. The only ways in are nginx → `127.0.0.1:18090` (admin) and `127.0.0.1:13000` (Metabase).
- **ClickHouse users.**
  - `loader` (used by the admin) works only with tables in `interview`, plus `file()` inside
    `user_files` (the uploads mount). No `url`/`remote`/`s3`/`mysql`/…, no dictionaries,
    no URL/File engines, no other databases.
  - `metabase` (used by candidates) has read-only `SELECT, SHOW ON interview.*`.
- **Admin app.**
  - Loading from a URL has been removed; only file uploads remain.
  - Limits:
    - an upload — 1 GB;
    - uploads + samples + ClickHouse tables together — 8 GB;
    - task.md and readme.md — 200 KB each;
    - attachments — 10 MB each, `png/jpg/jpeg/gif/webp/csv/txt/pdf` only, so no SVG or HTML;
    - at most 50 samples.
  - Markdown is rendered with raw HTML escaped and `javascript:` links refused.
  - Every page sends CSP, `nosniff`, `same-origin` referrer policy and `DENY` framing headers. The public task
    page sends `default-src 'none'`.
- **Secrets on the host.** The plain admin password and the controller secrets (`ctl/`) are
  root-only and are not mounted into any container.

What admin access still allows, by design: start and stop the stack, load and drop tables,
create and deactivate candidate users, manage samples, and see the Metabase admin login.
Anything done as the Metabase admin stays inside the Metabase container, which has no host
access and no network beyond the stack.

## Files

| file | installed as |
| --- | --- |
| `compose.yml`, `clickhouse/*.xml`, `metabase/log4j2.xml` | `/opt/interview/…` (root, read-only for containers) |
| `admin/` (`app.py`, `Dockerfile`, `compose.yml`, `requirements.txt`) | `/opt/interview/admin/`, image `interview-admin:local`, project `interview-admin` (`restart: unless-stopped`) |
| `ctl/interview_ctl.py`, `ctl/interview-ctl.service` | `/opt/interview/ctl/` (root 700), `/etc/systemd/system/` |
| `nginx-interview.conf` | `/etc/nginx/snippets/muse-slop-interview.conf`, included from the `:443` server |

On the server:

| path | owner, mode | what it holds |
| --- | --- | --- |
| `/opt/interview/admin.env` | root 600 | admin login hash, public address |
| `/opt/interview/admin_credentials.txt` | root 600 | the plain admin password |
| `/opt/interview/ctl/` | root 700 | Postgres password, `stack.env` |
| `/opt/interview/state/` | ivadmin 700 | `secrets.json` (ClickHouse passwords), `stack.json`, `metabase.json`, `candidates.json` |
| `/opt/interview/samples/` | ivadmin 700 | samples |
| `/opt/interview/uploads/` | ivadmin 711 | pending CSV uploads |

The token check works like this: nginx `auth_request` calls `/_internal/mbcheck`, which is not
reachable from outside. A token that does not match the current one, or a stack that is not
ready, gets a 404.

## Command line on the server

`install.sh` puts `iv` into `/usr/local/bin`. It drives the admin as root on the server, so scripts and agents don't need the browser:
`iv status`, `iv start --sample <slug>`, `iv user "<name>"`, `iv upload FILE TABLE --schema FILE`, `iv sql "SELECT …"`, `iv save-sample …`.
`iv help` lists all commands. The agent guide is `CLAUDE.md`.

## Install / update

From a laptop with root ssh access to the server:

```bash
./deploy.sh <ssh host> https://<server address>
```

`deploy.sh` copies the repository to the server and runs `install.sh` there. `install.sh` is
idempotent. It keeps credentials, data, volumes and samples, validates nginx before the reload and
restores the site file if validation fails. It also retires the old host-run admin (systemd unit
`interview-admin` and its venv) if present. It expects nginx with `auth_request`, Docker with the
compose plugin, `python3` and iptables. The nginx site file is `SITE` (default
`/etc/nginx/sites-available/muse-slop`), and the include line goes before its
`# ---- SFTPGo ----` marker.

The first install writes the admin login to `/opt/interview/admin_credentials.txt` (root only).

## Pitfalls already hit

- ClickHouse 26.x answers `compress=1` with ZSTD, but the Metabase JDBC driver reads only LZ4
  (`Invalid LZ4 magic byte: '-112'`). That is why the `analyst` profile sets
  `network_compression_method=LZ4`.
- The ClickHouse entrypoint chowns everything under `/var/lib/clickhouse`, including the read-only
  uploads mount. `CLICKHOUSE_DO_NOT_CHOWN=1` stops it.
- `background_pool_size=4` requires the `merge_tree` `number_of_free_entries_*` settings to be lowered too.
- The docker `local` log driver refuses `max-file=1` unless `compress=false`.
- nginx regex locations containing `{n,m}` must be quoted.
- Metabase as a non-root user needs a writable `MB_PLUGINS_DIR` (a tmpfs here). Its entrypoint
  switches users only when started as root.
