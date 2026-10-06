# analytics-sql-interview

An on-demand ClickHouse + Metabase stack for SQL / data-analyst interviews. It runs on a small
server next to other services, is started only for an interview, and is managed from a small
admin page:

```
https://<server>/iv-admin/          admin (own login; credentials: /opt/interview/state/admin_credentials.txt, root only)
https://<server>/m/<token>/         Metabase for the candidate; <token> is new on every start
https://<server>/iv-task/<token>/   the active sample's task for the candidate
```

## Interviewer flow

1. Open `/iv-admin/`, sign in, press **Start** and pick an auto-stop timer (2/4/8/24 h or never).
   It is ready in ~1–2 minutes; the very first start, or the first one after a wipe, takes longer
   because it sets up Metabase. Metabase is configured automatically: an admin user, the
   ClickHouse connection (`Interview ClickHouse` → database `interview`) and SQL access for all users.
2. **Load a CSV / TSV**: upload a file or paste a link (`.gz/.zst/.xz/.bz2/.lz4` are read as is).
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
   fresh install. Stopped, the stack takes no RAM or CPU; only the admin itself runs (~75 MB).

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

## Files

| file | installed as |
| --- | --- |
| `compose.yml`, `clickhouse/*.xml`, `metabase/log4j2.xml` | `/opt/interview/…` |
| `admin/app.py`, `admin/requirements.txt` | `/opt/interview/admin/` (venv `.venv`) |
| `interview-admin.service` | `/etc/systemd/system/` (uvicorn on `127.0.0.1:18090`) |
| `nginx-interview.conf` | `/etc/nginx/snippets/muse-slop-interview.conf`, included from the `:443` server |

State in `/opt/interview/state/` (0700): `admin.env` (scrypt hash of the admin password),
`secrets.json` (Postgres/ClickHouse passwords), `stack.json` (phase, current token, timer),
`metabase.json` (Metabase admin + db id) and `candidates.json`.

The token check works like this: nginx `auth_request` calls `/_internal/mbcheck`, which is not
reachable from outside. A token that does not match the current one, or a stack that is not
ready, gets a 404.

## Install / update

From a laptop with root ssh access to the server:

```bash
./deploy.sh <ssh host> https://<server address>
```

`deploy.sh` copies the repository to the server and runs `install.sh` there. `install.sh` is
idempotent. It keeps credentials, data, volumes and samples, validates nginx before the reload and
restores the site file if validation fails. It expects nginx with `auth_request`, Docker with the
compose plugin, and `python3-venv`. The nginx site file is `SITE` (default
`/etc/nginx/sites-available/muse-slop`), and the include line goes before its
`# ---- SFTPGo ----` marker.

The first install writes the admin login to `/opt/interview/state/admin_credentials.txt`
(root only).

## Pitfalls already hit

- ClickHouse 26.x answers `compress=1` with ZSTD, but the Metabase JDBC driver reads only LZ4
  (`Invalid LZ4 magic byte: '-112'`). That is why the `analyst` profile sets
  `network_compression_method=LZ4`.
- The ClickHouse entrypoint chowns everything under `/var/lib/clickhouse`, including the read-only
  uploads mount. `CLICKHOUSE_DO_NOT_CHOWN=1` stops it.
- `background_pool_size=4` requires the `merge_tree` `number_of_free_entries_*` settings to be lowered too.
- The docker `local` log driver refuses `max-file=1` unless `compress=false`.
- nginx regex locations containing `{n,m}` must be quoted.
