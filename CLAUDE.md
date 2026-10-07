# Agent guide — analytics-sql-interview

An on-demand ClickHouse + Metabase stack for SQL / data-analyst interviews, plus an admin page
and saved interview "samples" (tables + candidate task + interviewer notes). Human-facing details:
`README.md`. This file is the operating manual for an agent.

## Rules (STRICT)

1. **This repository is public.** Never commit sample data (`samples/*/data/`), interviewer notes
   (`samples/*/readme.md`), attachments, candidate credentials, server addresses or passwords.
   `.gitignore` already blocks the sample parts; don't work around it. A candidate must not be able
   to find a task's answers here.
2. **Operate the stack only through `iv` on the server** (`ssh <host> iv …`), never with
   `docker`/`docker compose` by hand, and never by editing `/opt/interview/state/*.json`. `iv` goes
   through the admin web app, so the same validation, limits and Metabase setup apply.
3. **Change the server only by deploying this repository** (`./deploy.sh`). Never hand-edit files under
   `/opt/interview`, the nginx snippet or the systemd unit — the next deploy overwrites them and
   the repo stops describing reality.
4. **Never print secrets into the chat:**
   - the admin password (`/opt/interview/admin_credentials.txt`);
   - `/opt/interview/state/secrets.json` and `/opt/interview/ctl/*`;
   - the Metabase admin login.
   Candidate credentials from `iv user` exist to be handed out — pass them to the user, but don't
   echo them anywhere else.
5. **Ask before anything the user did not request** that stops or destroys state:
   - `iv stop` changes nothing but frees memory;
   - `iv wipe --yes` deletes all tables, Metabase users and questions;
   - `iv delete-sample` deletes a sample for good;
   - a deploy restarts the admin.
   Check `iv status` first. If the stack is `ready`, someone may be in the middle of an interview.
6. **Don't weaken the security model** (§ "Security invariants") when changing code. If a feature
   seems to need it, stop and ask.

## Where it runs

- **Server.** One Linux host next to other services (SFTPGo, nginx); `README.md` describes the layout.
  Reach it over ssh as root. The ssh host alias is per-person: ask the user for it if it is not in
  the conversation. The current team uses `muse_slop`.
- **Public base URL** (`https://<server address>`) is passed to `deploy.sh`/`install.sh`. On the
  server it is stored in `/opt/interview/admin.env`, and `iv status` shows it inside every URL.
- **`iv`** is installed by `install.sh` to `/usr/local/bin/iv` and must run as root on the server.

## Operating the stack (`ssh <host> iv …`)

| command | what it does |
| --- | --- |
| `iv status` | JSON: `phase` (stopped / starting / ready / stopping / error), `message`, Metabase `url`, `task_url`, `auto_stop`, active `sample` |
| `iv start [--sample SLUG] [--hours 2\|4\|8\|24\|0] [--wipe-at-end] [--no-wait]` | start (waits until ready, ~1.5–2 min; the first start after a wipe sets up Metabase). With `--sample`, the sample's tables, task page and Metabase "start here" question are created |
| `iv stop` · `iv wipe --yes` · `iv extend` | stop (data kept) · stop and delete volumes · +2 h to the auto-stop timer |
| `iv samples` · `iv load-sample SLUG` | list samples · make the running stack hold exactly that sample: its tables are recreated and **every other table in `interview` is dropped**; other samples' "start here" questions are archived |
| `iv infer FILE [--format F] [--delim D] [--no-nullable]` | print the schema ClickHouse would infer, without creating anything |
| `iv upload FILE TABLE [--schema FILE] [--order-by EXPR] [--format F] [--delim D] [--replace] [--errors N] [--no-nullable]` | load a CSV/TSV into `interview.TABLE`. With `--schema` (one `column Type` per line, in the file's column order) the types are exactly those; names may differ from the header |
| `iv drop TABLE` · `iv tables` | drop · list with rows and size |
| `iv sql "SELECT …"` | run a query as the **candidates'** read-only ClickHouse user (it is the right way to check what a candidate sees) |
| `iv user [NOTE]` · `iv users` · `iv deactivate ID` | candidate Metabase user (prints URL / login / password / task) · list · deactivate |
| `iv save-sample NAME --tables T1,T2 --task TASK.md --readme README.md [--asset FILE]… [--overwrite]` · `iv set-texts SLUG [--task F] [--readme F]` · `iv delete-sample SLUG --yes` | save the current tables + texts as a sample · replace only the texts (no stack needed) · delete one |

`iv` exits non-zero and prints the admin's error on any failure. Files for `upload`, `infer`,
`save-sample` must be on the server: `scp` them to `/root/` first and delete them afterwards.

**Typical interview prep:** `iv status` → `iv start --sample <slug> --hours 4` → `iv user "<candidate name>"`
→ give the user the printed URL / login / password / task link. During the interview, the
interviewer watches `/iv-admin/live`: Claude evaluates each candidate query (README § "Live evaluation"). **Afterwards:** `iv stop`, or
`iv wipe --yes` only if the user asks.

## Creating a new sample (interview case)

1. **Prepare the data outside this repo.**
   - Anonymize: random ids instead of real ones, every timestamp shifted by a whole number of weeks
     (weekdays stay right), money multiplied by a secret factor, countries collapsed into regions.
   - No personal data, no real account ids.
   - Keep it small: tens of thousands of rows load in seconds; the project limit is 8 GB in total
     and 1 GB per file.
2. **Write the files:**
   - CSV with a header row;
   - a schema file per table with exact types. Without one, ClickHouse infers `Nullable(...)` for
     every column, and an `IS NULL` check on a `LEFT JOIN` then behaves differently from a typed
     table.
3. **Load** into a stack with no other tables you care about. Loading a sample later drops every other table anyway. `scp` the files to the server, then
   `iv upload data.csv events --schema events.schema --order-by "(event_at, id)"` for each table.
4. **Verify as the candidate.** `iv tables` shows the row counts. Run the reference solution with
   `iv sql "<reference SQL>"` and compare it with the numbers you expect, e.g. from a pandas
   calculation of the same thing.
5. **Write the texts:**
   - `task.md` — for the candidate, in **English**. Include the tables and columns, the data
     snapshot time, the task, and the expected time. No hints and no answers.
   - `readme.md` — interviewer notes:
     - where the data came from and how it was anonymized;
     - the traps planted in the data and what a strong candidate does about each;
     - the reference answer and SQL.
     Attachments go in as `--asset` and are referenced as `![](assets/<file>)`. Allowed types:
     png, jpg, jpeg, gif, webp, csv, txt, pdf (no SVG or HTML), up to 10 MB each.
6. **Save:** `iv save-sample "<Name>" --tables a,b --task task.md --readme readme.md --asset chart.png`.
   The slug is derived from the name. Re-saving with `--overwrite` replaces the data and keeps the
   attachments.
7. **Test the real flow end to end** (when nobody is interviewing):
   - `iv stop`, then `iv start --sample <slug>`;
   - open `task_url` and check the page;
   - `iv user test` and `iv sql` checks;
   - `iv deactivate <id>`.
   To edit the texts later, use the sample page in the admin, or re-save.

## Changing the code

Layout:
- `admin/app.py` — FastAPI admin, runs in its own container;
- `ctl/interview_ctl.py` — root controller, the only Docker-facing process;
- `compose.yml` — the stack;
- `clickhouse/`, `metabase/` — configs;
- `nginx-interview.conf` — the nginx snippet;
- `install.sh`, `deploy.sh`, `bin/iv`.

**Security invariants** — keep all of these true:
- **Admin container:**
  - uid 10001, read-only rootfs, `cap_drop: ALL`, `no-new-privileges`, no Docker socket;
  - mounts only `/opt/interview/{state,uploads,samples}` and the controller socket dir.
  - Plain secrets (`admin_credentials.txt`, `ctl/`) are never mounted into it.
- **Controller:**
  - accepts a fixed verb list (`up`, `down`, `ps`, `stats`, `logs`) with regex-validated
    parameters, a 4 KB request cap, and no shell;
  - new verbs need the same discipline.
- **Stack containers:** non-root, read-only rootfs, `cap_drop: ALL`, `no-new-privileges`, on
  `interview_net`. ClickHouse has no published port; Metabase is published only on
  `127.0.0.1:13000`, the admin on `127.0.0.1:18090`.
- **Firewall:** the `DOCKER-USER`/`INPUT` rules for `br-interview` let no container open a new
  connection outside the stack.
- **ClickHouse users:**
  - `loader` — only the `interview` database, plus `file()` inside `user_files`;
  - `metabase` — read-only.
  - No `url`/`remote`/`s3`/… grants.
- **Admin app:**
  - no server-side fetching of user-supplied URLs;
  - Markdown rendered with raw HTML disabled;
  - CSP on every page;
  - upload, disk, text and attachment limits;
  - attachment type whitelist;
  - same-origin check on every POST.
- **The Anthropic key stays root-only** (`/opt/interview/ctl/anthropic_api_key`).
  - Only the controller's `evaluate` verb uses it.
  - Model, effort and instructions are fixed in `ctl/interview_ctl.py`, and calls are
    rate-limited.
  - Never mount the key into a container, print it, or move prompt control into the admin.
  - The candidates' user must not be able to read `system.query_log`.
- **Referrer policy stays `same-origin`.** With `no-referrer`, browsers send `Origin: null` on form
  POSTs and every browser login fails as "cross-origin".

**Deploy:** `./deploy.sh <ssh host> https://<server address>`. It is idempotent: it keeps state,
volumes and samples, validates nginx and restores it on failure, rebuilds the admin image and
restarts it. A restarted admin re-attaches to a running stack; its Metabase URL stays the same.

**Verify after a deploy:**
1. `iv status`; `systemctl is-active interview-ctl`.
2. The admin login page answers 200.
3. When the stack is free: `iv stop && iv start --sample <slug>`, then `iv user`, `iv sql`, and
   `iv deactivate`.
4. If you touched isolation, probe it from inside the containers, as the commit history does:
   - outbound TCP to 1.1.1.1, 169.254.169.254 and the bridge gateway must time out;
   - host paths must not be visible from the admin container;
   - the controller must refuse unknown verbs.
5. Test browser-facing changes in a real browser too. curl sets `Origin` itself and hides some bugs.

## Known pitfalls

- ClickHouse 26.x answers `compress=1` with ZSTD; the Metabase JDBC driver reads only LZ4. Keep
  `network_compression_method=LZ4` in the `analyst` profile.
- Containers run as fixed uids (101 ClickHouse, 2000 Metabase, 70 Postgres). Volumes created by an
  older root-run version would need a `chown`; a wipe recreates them correctly.
- Metabase as non-root needs a writable `MB_PLUGINS_DIR` (tmpfs).
- `background_pool_size=4` requires the lowered `merge_tree` `number_of_free_entries_*` settings.
- The docker `local` log driver refuses `max-file=1` unless `compress=false`.
- nginx regex locations containing `{n,m}` must be quoted.
- With auto-inferred schemas, the `Nullable` columns change how `LEFT JOIN` misses look (`NULL`
  instead of the default). Write reference SQL against the typed schema the sample actually uses.
