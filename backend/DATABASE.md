# SQLite persistence and recovery

The application uses SQLite. By default, the database remains at
`backend/typoguard.db` for local development. Set `TYPOGUARD_SQLITE_PATH` to
change the file location. On Render, attach a persistent disk to a **paid** web
service and set this variable to a file beneath its mount path (for example,
`/var/data/typoguard.db` when the mount is `/var/data`). A database left on the
service's ordinary filesystem is ephemeral.

Startup creates missing tables and applies the existing additive fingerprint
column migration. Both operations are repeatable; they do not recreate the
database or delete rows. The persistence test creates an isolated database,
reopens it, runs startup schema work twice, then backs it up and restores it.
It does not modify the checked-in local database.

## Backup and restore

For a consistent SQLite backup while the service may be writing, use SQLite's
online backup API rather than copying the live database file. Run this from a
maintenance process with access to the mounted disk, replacing the paths with
the configured database and a backup destination:

```python
import sqlite3

with sqlite3.connect("/var/data/typoguard.db") as source:
    with sqlite3.connect("/var/data/typoguard-backup.db") as backup:
        source.backup(backup)
```

To restore, stop the service or otherwise prevent writes, then use the backup
database as the source and the configured database path as the destination with
the same `source.backup(destination)` API. Verify the restored database before
restarting the service. Keep at least one backup outside the service disk; a
backup on the same disk does not protect against disk loss. Restrict backup
access because it contains application data.

Render persistent disks are single-instance storage: a service with an attached
disk cannot scale horizontally, and deploys have a short interruption while the
disk moves to the new instance. Disk storage is billed at the current per-GB
rate. This fits the current small, single-instance dataset and avoids a
database migration, but it is not a good fit for multi-instance availability
or higher write concurrency. Render Postgres is the more suitable next step
when those requirements justify the added monthly database cost and an
explicit, backed-up migration. Do not switch a connection setting and assume
that it transfers SQLite data.

This repository does not yet automate off-host backups or a SQLite-to-Postgres
migration. The current local database contains 10 trusted-domain rows and 10
fingerprint rows; the CSV is also available as the trusted-domain source, but
it does not replace backing up database state.
