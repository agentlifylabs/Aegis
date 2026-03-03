# Aegis Backup and Restore

The Aegis event log is the **source of truth** for all agent runs. Backup
procedures differ by storage backend.

---

## SQLite (development / single-node)

### Backup

SQLite's online backup API produces a consistent snapshot without stopping
aegisd:

```bash
# Hot backup using sqlite3 CLI (safe while aegisd is running)
sqlite3 /var/lib/aegis/aegis.db ".backup '/var/lib/aegis/backup/aegis-$(date +%Y%m%dT%H%M%S).db'"
```

Or using the `VACUUM INTO` command (requires SQLite ≥ 3.27):

```bash
sqlite3 /var/lib/aegis/aegis.db "VACUUM INTO '/var/backups/aegis/aegis-$(date +%Y%m%dT%H%M%S).db'"
```

**Automate with cron:**

```cron
# Daily backup at 02:00, keep 14 days
0 2 * * * aegis sqlite3 /var/lib/aegis/aegis.db \
  "VACUUM INTO '/var/backups/aegis/aegis-$(date +\%Y\%m\%dT\%H\%M\%S).db'" \
  && find /var/backups/aegis -name '*.db' -mtime +14 -delete
```

### Restore

```bash
# 1. Stop aegisd
sudo systemctl stop aegisd

# 2. Replace database
cp /var/backups/aegis/aegis-20260101T020000.db /var/lib/aegis/aegis.db
chown aegis:aegis /var/lib/aegis/aegis.db

# 3. Verify integrity
sqlite3 /var/lib/aegis/aegis.db "PRAGMA integrity_check;"

# 4. Restart
sudo systemctl start aegisd
```

---

## PostgreSQL (production)

### Continuous archiving (WAL — recommended)

Enable WAL archiving in `postgresql.conf`:

```ini
wal_level = replica
archive_mode = on
archive_command = 'cp %p /var/lib/pgwal/%f'
```

Use [pgBackRest](https://pgbackrest.org/) or [Barman](https://pgbarman.org/)
for managed WAL archiving and point-in-time recovery.

### pg_dump (logical backup)

```bash
# Full logical backup (plain SQL, compresses well)
pg_dump \
  --host=postgres \
  --username=aegis \
  --dbname=aegis \
  --format=custom \
  --file=/var/backups/aegis/aegis-$(date +%Y%m%dT%H%M%S).pgdump

# Verify the dump
pg_restore --list /var/backups/aegis/aegis-*.pgdump | head -20
```

**Automate with cron (runs inside the Postgres container or a sidecar):**

```bash
#!/bin/bash
# /usr/local/bin/aegis-backup.sh
set -euo pipefail
BACKUP_DIR=/var/backups/aegis
TIMESTAMP=$(date +%Y%m%dT%H%M%S)
FILE="$BACKUP_DIR/aegis-$TIMESTAMP.pgdump"

pg_dump \
  --host="${PGHOST:-postgres}" \
  --username="${PGUSER:-aegis}" \
  --dbname="${PGDATABASE:-aegis}" \
  --format=custom \
  --file="$FILE"

# Retain 30 days
find "$BACKUP_DIR" -name '*.pgdump' -mtime +30 -delete
echo "Backup complete: $FILE"
```

### Restore from pg_dump

```bash
# 1. Create a fresh database (or drop and recreate)
psql --host=postgres --username=aegis \
  -c "DROP DATABASE IF EXISTS aegis_restore; CREATE DATABASE aegis_restore;"

# 2. Restore
pg_restore \
  --host=postgres \
  --username=aegis \
  --dbname=aegis_restore \
  --verbose \
  /var/backups/aegis/aegis-20260101T020000.pgdump

# 3. Verify hash chain integrity via aegisctl
aegisctl verify --tenant-id <TENANT> --session-id <SESSION> --server http://localhost:8080
```

### Point-in-time recovery (PITR)

With WAL archiving enabled:

```bash
# In recovery.conf (PG < 12) or postgresql.conf (PG ≥ 12)
restore_command = 'cp /var/lib/pgwal/%f %p'
recovery_target_time = '2026-01-15 03:00:00'
recovery_target_action = 'promote'
```

---

## Verifying backup integrity

After any restore, verify the event-log hash chain for each active session:

```bash
# Via aegisctl
aegisctl verify --tenant-id <TENANT_ID> --session-id <SESSION_ID> \
  --server http://localhost:8080

# Bulk verify all sessions (jq required)
curl -s "http://localhost:8080/v1/events?tenant_id=<TENANT_ID>&limit=1000" \
  | jq -r '.Events[].session_id' | sort -u \
  | xargs -I{} aegisctl verify --tenant-id <TENANT_ID> --session-id {} \
      --server http://localhost:8080
```

A clean restore reports `OK: chain valid for session <ID>` for every session.

---

## Telemetry traces (NDJSON)

The NDJSON trace file at `/var/lib/aegis/traces.ndjson` is append-only.
Back it up alongside the database:

```bash
cp /var/lib/aegis/traces.ndjson \
   /var/backups/aegis/traces-$(date +%Y%m%dT%H%M%S).ndjson
```

Traces are not required for restore — they are a secondary observability
artefact. The event log is the authoritative source of truth.
