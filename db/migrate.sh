#!/usr/bin/env bash
# Apply pending SQL migrations to an already-running deployment.
#
# db/init.sql is mounted into docker-entrypoint-initdb.d, so it only ever runs
# against an empty data directory. Schema and policy changes therefore never
# reach an existing database on their own — that gap is how the live DB and
# init.sql drifted apart in the first place (see the ON_ERROR_STOP note in
# db/init.sql). Every file in db/migrations/ is applied once, in filename
# order, and recorded in the schema_migrations ledger.
#
# Each migration runs inside a single transaction together with its ledger
# insert, so a failure leaves neither behind. Statements that cannot run in a
# transaction block (CREATE INDEX CONCURRENTLY, some Timescale chunk
# operations) do not belong in a migration file — do those by hand.
#
# Usage: make migrate    (or: bash db/migrate.sh)
set -euo pipefail

cd "$(dirname "$0")/.."

[ -f .env ] || { echo "error: .env not found — run deploy/setup.sh first" >&2; exit 1; }

# Read individual keys rather than sourcing .env. Sourcing executes the file as
# shell: a secret containing shell metacharacters either aborts with a syntax
# error that echoes the secret to stderr, or gets executed outright if it
# contains $(...). Only non-secret identifiers are read here; the psql
# connection below authenticates over the container's local socket.
env_get() {
    sed -n "s/^[[:space:]]*$1=//p" .env | head -1 | sed 's/[[:space:]]*$//'
}

PG_USER="$(env_get PG_USER)"
PG_DB="$(env_get PG_DB)"

[ -n "$PG_USER" ] || { echo "error: PG_USER not set in .env" >&2; exit 1; }
[ -n "$PG_DB" ]   || { echo "error: PG_DB not set in .env" >&2; exit 1; }

if [ -z "$(docker compose ps --status running -q postgres 2>/dev/null)" ]; then
    echo "error: postgres is not running (try: docker compose up -d postgres)" >&2
    exit 1
fi

psql_run() {
    docker compose exec -T postgres \
        psql -v ON_ERROR_STOP=1 -U "$PG_USER" -d "$PG_DB" "$@"
}

psql_run -q -c "CREATE TABLE IF NOT EXISTS schema_migrations (
    filename   TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);"

shopt -s nullglob
migrations=(db/migrations/*.sql)
if [ ${#migrations[@]} -eq 0 ]; then
    echo "no migrations found in db/migrations/"
    exit 0
fi

applied=0
for path in "${migrations[@]}"; do
    name="$(basename "$path")"
    seen="$(psql_run -tAc \
        "SELECT 1 FROM schema_migrations WHERE filename = '$name'" | tr -d '[:space:]')"
    if [ "$seen" = "1" ]; then
        echo "  skip   $name"
        continue
    fi
    echo "  apply  $name"
    {
        echo "BEGIN;"
        cat "$path"
        echo "INSERT INTO schema_migrations (filename) VALUES ('$name');"
        echo "COMMIT;"
    } | psql_run -q -f -
    applied=$((applied + 1))
done

echo "────────────────────────────────────────"
echo "migrations applied: $applied"
