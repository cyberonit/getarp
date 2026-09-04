# Maintenance Scripts

## check-updates.sh

Checks all project dependencies for outdated versions and applies updates in three stages.

### Usage

```bash
bash maintenance/check-updates.sh check    # (default) dry-run — report only, no changes
bash maintenance/check-updates.sh apply    # update requirements pins + npm packages, pull base images
bash maintenance/check-updates.sh commit   # make up, make rules, then git commit + push the pins
```

(`--apply` is still accepted as an alias for the apply stage.)

### What each stage covers

| Stage | Step | Tool | Touches |
|---|---|---|---|
| check | report outdated Python/npm/base-image versions | `pip`, `npm`, docker | nothing |
| apply | re-pin Python packages | `pip` | `api/requirements.txt`, `pipeline/requirements.txt` |
| apply | update npm packages | `npm` (via Docker) | `frontend/package.json` |
| apply | pull latest base images | `docker compose pull` | local image cache |
| commit | rebuild + deploy images | `make up` (includes `--build`) | local images, running containers |
| commit | refresh + reload Suricata ET Open rules | `make rules` equivalent | `ids/suricata/rules/suricata.rules` |
| commit | commit + push dependency changes | `git` | only the files the apply stage edits |

### Workflow

1. `check` — review what's outdated.
2. Check any flagged `requirements.txt` pins before upgrading — some are pinned for compatibility reasons (e.g. `bcrypt==4.0.1` due to passlib 1.7.4 incompatibility with newer versions).
3. `apply` — update the pins and npm packages, pull new base images.
4. `commit` — rebuild and deploy the images (`make up`), refresh the Suricata rules, and commit + push the dependency bumps (only `requirements.txt` / `package.json` files; unrelated working-tree changes are left alone).

> Suricata rules can also be updated independently with `make rules`.

## backfill-geo.py

One-off backfill that repoints existing `ip_enrichment` rows at whichever geo
feed now has precedence. Written for the `ipinfo-lite` feed, which takes the
country ahead of `geolite`; adding a geo feed otherwise only changes rows as
they are re-enriched, so the map takes `ENRICHMENT_CACHE_TTL_DAYS` (14) to
converge. Already applied on this host (2026-09-04, 8 280 of 36 156 rows).

**Geo only** — reputation, confidence, categories, `is_known_attacker` and
`updated_at` are never touched, and it makes no API calls. Do *not* do this by
re-queueing the IPs with `force=1` instead: force bypasses the durable cache and
re-runs the whole tiered flow, which on a dataset this size puts ~33 000 IPs
through the Tier-2 activity gate, burns GreyNoise's weekly and AbuseIPDB's daily
quota within minutes, and then overwrites real verdicts with the `unknown` that
a quota-exhausted stub merges to.

```bash
# snapshot first — this is the only rollback
docker compose exec postgres psql -U "$PG_USER" -d "$PG_DB" -c \
  "CREATE TABLE ip_enrichment_geo_backup AS
     SELECT src_ip, country, asn, org FROM ip_enrichment;"

# dry run: reports what would change, writes nothing
docker compose run --rm --no-deps --user root \
  -v "$PWD/maintenance:/work:ro" --entrypoint python enrichment /work/backfill-geo.py

# apply
docker compose run --rm --no-deps --user root -e APPLY=1 \
  -v "$PWD/maintenance:/work:ro" --entrypoint python enrichment /work/backfill-geo.py
```

Idempotent: a second run reports 0 rows to update. It runs inside the
`enrichment` service so it inherits the database credentials and the `geoip`
volume; `--user root` is only needed so it can read the bind-mounted script.

## Scheduled runs

A crontab entry runs the **full cycle** (check → apply → commit) on the **1st of every month at 07:00** (installed by `deploy/setup.sh`):

```
0 7 1 * * { bash /home/getarp-intel/maintenance/check-updates.sh check && bash /home/getarp-intel/maintenance/check-updates.sh apply && bash /home/getarp-intel/maintenance/check-updates.sh commit; } >> /home/getarp-intel/maintenance/logs/updates-$(date +\%Y-\%m).log 2>&1
```

The stages are chained with `&&`, so a failed apply never deploys or pushes a half-applied update. Logs are written to `maintenance/logs/updates-YYYY-MM.log` (one file per month, excluded from git).

To review the latest log:

```bash
cat maintenance/logs/updates-$(date +%Y-%m).log
```

### Reverting a bad update

The commit stage pushes each month's dependency bumps as a single
`Maintenance: dependency updates YYYY-MM-DD` commit, so if an update breaks
the app, roll back with:

```bash
git log --oneline -5                       # find the maintenance commit
git revert <maintenance-commit> && git push
bash maintenance/check-updates.sh commit   # rebuild + deploy on the reverted pins
```
