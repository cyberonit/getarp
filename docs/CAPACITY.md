# Disk capacity plan — 3-year data retention

Sizing for a single-VM deployment (min 2 vCPU / 4 GB, recommended 4 vCPU / 8 GB) retaining **3 years** of
threat data in PostgreSQL/TimescaleDB. Postgres is the system of record; raw
sensor logs are rotated and only kept 14 days for forensics.

## Measured baseline (production, Jun 13 – Jul 6 2026, 23 days)

| Metric | Measured |
|---|---|
| events rate (steady state) | ~3,400 rows/day |
| events rate (worst burst day) | 171,000 rows/day |
| events storage | 962 MB / 809K rows ≈ 1.25 KB/row (uncompressed, incl. indexes) |
| attack_events rate | ~2,500 rows/day, ~250 B/row |
| new attacker IPs | ~200/day |
| ip_enrichment | ~9.4 KB/IP (raw provider JSONB dominates) |
| status_snapshots | ~0.75 MB/day |
| Suricata eve.json | ~65 MB/day (93% is flow/dns records the pipeline discards) |
| fast.log + cowrie + extra logs | ~10 MB/day combined |

## Design basis

Planned at **3× the steady-state rate** (10K events/day, 5K attack rows/day,
300 new IPs/day) so sustained growth and burst days are absorbed without
re-planning.

## 3-year projection (1,095 days)

| Component | Size | Notes |
|---|---|---|
| events hypertable | ~3 GB | 13.7 GB raw ÷ ~5× columnar compression (chunks >7 days); worst case 7 GB at 2× |
| attack_events + scan_events | ~1.5 GB | plain tables, no compression |
| ips + ip_enrichment | ~3 GB | 330K IPs; enrichment raw JSONB is the bulk |
| status_snapshots | ~1 GB | |
| behavior_profiles, reports, audit | <0.3 GB | bounded by retention loop |
| WAL, bloat, vacuum headroom | ×1.5 | |
| **Database total** | **~13 GB → budget 20 GB** | |
| Rotated sensor logs (14-day keep, gzipped) | ~2 GB | without rotation eve.json alone would hit ~71 GB/3y |
| Docker images + build cache | ~15 GB | prune periodically (`docker image prune`, `docker builder prune`) |
| Container stdout logs | ~0.5 GB | capped by compose logging (10 MB × 3 per service) |
| OS + packages + journal | ~10 GB | |
| **Working set** | **~50 GB** | |

**Requirement: 100 GB disk** (2× headroom over the working set) — this is the
stated minimum in the HLD. The hard engineering floor is ~60 GB, but that
leaves no margin and demands disciplined image/build-cache pruning. If
sustained rate ever reaches ~100K events/day, re-plan at 150–200 GB.

## What enforces the retention

- `db/init.sql` — TimescaleDB retention policies: `events` and
  `status_snapshots` drop chunks older than 3 years; compression policy
  compresses `events` chunks older than 7 days.
- `analytics/engine.py` `retention_loop` — nightly DELETE of rows older than
  3 years in `scan_events`, `attack_events`, `behavior_profiles`, `ips`
  (cascades to `ip_enrichment`) and `reports`. Requires the DELETE grants in
  `db/init.sql`.
- `/etc/cron.daily/getarp-logs` (installed by `deploy/setup.sh` from
  `deploy/rotate-logs.sh`) — daily rotation of eve.json/fast.log/extra.json
  (SIGHUP to Suricata), compression of Cowrie's self-rotated files, and
  deletion of archives older than `KEEP_DAYS` (default 14).

## Applying 3-year retention to an already-running deployment

`init.sql` only runs on first boot. On an existing database run:

```sql
SELECT remove_retention_policy('events');
SELECT remove_retention_policy('status_snapshots');
SELECT add_retention_policy('events', INTERVAL '3 years');
SELECT add_retention_policy('status_snapshots', INTERVAL '3 years');
-- if compression was never enabled (check: SELECT compression_enabled
-- FROM timescaledb_information.hypertables WHERE hypertable_name='events'):
ALTER TABLE events SET (timescaledb.compress,
    timescaledb.compress_segmentby = 'src_ip',
    timescaledb.compress_orderby = 'ts DESC');
SELECT add_compression_policy('events', INTERVAL '7 days');
```

## Monitoring

- Alert when the disk passes **70%** — at the projected growth rate that
  leaves months of runway.
- Verify the background jobs stay healthy:
  `SELECT job_id, proc_name, last_run_status FROM timescaledb_information.jobs
   JOIN timescaledb_information.job_stats USING (job_id);`
- `docker system df` monthly; prune unused images/build cache.

## Levers if disk pressure appears

1. Drop `flow`/`dns`/`tls` from the Suricata eve-log types
   (`ids/suricata/suricata.yaml`) — cuts sensor log volume ~90%; the pipeline
   ignores those record types anyway.
2. Trim `ip_enrichment.raw` (store only the fields the UI reads) — roughly
   halves the enrichment footprint.
3. Convert `attack_events` to a compressed hypertable.
4. Lower `KEEP_DAYS` for rotated raw logs.
