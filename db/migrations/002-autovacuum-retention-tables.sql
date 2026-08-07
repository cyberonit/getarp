-- Phase 2 — let autovacuum keep pace with the nightly retention DELETEs.
--
-- These tables are plain heaps cleaned by analytics/engine.py retention_loop,
-- not hypertables with drop_chunks, so expiring a day of data leaves dead
-- tuples behind rather than dropping a chunk.
--
-- attack_events was already tuned to vacuum_scale_factor 0.05 in db/init.sql,
-- chosen when the table was purely append-only (it still shows n_tup_upd = 0
-- and 3 dead tuples today — nothing has ever been deleted from it, because the
-- old 3-year horizon would not have expired anything until 2029).
--
-- A 1-year horizon changes that workload: from 2027-06-13 the retention loop
-- deletes ~17,400 rows every night, for ever. At the 6.35M-row plateau, 0.05
-- puts the trigger at ~318k dead tuples — about 18 days of deletes, ~79 MB of
-- dead rows carried at peak. 0.01 + 10k brings it to ~73.5k, roughly every
-- 4 days. Modest in absolute terms, but it keeps a steady-state delete from
-- accumulating into periodic large vacuums.
--
-- ips, ip_enrichment and behavior_profiles have no per-table settings at all
-- and sit on the server default of 0.2. ips carries heavy update churn on top
-- of its deletes (measured 1.85M updates, only 38% HOT, because last_seen is
-- indexed and changes on nearly every event) which puts it ~9 days between
-- vacuums at the 1-year plateau; 0.02 + 5k moves it to ~2 days.
-- ip_enrichment is included because deletes from ips cascade into it
-- (FK ON DELETE CASCADE) at ~2.7 KB of TOAST per row.
--
-- ALTER TABLE ... SET merges into existing reloptions, so the
-- autovacuum_analyze_scale_factor values already set in db/init.sql survive.

ALTER TABLE attack_events SET (
    autovacuum_vacuum_scale_factor = 0.01,
    autovacuum_vacuum_threshold    = 10000
);

ALTER TABLE ips SET (
    autovacuum_vacuum_scale_factor = 0.02,
    autovacuum_vacuum_threshold    = 5000
);

ALTER TABLE ip_enrichment SET (
    autovacuum_vacuum_scale_factor = 0.02,
    autovacuum_vacuum_threshold    = 5000
);

ALTER TABLE behavior_profiles SET (
    autovacuum_vacuum_scale_factor = 0.02,
    autovacuum_vacuum_threshold    = 5000
);
