-- Phase 1 — shorten raw-data retention from 3 years to 1 year.
--
-- Rationale: capacity is not the constraint (the 1-year projection is ~7.4 GB
-- against 263 GB free), so the horizon is chosen for data-protection reasons —
-- `events` carries third-party PII (attacker usernames, passwords, commands).
-- 1 year keeps a full seasonal cycle of raw data for threat analysis while
-- cutting PII exposure 3x.
--
-- Safe to apply at any time: a retention policy only drops chunks already
-- older than the horizon. On this deployment the oldest data is 2026-06-13, so
-- applying it deletes nothing — the first real expiry is 2027-06-13.
--
-- The matching horizon for the plain tables lives in analytics/engine.py
-- (RAW_RETENTION / AGGREGATE_RETENTION) and ships in the analytics image;
-- db/init.sql carries the same values for fresh deployments.

SELECT remove_retention_policy('events',           if_exists => true);
SELECT remove_retention_policy('status_snapshots', if_exists => true);

SELECT add_retention_policy('events',           INTERVAL '1 year', if_not_exists => true);
SELECT add_retention_policy('status_snapshots', INTERVAL '1 year', if_not_exists => true);
