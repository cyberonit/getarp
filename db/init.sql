-- getarp.net Defence Intelligence — schema
-- Runs once on first container start.

CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ───────────────────────────── raw events ─────────────────────────────
CREATE TABLE events (
    event_id   UUID         DEFAULT gen_random_uuid(),
    ts         TIMESTAMPTZ  NOT NULL,
    sensor     TEXT         NOT NULL,
    service    TEXT,
    event_type TEXT         NOT NULL,
    src_ip     INET         NOT NULL,
    src_port   INTEGER,
    dst_port   INTEGER,
    username   TEXT,
    password   TEXT,
    command    TEXT,
    signature  TEXT,
    severity   SMALLINT     DEFAULT 0,
    session    TEXT,
    raw        JSONB,
    PRIMARY KEY (ts, event_id)
);
SELECT create_hypertable('events', 'ts', chunk_time_interval => INTERVAL '1 day');
CREATE INDEX idx_events_ts       ON events (ts DESC);
CREATE INDEX idx_events_src_ip   ON events (src_ip, ts DESC);
CREATE INDEX idx_events_service  ON events (service, ts DESC);
CREATE INDEX idx_events_type     ON events (event_type, ts DESC);

-- Columnar compression for aged chunks. events is append-only and the bulk of
-- its size is the raw JSONB payload, which compresses ~10x. Segment by src_ip so
-- the per-IP event lookup (/api/ips/{ip}) can skip other segments in a compressed
-- chunk; order by ts DESC to match every time-ranged read. Chunks older than
-- 30 days are compressed by the background policy (recent chunks stay
-- uncompressed for fast inserts/queries).
ALTER TABLE events SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'src_ip',
    timescaledb.compress_orderby   = 'ts DESC, event_id'
);
SELECT add_compression_policy('events', INTERVAL '30 days');

-- one row per observed source IP (the "attackers" list the UI shows)
CREATE TABLE ips (
    src_ip        INET PRIMARY KEY,
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    event_count   BIGINT      NOT NULL DEFAULT 0,
    services_hit  TEXT[]      NOT NULL DEFAULT '{}',
    ports_hit     INTEGER[]   NOT NULL DEFAULT '{}',
    threat_score  REAL        NOT NULL DEFAULT 0,     -- 0..100, set by analytics
    classification TEXT        DEFAULT 'unknown'      -- scanner|bruteforcer|exploiter|...
);
CREATE INDEX idx_ips_first_seen ON ips (first_seen);
CREATE INDEX idx_ips_last_seen  ON ips (last_seen);

-- enrichment, keyed by IP, written by the swappable provider
CREATE TABLE ip_enrichment (
    src_ip      INET PRIMARY KEY REFERENCES ips(src_ip) ON DELETE CASCADE,
    provider    TEXT,
    country     TEXT,
    asn         TEXT,
    org         TEXT,
    reputation  TEXT,                  -- malicious|suspicious|known|clean|unknown
    confidence  REAL,                  -- 0..1
    categories  TEXT[],
    is_known_attacker BOOLEAN,
    updated_at  TIMESTAMPTZ DEFAULT now(),
    raw         JSONB
);

-- Tier-1 threat-intel feeds, bulk-downloaded on a schedule by the enrichment
-- worker (enrichment/feeds.py) and matched locally — no per-IP API quota spent.
CREATE TABLE feed_indicators (
    source     TEXT        NOT NULL,      -- feodo|threatfox|crowdsec-lapi
    indicator  INET        NOT NULL,
    type       TEXT        NOT NULL DEFAULT 'ip',
    category   TEXT,
    meta       JSONB,
    updated_at TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (source, indicator)
);
CREATE INDEX idx_feed_indicators_indicator ON feed_indicators (indicator);

-- correlated scan events
CREATE TABLE scan_events (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    src_ip      INET NOT NULL,
    scan_type   TEXT,                  -- vertical|horizontal|sweep
    ports       INTEGER[],
    port_count  INTEGER,
    window_s    INTEGER,
    detail      JSONB
);
CREATE INDEX idx_scan_src ON scan_events (src_ip, ts DESC);
CREATE INDEX idx_scan_ts  ON scan_events (ts DESC);
-- Append-heavy: default autoanalyze (~20% growth) rarely fires on a large table,
-- leaving the planner with stale row estimates. Re-analyze after ~2% change.
ALTER TABLE scan_events SET (autovacuum_analyze_scale_factor = 0.02);

-- correlated attack events
CREATE TABLE attack_events (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    src_ip      INET NOT NULL,
    attack_type TEXT,                  -- bruteforce|cred_stuffing|exploit|post_auth_exec
    service     TEXT,
    evidence    JSONB,
    severity    SMALLINT DEFAULT 0,
    ai_score    REAL                   -- reserved for a future AI/ML module
);
CREATE INDEX idx_attack_src ON attack_events (src_ip, ts DESC);
CREATE INDEX idx_attack_ts  ON attack_events (ts DESC);
-- Append-heavy and the largest non-hypertable: keep planner stats fresh so joins
-- on it don't get bad row estimates. Re-analyze after ~2% change, vacuum at ~5%.
ALTER TABLE attack_events SET (
    autovacuum_analyze_scale_factor = 0.02,
    autovacuum_vacuum_scale_factor  = 0.05
);

-- per-IP behavioral profile (one row, upserted)
CREATE TABLE behavior_profiles (
    src_ip          INET PRIMARY KEY,
    sessions        INTEGER DEFAULT 0,
    avg_session_s   REAL,
    commands_seen   TEXT[],
    tooling_hints   TEXT[],            -- e.g. masscan, hydra, mirai-like
    tactics         TEXT[],           -- MITRE-ish tags
    cluster_id      INTEGER,
    threat_score    REAL DEFAULT 0,
    updated_at      TIMESTAMPTZ DEFAULT now(),
    detail          JSONB
);
CREATE INDEX idx_behavior_threat_score ON behavior_profiles (threat_score DESC);

-- 5-minute live status snapshots
CREATE TABLE status_snapshots (
    ts                TIMESTAMPTZ NOT NULL DEFAULT now(),
    active_attackers  INTEGER,
    new_ips           INTEGER,
    events_per_min    REAL,
    top_ports         JSONB,
    top_services      JSONB,
    top_countries     JSONB,
    threat_level      TEXT,            -- low|elevated|high|critical
    detail            JSONB,
    PRIMARY KEY (ts)
);
SELECT create_hypertable('status_snapshots', 'ts', chunk_time_interval => INTERVAL '7 days');

-- generated reports
CREATE TABLE reports (
    id          BIGSERIAL PRIMARY KEY,
    created_at  TIMESTAMPTZ DEFAULT now(),
    period_from TIMESTAMPTZ,
    period_to   TIMESTAMPTZ,
    kind        TEXT,                  -- daily|weekly|adhoc
    summary     JSONB,
    html        TEXT
);

-- admin users for the backend
CREATE TABLE users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'admin',
    created_at    TIMESTAMPTZ DEFAULT now()
);

-- runtime settings editable from the admin backend (key/value)
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      JSONB NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now()
);
INSERT INTO settings(key, value) VALUES
  ('enrichment_provider', '"tiered"'),
  ('scan_port_threshold', '5'),
  ('bruteforce_threshold', '5'),
  ('status_interval_seconds', '300')
ON CONFLICT DO NOTHING;

-- revoked token blacklist (for early JWT invalidation)
CREATE TABLE revoked_tokens (
    jti        TEXT PRIMARY KEY,
    revoked_at TIMESTAMPTZ DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_revoked_expires ON revoked_tokens (expires_at);

-- admin audit trail — immutable log of all privileged operations
CREATE TABLE audit_log (
    id         BIGSERIAL PRIMARY KEY,
    ts         TIMESTAMPTZ DEFAULT now(),
    username   TEXT NOT NULL,
    action     TEXT NOT NULL,
    detail     JSONB
);
CREATE INDEX idx_audit_ts ON audit_log (ts DESC);

-- ─────────────── retention (tune for your legal/PII requirements) ───────────────
-- 3-year retention target; see docs/CAPACITY.md for the disk model.
-- Non-hypertables (scan_events, attack_events, ips, behavior_profiles, reports)
-- are cleaned by analytics/engine.py retention_loop with the same 3-year horizon.
SELECT add_retention_policy('events', INTERVAL '3 years');
SELECT add_retention_policy('status_snapshots', INTERVAL '3 years');

-- compress chunks older than 7 days (events are read-mostly past that point)
ALTER TABLE events SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'src_ip',
    timescaledb.compress_orderby = 'ts DESC'
);
SELECT add_compression_policy('events', INTERVAL '7 days');

-- ─────────────── per-service least-privilege roles ───────────────
-- Each backend service gets its own role with only the grants it needs.
-- The bootstrap user (PG_USER) owns the schema; these roles are narrower.

DO $$
DECLARE
    pw TEXT;
BEGIN
    -- Passwords are set via env vars injected by setup.sh.  If the role
    -- already exists (re-run of init.sql) the CREATE is skipped.

    -- role: pipeline — INSERT events, upsert ips, read settings
    pw := current_setting('app.pipeline_password', true);
    IF pw IS NOT NULL AND pw != '' THEN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'svc_pipeline') THEN
            EXECUTE format('CREATE ROLE svc_pipeline LOGIN PASSWORD %L', pw);
        END IF;
        GRANT USAGE ON SCHEMA public TO svc_pipeline;
        GRANT SELECT, INSERT ON events TO svc_pipeline;
        GRANT SELECT, INSERT, UPDATE ON ips TO svc_pipeline;
        GRANT SELECT ON settings TO svc_pipeline;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO svc_pipeline;
    END IF;

    -- role: enrichment — upsert ip_enrichment, update ips, read settings
    pw := current_setting('app.enrichment_password', true);
    IF pw IS NOT NULL AND pw != '' THEN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'svc_enrichment') THEN
            EXECUTE format('CREATE ROLE svc_enrichment LOGIN PASSWORD %L', pw);
        END IF;
        GRANT USAGE ON SCHEMA public TO svc_enrichment;
        GRANT SELECT, INSERT, UPDATE ON ip_enrichment TO svc_enrichment;
        GRANT SELECT, INSERT, UPDATE, DELETE ON feed_indicators TO svc_enrichment;
        GRANT SELECT, UPDATE ON ips TO svc_enrichment;
        GRANT SELECT ON settings TO svc_enrichment;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO svc_enrichment;
    END IF;

    -- role: analytics — insert scans/attacks/status/reports/profiles, update ips, read settings
    pw := current_setting('app.analytics_password', true);
    IF pw IS NOT NULL AND pw != '' THEN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'svc_analytics') THEN
            EXECUTE format('CREATE ROLE svc_analytics LOGIN PASSWORD %L', pw);
        END IF;
        GRANT USAGE ON SCHEMA public TO svc_analytics;
        GRANT SELECT ON events TO svc_analytics;
        -- DELETE: retention_loop in analytics/engine.py prunes these tables
        GRANT SELECT, INSERT, DELETE ON scan_events, attack_events, reports TO svc_analytics;
        GRANT SELECT, INSERT ON status_snapshots TO svc_analytics;
        GRANT SELECT, INSERT, UPDATE, DELETE ON behavior_profiles TO svc_analytics;
        GRANT SELECT, UPDATE, DELETE ON ips TO svc_analytics;
        GRANT SELECT ON ip_enrichment, feed_indicators TO svc_analytics;
        GRANT SELECT ON settings TO svc_analytics;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO svc_analytics;
    END IF;

    -- role: api — mostly read-only, write users/settings/reports/revoked_tokens
    pw := current_setting('app.api_password', true);
    IF pw IS NOT NULL AND pw != '' THEN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'svc_api') THEN
            EXECUTE format('CREATE ROLE svc_api LOGIN PASSWORD %L', pw);
        END IF;
        GRANT USAGE ON SCHEMA public TO svc_api;
        GRANT SELECT ON events, ips, ip_enrichment, feed_indicators, scan_events,
                        attack_events, behavior_profiles, status_snapshots TO svc_api;
        GRANT SELECT, INSERT, UPDATE ON users, settings, reports, revoked_tokens TO svc_api;
        GRANT DELETE ON revoked_tokens TO svc_api;
        GRANT INSERT, SELECT ON audit_log TO svc_api;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO svc_api;
    END IF;
END $$;
