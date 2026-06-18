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
  ('enrichment_provider', '"crowdsec"'),
  ('scan_port_threshold', '5'),
  ('bruteforce_threshold', '10'),
  ('status_interval_seconds', '300')
ON CONFLICT DO NOTHING;

-- revoked token blacklist (for early JWT invalidation)
CREATE TABLE revoked_tokens (
    jti        TEXT PRIMARY KEY,
    revoked_at TIMESTAMPTZ DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_revoked_expires ON revoked_tokens (expires_at);

-- ─────────────── retention (tune for your legal/PII requirements) ───────────────
SELECT add_retention_policy('events', INTERVAL '90 days');
SELECT add_retention_policy('status_snapshots', INTERVAL '180 days');

-- retention for analytics tables that otherwise grow unbounded
DO $$
BEGIN
    -- scan_events / attack_events: keep 90 days to match events
    IF NOT EXISTS (SELECT 1 FROM timescaledb_information.jobs
                   WHERE hypertable_name = 'scan_events') THEN
        PERFORM NULL;  -- not a hypertable; use pg_cron or app-level cleanup
    END IF;
END $$;

-- compress chunks older than 7 days (events are read-mostly past that point)
ALTER TABLE events SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'src_ip',
    timescaledb.compress_orderby = 'ts DESC'
);
SELECT add_compression_policy('events', INTERVAL '7 days');

-- continuous aggregate powering fast dashboard counters
CREATE MATERIALIZED VIEW events_5m
WITH (timescaledb.continuous) AS
SELECT time_bucket('5 minutes', ts) AS bucket,
       service,
       count(*) AS n,
       count(DISTINCT src_ip) AS distinct_ips
FROM events
GROUP BY bucket, service
WITH NO DATA;
SELECT add_continuous_aggregate_policy('events_5m',
    start_offset => INTERVAL '1 hour',
    end_offset   => INTERVAL '5 minutes',
    schedule_interval => INTERVAL '5 minutes');

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
        GRANT SELECT, INSERT ON scan_events, attack_events, status_snapshots, reports TO svc_analytics;
        GRANT SELECT, INSERT, UPDATE ON behavior_profiles TO svc_analytics;
        GRANT SELECT, UPDATE ON ips TO svc_analytics;
        GRANT SELECT ON ip_enrichment TO svc_analytics;
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
        GRANT SELECT ON events, ips, ip_enrichment, scan_events, attack_events,
                        behavior_profiles, status_snapshots TO svc_api;
        GRANT SELECT, INSERT, UPDATE ON users, settings, reports, revoked_tokens TO svc_api;
        GRANT DELETE ON revoked_tokens TO svc_api;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO svc_api;
    END IF;
END $$;
