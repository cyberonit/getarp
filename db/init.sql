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

-- ─────────────── retention (tune for your legal/PII requirements) ───────────────
SELECT add_retention_policy('events', INTERVAL '90 days');
SELECT add_retention_policy('status_snapshots', INTERVAL '180 days');

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
