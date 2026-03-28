-- Initial schema for DDoS Defense Platform
-- TimescaleDB extension required

-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- ------------------------------------------------------------
-- Metrics table (time-series data)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS metrics (
    time        TIMESTAMPTZ NOT NULL,
    metric_name TEXT NOT NULL,
    value       DOUBLE PRECISION NOT NULL,
    tags        JSONB
);

-- Convert to hypertable (partition by time)
SELECT create_hypertable('metrics', 'time', if_not_exists => TRUE);

-- Create indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_metrics_time ON metrics (time DESC);
CREATE INDEX IF NOT EXISTS idx_metrics_name ON metrics (metric_name);
CREATE INDEX IF NOT EXISTS idx_metrics_tags ON metrics USING gin (tags);

-- ------------------------------------------------------------
-- Alerts table
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id          UUID PRIMARY KEY,
    alert_type  TEXT NOT NULL,
    severity    INTEGER NOT NULL,
    confidence  FLOAT,
    target      TEXT,
    details     JSONB,
    created_at  TIMESTAMPTZ NOT NULL,
    resolved_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts (alert_type);

-- ------------------------------------------------------------
-- Mitigation actions table
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mitigation_actions (
    id            UUID PRIMARY KEY,
    alert_id      UUID REFERENCES alerts(id) ON DELETE CASCADE,
    action_type   TEXT NOT NULL,
    target        TEXT NOT NULL,
    status        TEXT NOT NULL,  -- pending, success, failed, rolled_back
    details       JSONB,
    created_at    TIMESTAMPTZ NOT NULL,
    rolled_back_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_actions_alert_id ON mitigation_actions (alert_id);
CREATE INDEX IF NOT EXISTS idx_actions_created_at ON mitigation_actions (created_at DESC);

-- ------------------------------------------------------------
-- Blacklist table (persistent block list)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS blacklist (
    ip          INET PRIMARY KEY,
    reason      TEXT,
    created_at  TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ,
    created_by  TEXT  -- 'auto' or 'manual'
);

CREATE INDEX IF NOT EXISTS idx_blacklist_expires ON blacklist (expires_at) WHERE expires_at IS NOT NULL;

-- ------------------------------------------------------------
-- Rate limiting counters (optional, if using DB for state)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rate_limit_counters (
    key         TEXT PRIMARY KEY,          -- e.g., "ip:192.168.1.1"
    count       BIGINT NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL
);

-- ------------------------------------------------------------
-- ML model metadata (tracking trained models)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml_models (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL,
    path        TEXT NOT NULL,
    metrics     JSONB,
    trained_at  TIMESTAMPTZ NOT NULL,
    deployed_at TIMESTAMPTZ,
    active      BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_ml_models_active ON ml_models (active) WHERE active = TRUE;

-- ------------------------------------------------------------
-- Down migration (optional, for rollback)
-- ------------------------------------------------------------
-- DROP TABLE IF EXISTS ml_models;
-- DROP TABLE IF EXISTS rate_limit_counters;
-- DROP TABLE IF EXISTS blacklist;
-- DROP TABLE IF EXISTS mitigation_actions;
-- DROP TABLE IF EXISTS alerts;
-- DROP TABLE IF EXISTS metrics;
-- DROP EXTENSION IF EXISTS timescaledb;