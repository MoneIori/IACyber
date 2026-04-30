-- IACyber — PostgreSQL Init Script
-- Crea DB separati per Keycloak e app, abilita TimescaleDB

CREATE DATABASE keycloak;
CREATE DATABASE iacyber;

\c iacyber;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- ─── Tabelle core ────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS raw_events (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id    VARCHAR(100) NOT NULL,
    source_type  VARCHAR(50)  NOT NULL,
    raw_payload  TEXT         NOT NULL,
    source_ip    VARCHAR(45)  NOT NULL,
    status       VARCHAR(20)  NOT NULL DEFAULT 'RECEIVED',
    ingested_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Converti in hypertable TimescaleDB per query time-series efficienti
SELECT create_hypertable('raw_events', 'ingested_at', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_raw_events_tenant_time ON raw_events (tenant_id, ingested_at DESC);

-- ─── Tenant (gestione multi-tenant) ──────────────────────────

CREATE TABLE IF NOT EXISTS tenants (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name       VARCHAR(200) NOT NULL UNIQUE,
    tier       VARCHAR(50)  NOT NULL DEFAULT 'starter',
    region     VARCHAR(50)  NOT NULL DEFAULT 'eu-west-1',
    config     JSONB        NOT NULL DEFAULT '{}',
    active     BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ─── Asset Inventory ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS assets (
    id                   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id            VARCHAR(100) NOT NULL,
    hostname             VARCHAR(255),
    ip                   VARCHAR(45)  NOT NULL,
    os                   VARCHAR(200),
    sbom                 JSONB        NOT NULL DEFAULT '{}',
    risk_score           DECIMAL(4,2) DEFAULT 0.0,
    predicted_risk_score DECIMAL(4,2) DEFAULT 0.0,
    last_scanned         TIMESTAMPTZ,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_assets_tenant ON assets (tenant_id);
CREATE INDEX IF NOT EXISTS idx_assets_ip     ON assets (ip);

-- ─── Code Findings (SAST) ────────────────────────────────────

CREATE TABLE IF NOT EXISTS code_findings (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id    VARCHAR(100) NOT NULL,
    repo_url     VARCHAR(500) NOT NULL,
    file_path    VARCHAR(500) NOT NULL,
    line_number  INT,
    cwe_id       VARCHAR(20),
    cve_ref      VARCHAR(50),
    cvss_score   DECIMAL(4,2),
    severity     VARCHAR(20)  NOT NULL,
    description  TEXT,
    ai_fix       TEXT,
    git_pr_url   VARCHAR(500),
    status       VARCHAR(30)  NOT NULL DEFAULT 'OPEN',
    detected_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_tenant   ON code_findings (tenant_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON code_findings (severity, status);

-- ─── Predicted Vulnerabilities ───────────────────────────────

CREATE TABLE IF NOT EXISTS predicted_vulnerabilities (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         VARCHAR(100) NOT NULL,
    asset_id          UUID REFERENCES assets(id) ON DELETE CASCADE,
    component         VARCHAR(300) NOT NULL,
    version           VARCHAR(100),
    probability_score DECIMAL(5,4) NOT NULL,
    prediction_basis  TEXT,
    affected_repos    JSONB DEFAULT '[]',
    predicted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at        TIMESTAMPTZ
);

SELECT create_hypertable('predicted_vulnerabilities', 'predicted_at', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_predictions_tenant    ON predicted_vulnerabilities (tenant_id);
CREATE INDEX IF NOT EXISTS idx_predictions_component ON predicted_vulnerabilities (component);

-- ─── Git Integrations ────────────────────────────────────────

CREATE TABLE IF NOT EXISTS git_integrations (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id        VARCHAR(100) NOT NULL,
    provider         VARCHAR(50)  NOT NULL,  -- GITHUB, GITLAB, BITBUCKET
    repo_url         VARCHAR(500) NOT NULL,
    token_vault_path VARCHAR(300) NOT NULL,  -- path in Vault, mai il token raw
    auto_pr_enabled  BOOLEAN      NOT NULL DEFAULT TRUE,
    last_scan        TIMESTAMPTZ,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, repo_url)
);
