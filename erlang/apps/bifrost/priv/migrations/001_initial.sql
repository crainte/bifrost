CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    filename    TEXT NOT NULL
);

DO $$ BEGIN
    CREATE TYPE rcode_type AS ENUM (
        'NOERROR', 'FORMERR', 'SERVFAIL', 'NXDOMAIN',
        'NOTIMP', 'REFUSED', 'YXDOMAIN', 'YXRRSET',
        'NXRRSET', 'NOTAUTH', 'NOTZONE',
        'BIFROST_BLOCK',
        'BIFROST_ALLOW',
        'BIFROST_RW',
        'BIFROST_CACHE',
        'UNKNOWN'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS blocklists (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    url             TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    source          TEXT NOT NULL DEFAULT 'ui',
    domain_count    INTEGER,
    last_fetched_at TIMESTAMPTZ,
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rewrites (
    id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain   TEXT NOT NULL UNIQUE,
    target   TEXT NOT NULL,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS allowlist (
    id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain   TEXT NOT NULL UNIQUE,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS clients (
    ip         INET PRIMARY KEY,
    name       TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS query_log (
    id           BIGSERIAL,
    client_ip    INET NOT NULL,
    domain       TEXT NOT NULL,
    qtype        SMALLINT NOT NULL,
    action       rcode_type NOT NULL,
    client_rcode rcode_type NOT NULL,
    ede_code     SMALLINT,
    list_id      TEXT,
    latency_us   INTEGER,
    queried_at   TIMESTAMPTZ NOT NULL DEFAULT now()
) PARTITION BY RANGE (queried_at);

CREATE INDEX IF NOT EXISTS query_log_domain_idx ON query_log (domain);
CREATE INDEX IF NOT EXISTS query_log_client_idx ON query_log (client_ip);
CREATE INDEX IF NOT EXISTS query_log_list_idx   ON query_log (list_id);
CREATE INDEX IF NOT EXISTS query_log_time_idx   ON query_log (queried_at DESC);
CREATE INDEX IF NOT EXISTS query_log_action_idx ON query_log (action);

CREATE TABLE IF NOT EXISTS list_stats (
    list_id      TEXT NOT NULL,
    period_start TIMESTAMPTZ NOT NULL,
    block_count  BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (list_id, period_start)
);
