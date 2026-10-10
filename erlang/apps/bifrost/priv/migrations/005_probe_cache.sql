-- Cache of out-of-band header probes (CORS/CSP) done by domain_analyzer.
-- Avoids re-probing the same candidate on every 15-min scan.
CREATE TABLE IF NOT EXISTS probe_cache (
    domain        TEXT PRIMARY KEY,
    cors_wildcard BOOLEAN NOT NULL DEFAULT false,
    has_csp       BOOLEAN NOT NULL DEFAULT true,
    probed_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
