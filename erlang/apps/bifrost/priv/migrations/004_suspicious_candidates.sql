-- Threat detection: domains the domain_analyzer flagged as likely
-- algorithmically-generated / throwaway ad domains. Reviewed on the Threats page.
-- status: pending (awaiting review) | blocked (acted) | dismissed (marked safe)
CREATE TABLE IF NOT EXISTS suspicious_candidates (
    domain     TEXT PRIMARY KEY,
    score      INTEGER NOT NULL,
    reasons    JSONB NOT NULL DEFAULT '[]'::jsonb,
    hits       INTEGER NOT NULL DEFAULT 0,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    age_days   INTEGER,
    status     TEXT NOT NULL DEFAULT 'pending',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS suspicious_status_idx ON suspicious_candidates (status, score DESC);

-- Cache RDAP results so the analyzer doesn't re-query registrars; a domain's
-- registration age is immutable, so this never needs refreshing.
CREATE TABLE IF NOT EXISTS rdap_cache (
    domain     TEXT PRIMARY KEY,
    age_days   INTEGER,
    looked_up  TIMESTAMPTZ NOT NULL DEFAULT now()
);
