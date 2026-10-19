-- Expiring campaign suppressions for the Threats review queue. These are NOT
-- DNS policy: they only stop the analyzer from re-queueing generated hostnames
-- shaped like <leading_label>.<registrable>.<tld>. client_ip NULL = all clients.
CREATE TABLE IF NOT EXISTS threat_suppressions (
    id              BIGSERIAL PRIMARY KEY,
    tld             TEXT NOT NULL CHECK (tld ~ '^[a-z0-9-]{2,63}$'),
    leading_label   TEXT NOT NULL CHECK (leading_label ~ '^[0-9]+x*$' AND length(leading_label) <= 63),
    client_ip       INET,
    matched_domains INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS threat_suppressions_active_idx
    ON threat_suppressions (tld, leading_label, expires_at)
    WHERE revoked_at IS NULL;
