-- Explicit campaign-wide DNS block rules (threat-campaign-blocking). These are
-- DNS POLICY, deliberately separate from threat_suppressions (review-only) and
-- manual_blocks (exact names). A rule is the campaign PATTERN, so it also
-- blocks hostnames that have never been queried.
--
--   family: {n}.<parent>        first label ^[0-9]+x*$, rest = parent exactly
--   marker: <label>.*.<tld>     first label = leading_label, 3+ labels, ends .tld
--
-- client_ip NULL = all clients. client_scope is the normalised text form of that
-- scope ('' = all) so ONE partial unique index makes activation idempotent.
-- Rows are never deleted: revoking stamps revoked_at, keeping operator intent
-- and history; the same scope can be re-activated afterwards as a new row.
CREATE TABLE IF NOT EXISTS campaign_blocks (
    id               BIGSERIAL PRIMARY KEY,
    kind             TEXT NOT NULL CHECK (kind IN ('family', 'marker')),
    parent           TEXT NOT NULL DEFAULT '',
    leading_label    TEXT NOT NULL DEFAULT '',
    tld              TEXT NOT NULL CHECK (tld ~ '^[a-z0-9-]{2,63}$'),
    client_ip        INET,
    client_scope     TEXT NOT NULL DEFAULT '',
    observed_domains INTEGER NOT NULL DEFAULT 0,
    revision         BIGINT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at       TIMESTAMPTZ,
    revoked_revision BIGINT,
    CHECK (client_scope = COALESCE(host(client_ip), '')),
    CHECK ((kind = 'family' AND leading_label = ''
            AND parent ~ '^[a-z0-9_-]+(\.[a-z0-9_-]+)+$'
            AND right(parent, length(tld) + 1) = '.' || tld)
        OR (kind = 'marker' AND parent = ''
            AND leading_label ~ '^[0-9]+x*$' AND length(leading_label) <= 63)),
    CHECK ((revoked_at IS NULL) = (revoked_revision IS NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS campaign_blocks_active_identity
    ON campaign_blocks (kind, parent, leading_label, tld, client_scope)
    WHERE revoked_at IS NULL;

-- One monotonically increasing policy revision, bumped by the same statement
-- that adds or revokes a rule. Writers serialise on this row, so a revision
-- never commits out of order and Rust/peers can reject a stale push by number
-- alone. It never decreases, including on revoke.
CREATE TABLE IF NOT EXISTS campaign_block_policy (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    revision  BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0)
);

INSERT INTO campaign_block_policy (singleton) VALUES (true) ON CONFLICT DO NOTHING;
