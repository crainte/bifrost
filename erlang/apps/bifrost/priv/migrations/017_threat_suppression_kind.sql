-- Campaign suppressions gain a second shape. A `marker` suppression (every
-- existing row) hides <leading_label>.<anything>.<tld>; a `family` suppression
-- hides enumerated siblings of ONE parent, {n}.<parent>, and has no leading
-- label of its own. tld is kept for families (the parent's last label) so the
-- column stays meaningful for every row.
--
-- leading_label becomes nullable for families. A pod still on the previous
-- release during a rolling restart compares split_part(...) = NULL, which is
-- never true, so it simply does not apply family rows rather than misapplying
-- them as a marker.
ALTER TABLE threat_suppressions
    ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'marker',
    ADD COLUMN IF NOT EXISTS parent TEXT;

ALTER TABLE threat_suppressions ALTER COLUMN leading_label DROP NOT NULL;

ALTER TABLE threat_suppressions DROP CONSTRAINT IF EXISTS threat_suppressions_kind_check;
ALTER TABLE threat_suppressions
    ADD CONSTRAINT threat_suppressions_kind_check CHECK (
        (kind = 'marker' AND leading_label IS NOT NULL AND parent IS NULL)
        OR (kind = 'family' AND leading_label IS NULL AND parent IS NOT NULL
            AND parent ~ '^[a-z0-9_-]+(\.[a-z0-9_-]+)+$'
            AND right(parent, length(tld) + 1) = '.' || tld));

CREATE INDEX IF NOT EXISTS threat_suppressions_family_idx
    ON threat_suppressions (parent, expires_at)
    WHERE revoked_at IS NULL AND kind = 'family';
