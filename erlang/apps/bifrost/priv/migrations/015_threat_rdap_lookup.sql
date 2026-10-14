ALTER TABLE suspicious_candidates
    ADD COLUMN IF NOT EXISTS rdap_lookup TEXT NOT NULL DEFAULT 'unavailable';

ALTER TABLE suspicious_candidates
    DROP CONSTRAINT IF EXISTS suspicious_candidates_rdap_lookup_check;

ALTER TABLE suspicious_candidates
    ADD CONSTRAINT suspicious_candidates_rdap_lookup_check
    CHECK (rdap_lookup IN ('done', 'pending', 'unavailable'));

UPDATE suspicious_candidates
SET rdap_lookup = 'done'
WHERE age_days IS NOT NULL;
