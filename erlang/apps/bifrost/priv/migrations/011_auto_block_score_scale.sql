-- Recalibrate auto_block_min_score: the score scale it refers to changed.
--
-- bifrost_domain_analyzer now folds bifrost_api_handler:score_rdap/1 into a
-- candidate's score (it previously fetched RDAP, kept only the age, and scored
-- none of it). Score gained an age term: <30d = +3, <180d = +2, <365d = +1.
--
-- The auto-block gate is `score >= min_score AND age_days < max_age`. Inside the
-- population that gate admits — age < max_age, default 30 — the age term is a
-- CONSTANT +3. So without this shift the gate would have silently loosened by
-- exactly 3 for every candidate it can ever fire on: with SCORE_THRESHOLD = 3 to
-- become a candidate at all, `min_score = 6` would have matched every candidate
-- under 30 days old.
--
-- Shifting by the same +3 holds the gate exactly where the operator put it, on
-- the new scale. Applied to whatever value is stored, not just the old default,
-- because a hand-tuned 4 is on the old scale too. Guarded to integer values: the
-- setting is operator-editable, and setting_int/2 tolerates garbage by falling
-- back to the default, so garbage here must be left alone rather than crash the
-- migration.
UPDATE settings
   SET value = ((value)::int + 3)::text
 WHERE key = 'auto_block_min_score'
   AND value ~ '^[0-9]+$';

-- And the default for a fresh install, which never saw the old scale.
INSERT INTO settings (key, value) VALUES ('auto_block_min_score', '9')
ON CONFLICT (key) DO NOTHING;
