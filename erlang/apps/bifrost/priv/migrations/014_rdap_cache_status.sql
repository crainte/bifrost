-- RDAP cache: tell transient failures from permanent ones, and stop freezing age.
--
-- 1. FROZEN AGE. age_days was computed at lookup time and never refreshed, so a
--    domain cached at 5 days old read as 5 days old forever: it kept the +3
--    rdap:new_domain score and kept passing the auto-block age gate
--    (age < auto_block_max_age_days) indefinitely. Store the registration DATE
--    and compute age at read time instead.
--
-- 2. EVERY FAILURE WAS PERMANENT. An all-NULL row meant "looked up", whatever
--    the cause — so a 429 or a timeout removed a domain from age scoring for
--    good. `status` separates final outcomes (ok, not_found, unsupported) from
--    `transient` ones, which are retried at `retry_at` with exponential backoff
--    driven by `attempts`. `pending` is a short lease claimed by whichever
--    session (on whichever pod) is fetching, so concurrent page loads and scans
--    never issue the same registry request twice.
--
-- age_days is kept and still written so pods running the previous release can
-- read the table during a rolling restart. Nothing new reads it; drop it in a
-- later migration.
ALTER TABLE rdap_cache ADD COLUMN IF NOT EXISTS registered_on DATE;
ALTER TABLE rdap_cache ADD COLUMN IF NOT EXISTS status   TEXT     NOT NULL DEFAULT 'ok';
ALTER TABLE rdap_cache ADD COLUMN IF NOT EXISTS attempts SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE rdap_cache ADD COLUMN IF NOT EXISTS retry_at TIMESTAMPTZ;

ALTER TABLE rdap_cache DROP CONSTRAINT IF EXISTS rdap_cache_status_check;
ALTER TABLE rdap_cache ADD CONSTRAINT rdap_cache_status_check
    CHECK (status IN ('ok', 'not_found', 'unsupported', 'transient', 'pending'));

-- Recover the registration date from what was stored: age was taken on the day
-- of the lookup.
UPDATE rdap_cache SET registered_on = looked_up::date - age_days
 WHERE age_days IS NOT NULL AND registered_on IS NULL;

-- An all-NULL row cannot be classified after the fact: it may be an unsupported
-- TLD, a 404, or a 429. Give each ONE re-check. Unsupported TLDs resolve
-- locally without a network request; the rest are paced like any other lookup.
UPDATE rdap_cache SET status = 'transient', retry_at = now()
 WHERE age_days IS NULL AND has_transfer_lock IS NULL
   AND pending_delete IS NULL AND privacy_protected IS NULL;
