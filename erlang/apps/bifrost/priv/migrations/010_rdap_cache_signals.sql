-- RDAP cache: persist the registry SIGNALS, not just the registration age.
--
-- rdap_cache held only age_days, and only bifrost_domain_analyzer ever read it.
-- The per-client suspicious scan (bifrost_api_handler:enrich_with_rdap/1)
-- re-derived transfer-lock / pending-delete / privacy-protected on EVERY page
-- load with a live RDAP request per domain: ticking "RDAP enrich" on the Clients
-- page issued up to 10 sequential registry requests (3s connect + 5s read each)
-- and re-issued the lot on every refresh or re-tick. Registries rate-limit RDAP.
--
-- These four fields are the only ones any consumer scores or renders, so they are
-- columns rather than a JSONB blob — same shape as probe_cache next door.
--
-- NULL = unknown. A row means "we looked up", so an all-NULL row is a NEGATIVE
-- entry (unsupported TLD, 404, timeout) and MUST stay cached, otherwise those
-- domains are re-probed on every scan forever.
ALTER TABLE rdap_cache ADD COLUMN IF NOT EXISTS has_transfer_lock BOOLEAN;
ALTER TABLE rdap_cache ADD COLUMN IF NOT EXISTS pending_delete    BOOLEAN;
ALTER TABLE rdap_cache ADD COLUMN IF NOT EXISTS privacy_protected BOOLEAN;

-- Every row that exists right now predates those columns AND was keyed on the
-- full queried domain rather than the registrable base, so it is both partial
-- and mis-keyed: age known, flags unknown forever, and never refreshed because
-- a row means "looked up". This table is a pure cache — 100% re-derivable from
-- RDAP, holds no operator input — so clearing it costs one lookup per active
-- domain and removes the partial-row case from every reader.
DELETE FROM rdap_cache;
