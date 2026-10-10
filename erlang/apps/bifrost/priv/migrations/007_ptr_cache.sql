-- Reverse-DNS (PTR) cache for friendly client names. Unlike rdap_cache, PTR can
-- change per DHCP lease, so entries carry a lookup timestamp and are re-resolved
-- when stale (TTL enforced in bifrost_ptr, not here). NULL name = negative cache
-- (NXDOMAIN / no PTR), still timestamped so we don't hammer the resolver.
CREATE TABLE IF NOT EXISTS ptr_cache (
    ip        INET PRIMARY KEY,
    name      TEXT,
    looked_up TIMESTAMPTZ NOT NULL DEFAULT now()
);
