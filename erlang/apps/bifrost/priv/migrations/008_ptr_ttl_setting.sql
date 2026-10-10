-- Runtime-tunable PTR cache re-resolve age (seconds). bifrost_ptr reads this
-- from the settings table; a client's PTR name is re-resolved once its cache
-- entry is older than this. Default 6 hours (21600s). Raise for stable static
-- leases, lower for churny DHCP.
INSERT INTO settings (key, value) VALUES ('ptr_ttl_seconds', '21600')
ON CONFLICT (key) DO NOTHING;
