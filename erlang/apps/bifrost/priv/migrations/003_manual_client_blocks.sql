-- Manually-blocked single domains (global). Pushed to Rust as the reserved
-- 'manual' blocklist via the existing load_blocklist path.
CREATE TABLE IF NOT EXISTS manual_blocks (
    domain   TEXT PRIMARY KEY,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Per-client domain blocks. A (client_ip, domain) pair blocks the domain only
-- for that client. Enforced in the Rust hot path, not via a blocklist.
CREATE TABLE IF NOT EXISTS client_blocks (
    client_ip INET NOT NULL,
    domain    TEXT NOT NULL,
    added_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (client_ip, domain)
);
