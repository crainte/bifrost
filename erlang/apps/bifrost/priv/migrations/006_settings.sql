-- Operational settings (key/value). Currently drives Threats auto-block.
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Auto-block is OFF by default: the operator opts in after the ranking proves
-- itself. Gate = lexical/RDAP/probe score >= min_score AND age_days < max_age.
INSERT INTO settings (key, value) VALUES
    ('auto_block_enabled', 'false'),
    ('auto_block_min_score', '6'),
    ('auto_block_max_age_days', '30')
ON CONFLICT (key) DO NOTHING;
