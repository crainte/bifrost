CREATE TABLE IF NOT EXISTS dns_settings (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    schema_version INTEGER NOT NULL DEFAULT 1 CHECK (schema_version = 1),
    revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0),
    overrides JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(overrides) = 'object'),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO dns_settings (singleton) VALUES (true) ON CONFLICT DO NOTHING;
