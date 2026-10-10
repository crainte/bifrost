-- Add response_records column to store DNS answer records (A, AAAA, CNAME, etc.)
-- Stored as JSONB array: [{"rtype": "A", "value": "1.2.3.4"}, {"rtype": "CNAME", "value": "foo.example.com"}]
ALTER TABLE query_log ADD COLUMN IF NOT EXISTS response_records JSONB;
