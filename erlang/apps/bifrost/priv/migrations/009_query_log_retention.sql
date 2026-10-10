-- Query-log retention, in whole months. query_log is partitioned by month, so
-- expiry is a DROP TABLE of the whole partition: instant, no VACUUM, no bloat.
-- bifrost_query_writer applies this at each monthly rollover.
--
-- 6 months at a typical 100k queries/day is roughly 3GB. Raise it if you have
-- the disk and want longer history; set it to 0 to keep every partition forever
-- (the pre-retention behaviour).
INSERT INTO settings (key, value) VALUES ('query_log_retention_months', '6')
ON CONFLICT (key) DO NOTHING;
