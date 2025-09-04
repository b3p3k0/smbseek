-- SMBSeek Share Summary View Enhancement
-- Adds view for complete share discovery and accessibility summary
-- Safe to run on existing databases - only adds view, no schema changes

-- Create comprehensive share summary view
CREATE VIEW IF NOT EXISTS v_host_share_summary AS
SELECT 
    s.ip_address,
    s.country,
    s.auth_method,
    s.first_seen,
    s.last_seen,
    COUNT(sa.share_name) as total_shares_discovered,
    SUM(CASE WHEN sa.accessible = 1 THEN 1 ELSE 0 END) as accessible_shares_count,
    GROUP_CONCAT(sa.share_name, ',') as all_shares_list,
    GROUP_CONCAT(CASE WHEN sa.accessible = 1 THEN sa.share_name END, ',') as accessible_shares_list,
    MAX(sa.test_timestamp) as last_share_test
FROM smb_servers s
INNER JOIN share_access sa ON s.id = sa.server_id
GROUP BY s.ip_address, s.country, s.auth_method, s.first_seen, s.last_seen
ORDER BY s.last_seen DESC;

-- Create index on the underlying table for better view performance
CREATE INDEX IF NOT EXISTS idx_share_access_server_accessible ON share_access(server_id, accessible);