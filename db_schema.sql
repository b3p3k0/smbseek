-- SMBSeek SQLite Database Schema
-- Central database for SMB scanning and analysis data

-- Drop existing tables if they exist (for fresh installations)
DROP TABLE IF EXISTS file_manifests;
DROP TABLE IF EXISTS vulnerabilities;
DROP TABLE IF EXISTS share_access;
DROP TABLE IF EXISTS failure_logs;
DROP TABLE IF EXISTS smb_servers;
DROP TABLE IF EXISTS scan_sessions;

-- Core scan session tracking
CREATE TABLE scan_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name VARCHAR(50) NOT NULL,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    config_snapshot TEXT, -- JSON snapshot of configuration used
    status VARCHAR(20) DEFAULT 'running', -- running, completed, failed
    total_targets INTEGER DEFAULT 0,
    successful_targets INTEGER DEFAULT 0,
    failed_targets INTEGER DEFAULT 0,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Central SMB server registry
CREATE TABLE smb_servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address VARCHAR(45) NOT NULL UNIQUE, -- IPv4 or IPv6
    country VARCHAR(100),
    country_code VARCHAR(2),
    auth_method VARCHAR(50), -- Guest/Blank, Anonymous, etc.
    shodan_data TEXT, -- JSON blob of Shodan metadata
    first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    scan_count INTEGER DEFAULT 1,
    status VARCHAR(20) DEFAULT 'active', -- active, inactive, blocked
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- SMB share accessibility results  
CREATE TABLE share_access (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    session_id INTEGER NOT NULL,
    share_name VARCHAR(255) NOT NULL,
    accessible BOOLEAN NOT NULL DEFAULT FALSE,
    permissions TEXT, -- JSON array of permissions (read, write, etc.)
    share_type VARCHAR(50), -- disk, printer, pipe, etc.
    share_comment TEXT,
    test_timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    access_details TEXT, -- JSON blob with detailed access information
    error_message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (server_id) REFERENCES smb_servers(id) ON DELETE CASCADE,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
);

-- File discovery and manifest records
CREATE TABLE file_manifests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    session_id INTEGER NOT NULL,
    share_name VARCHAR(255) NOT NULL,
    file_path TEXT NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    file_size INTEGER DEFAULT 0,
    file_type VARCHAR(50), -- extension or detected type
    file_extension VARCHAR(10),
    mime_type VARCHAR(100),
    last_modified DATETIME,
    is_ransomware_indicator BOOLEAN DEFAULT FALSE,
    is_sensitive BOOLEAN DEFAULT FALSE,
    discovery_timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    metadata TEXT, -- JSON blob for additional file metadata
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (server_id) REFERENCES smb_servers(id) ON DELETE CASCADE,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
);

-- Security vulnerability findings
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    session_id INTEGER NOT NULL,
    vuln_type VARCHAR(100) NOT NULL, -- weak_auth, open_shares, ransomware, etc.
    severity VARCHAR(20) NOT NULL, -- low, medium, high, critical
    title VARCHAR(255) NOT NULL,
    description TEXT,
    evidence TEXT, -- JSON blob with supporting evidence
    remediation TEXT,
    cvss_score DECIMAL(3,1),
    cve_ids TEXT, -- Comma-separated CVE identifiers
    discovery_timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'open', -- open, acknowledged, remediated, false_positive
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (server_id) REFERENCES smb_servers(id) ON DELETE CASCADE,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
);

-- Connection failure logs and analysis
CREATE TABLE failure_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    ip_address VARCHAR(45) NOT NULL,
    failure_timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    failure_type VARCHAR(100), -- connection_timeout, auth_failed, port_closed, etc.
    failure_reason TEXT,
    shodan_data TEXT, -- JSON blob of Shodan data for failed target
    analysis_results TEXT, -- JSON blob with failure analysis findings
    retry_count INTEGER DEFAULT 0,
    last_retry_timestamp DATETIME,
    resolved BOOLEAN DEFAULT FALSE,
    resolution_notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id) ON DELETE SET NULL
);

-- Create indexes for performance
CREATE INDEX idx_smb_servers_ip ON smb_servers(ip_address);
CREATE INDEX idx_smb_servers_country ON smb_servers(country);
CREATE INDEX idx_smb_servers_last_seen ON smb_servers(last_seen);
CREATE INDEX idx_share_access_server ON share_access(server_id);
CREATE INDEX idx_share_access_session ON share_access(session_id);
CREATE INDEX idx_share_access_accessible ON share_access(accessible);
CREATE INDEX idx_file_manifests_server ON file_manifests(server_id);
CREATE INDEX idx_file_manifests_session ON file_manifests(session_id);
CREATE INDEX idx_file_manifests_ransomware ON file_manifests(is_ransomware_indicator);
CREATE INDEX idx_vulnerabilities_server ON vulnerabilities(server_id);
CREATE INDEX idx_vulnerabilities_session ON vulnerabilities(session_id);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_failure_logs_ip ON failure_logs(ip_address);
CREATE INDEX idx_failure_logs_timestamp ON failure_logs(failure_timestamp);
CREATE INDEX idx_scan_sessions_timestamp ON scan_sessions(timestamp);
CREATE INDEX idx_scan_sessions_tool ON scan_sessions(tool_name);

-- Create views for common queries
CREATE VIEW v_active_servers AS
SELECT 
    s.id,
    s.ip_address,
    s.country,
    s.auth_method,
    s.first_seen,
    s.last_seen,
    s.scan_count,
    COUNT(DISTINCT sa.share_name) as accessible_shares_count,
    COUNT(DISTINCT fm.file_path) as files_discovered,
    COUNT(DISTINCT v.id) as vulnerability_count
FROM smb_servers s
LEFT JOIN share_access sa ON s.id = sa.server_id AND sa.accessible = TRUE
LEFT JOIN file_manifests fm ON s.id = fm.server_id
LEFT JOIN vulnerabilities v ON s.id = v.server_id AND v.status = 'open'
WHERE s.status = 'active'
GROUP BY s.id, s.ip_address, s.country, s.auth_method, s.first_seen, s.last_seen, s.scan_count;

CREATE VIEW v_vulnerability_summary AS
SELECT 
    vuln_type,
    severity,
    COUNT(*) as count,
    COUNT(DISTINCT server_id) as affected_servers
FROM vulnerabilities 
WHERE status = 'open'
GROUP BY vuln_type, severity
ORDER BY 
    CASE severity 
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2  
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        ELSE 5
    END,
    count DESC;

CREATE VIEW v_scan_statistics AS
SELECT 
    tool_name,
    DATE(timestamp) as scan_date,
    COUNT(*) as sessions,
    SUM(total_targets) as total_targets,
    SUM(successful_targets) as successful_targets,
    SUM(failed_targets) as failed_targets,
    ROUND(AVG(CAST(successful_targets AS FLOAT) / CAST(total_targets AS FLOAT)) * 100, 2) as success_rate
FROM scan_sessions 
WHERE total_targets > 0
GROUP BY tool_name, DATE(timestamp)
ORDER BY scan_date DESC;