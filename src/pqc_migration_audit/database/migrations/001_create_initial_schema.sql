-- Initial database schema for PQC Migration Audit
-- Migration: 001_create_initial_schema
-- Created: 2025-01-01

-- Create scan_results table
CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_path TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    scan_time REAL NOT NULL,
    scanned_files INTEGER NOT NULL,
    total_lines INTEGER NOT NULL,
    languages_detected TEXT NOT NULL,  -- JSON array
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create vulnerabilities table
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_result_id INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    line_number INTEGER NOT NULL,
    algorithm TEXT NOT NULL,
    severity TEXT NOT NULL,
    key_size INTEGER,
    description TEXT NOT NULL,
    code_snippet TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    cwe_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_result_id) REFERENCES scan_results(id) ON DELETE CASCADE
);

-- Create migration_plans table
CREATE TABLE IF NOT EXISTS migration_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_result_id INTEGER NOT NULL,
    plan_data TEXT NOT NULL,  -- JSON data
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_result_id) REFERENCES scan_results(id) ON DELETE CASCADE
);

-- Create risk_assessments table
CREATE TABLE IF NOT EXISTS risk_assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_result_id INTEGER NOT NULL,
    hndl_risk_score INTEGER NOT NULL,
    migration_hours INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    assessment_data TEXT NOT NULL,  -- JSON data
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_result_id) REFERENCES scan_results(id) ON DELETE CASCADE
);

-- Create inventory_items table
CREATE TABLE IF NOT EXISTS inventory_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_result_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    version TEXT,
    location TEXT NOT NULL,
    algorithms TEXT NOT NULL,  -- JSON array
    key_sizes TEXT,  -- JSON array
    usage_context TEXT NOT NULL,
    pqc_ready BOOLEAN DEFAULT FALSE,
    migration_priority TEXT NOT NULL,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_result_id) REFERENCES scan_results(id) ON DELETE CASCADE
);

-- Create compliance_assessments table
CREATE TABLE IF NOT EXISTS compliance_assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_result_id INTEGER NOT NULL,
    framework TEXT NOT NULL,
    compliance_percentage REAL NOT NULL,
    requirements_met TEXT NOT NULL,  -- JSON array
    requirements_pending TEXT NOT NULL,  -- JSON array
    deadline TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_result_id) REFERENCES scan_results(id) ON DELETE CASCADE
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_result ON vulnerabilities(scan_result_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_algorithm ON vulnerabilities(algorithm);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_file_path ON vulnerabilities(file_path);

CREATE INDEX IF NOT EXISTS idx_scan_results_timestamp ON scan_results(timestamp);
CREATE INDEX IF NOT EXISTS idx_scan_results_scan_path ON scan_results(scan_path);

CREATE INDEX IF NOT EXISTS idx_migration_plans_scan_result ON migration_plans(scan_result_id);

CREATE INDEX IF NOT EXISTS idx_risk_assessments_scan_result ON risk_assessments(scan_result_id);
CREATE INDEX IF NOT EXISTS idx_risk_assessments_risk_score ON risk_assessments(hndl_risk_score);

CREATE INDEX IF NOT EXISTS idx_inventory_items_scan_result ON inventory_items(scan_result_id);
CREATE INDEX IF NOT EXISTS idx_inventory_items_priority ON inventory_items(migration_priority);
CREATE INDEX IF NOT EXISTS idx_inventory_items_pqc_ready ON inventory_items(pqc_ready);

CREATE INDEX IF NOT EXISTS idx_compliance_assessments_scan_result ON compliance_assessments(scan_result_id);
CREATE INDEX IF NOT EXISTS idx_compliance_assessments_framework ON compliance_assessments(framework);

-- Create views for commonly used queries

-- View for vulnerability summary by scan
CREATE VIEW IF NOT EXISTS vulnerability_summary AS
SELECT 
    sr.id as scan_result_id,
    sr.scan_path,
    sr.timestamp,
    COUNT(v.id) as total_vulnerabilities,
    SUM(CASE WHEN v.severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
    SUM(CASE WHEN v.severity = 'high' THEN 1 ELSE 0 END) as high_count,
    SUM(CASE WHEN v.severity = 'medium' THEN 1 ELSE 0 END) as medium_count,
    SUM(CASE WHEN v.severity = 'low' THEN 1 ELSE 0 END) as low_count
FROM scan_results sr
LEFT JOIN vulnerabilities v ON sr.id = v.scan_result_id
GROUP BY sr.id, sr.scan_path, sr.timestamp;

-- View for algorithm distribution across all scans
CREATE VIEW IF NOT EXISTS algorithm_distribution AS
SELECT 
    algorithm,
    COUNT(*) as vulnerability_count,
    COUNT(DISTINCT scan_result_id) as affected_scans,
    AVG(CASE 
        WHEN severity = 'critical' THEN 4
        WHEN severity = 'high' THEN 3
        WHEN severity = 'medium' THEN 2
        WHEN severity = 'low' THEN 1
        ELSE 0
    END) as avg_severity_score
FROM vulnerabilities
GROUP BY algorithm
ORDER BY vulnerability_count DESC;

-- View for migration priority overview
CREATE VIEW IF NOT EXISTS migration_priority_overview AS
SELECT 
    migration_priority,
    COUNT(*) as item_count,
    COUNT(CASE WHEN pqc_ready = 1 THEN 1 END) as pqc_ready_count,
    ROUND(
        (COUNT(CASE WHEN pqc_ready = 1 THEN 1 END) * 100.0) / COUNT(*), 
        2
    ) as pqc_ready_percentage
FROM inventory_items
GROUP BY migration_priority
ORDER BY 
    CASE migration_priority
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        ELSE 5
    END;

-- View for compliance tracking
CREATE VIEW IF NOT EXISTS compliance_tracking AS
SELECT 
    framework,
    COUNT(*) as total_assessments,
    AVG(compliance_percentage) as avg_compliance,
    MAX(compliance_percentage) as best_compliance,
    MIN(compliance_percentage) as worst_compliance,
    MAX(created_at) as latest_assessment
FROM compliance_assessments
GROUP BY framework
ORDER BY avg_compliance DESC;