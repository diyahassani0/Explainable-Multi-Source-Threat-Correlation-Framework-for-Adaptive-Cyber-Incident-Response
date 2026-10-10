-- SQLite Schema for Threat Correlation Framework

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    year INTEGER NOT NULL,
    day INTEGER NOT NULL,
    amount_lost_inr REAL NOT NULL,
    incident_type TEXT NOT NULL,
    city TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    predicted_severity TEXT,
    confidence_score REAL DEFAULT 0.0,
    investigation_status TEXT DEFAULT 'New',
    source_ip TEXT,
    dest_ip TEXT,
    primary_source TEXT DEFAULT 'Endpoint',
    correlated_cluster_id INTEGER DEFAULT 0,
    mitre_tactic TEXT,
    analyst_verdict TEXT DEFAULT 'Unreviewed',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_logs (
    log_id TEXT PRIMARY KEY,
    incident_id INTEGER,
    timestamp TEXT NOT NULL,
    log_source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    source_ip TEXT,
    dest_ip TEXT,
    source_port INTEGER,
    dest_port INTEGER,
    protocol TEXT,
    action_taken TEXT,
    raw_log TEXT,
    threat_intel_score REAL DEFAULT 0.0,
    FOREIGN KEY(incident_id) REFERENCES incidents(id)
);

CREATE TABLE IF NOT EXISTS correlation_clusters (
    cluster_id INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster_name TEXT NOT NULL,
    root_cause_type TEXT NOT NULL,
    primary_ip TEXT,
    entity_target TEXT,
    correlation_rule TEXT,
    confidence REAL DEFAULT 0.0,
    attack_chain_stages TEXT,
    incident_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS soar_actions (
    action_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER,
    action_type TEXT NOT NULL,
    target_entity TEXT NOT NULL,
    execution_mode TEXT DEFAULT 'Simulated',
    status TEXT DEFAULT 'Pending Confirmation',
    playbook_name TEXT,
    blast_radius_risk TEXT DEFAULT 'Low',
    analyst_id TEXT DEFAULT 'SOC_Analyst_1',
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    details TEXT
);

CREATE TABLE IF NOT EXISTS analyst_notes (
    note_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    author TEXT DEFAULT 'SOC Analyst',
    note_text TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(incident_id) REFERENCES incidents(id)
);

CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(investigation_status);
CREATE INDEX IF NOT EXISTS idx_logs_source ON security_logs(log_source);
CREATE INDEX IF NOT EXISTS idx_logs_incident ON security_logs(incident_id);
