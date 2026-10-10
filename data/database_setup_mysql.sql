-- MySQL Compatibility Schema for Threat Correlation Framework
-- Database: threat_correlation_db

CREATE DATABASE IF NOT EXISTS threat_correlation_db;
USE threat_correlation_db;

CREATE TABLE IF NOT EXISTS incidents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    year INT NOT NULL,
    day INT NOT NULL,
    amount_lost_inr DOUBLE NOT NULL,
    incident_type VARCHAR(100) NOT NULL,
    city VARCHAR(100) NOT NULL,
    category VARCHAR(100) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    predicted_severity VARCHAR(50),
    confidence_score DOUBLE DEFAULT 0.0,
    investigation_status VARCHAR(50) DEFAULT 'New',
    source_ip VARCHAR(50),
    dest_ip VARCHAR(50),
    primary_source VARCHAR(50) DEFAULT 'Endpoint',
    correlated_cluster_id INT DEFAULT 0,
    mitre_tactic VARCHAR(100),
    analyst_verdict VARCHAR(50) DEFAULT 'Unreviewed',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_sev (severity),
    INDEX idx_stat (investigation_status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS security_logs (
    log_id VARCHAR(100) PRIMARY KEY,
    incident_id INT,
    timestamp VARCHAR(50) NOT NULL,
    log_source VARCHAR(50) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    source_ip VARCHAR(50),
    dest_ip VARCHAR(50),
    source_port INT,
    dest_port INT,
    protocol VARCHAR(20),
    action_taken VARCHAR(50),
    raw_log TEXT,
    threat_intel_score DOUBLE DEFAULT 0.0,
    INDEX idx_src (log_source),
    INDEX idx_inc (incident_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS correlation_clusters (
    cluster_id INT AUTO_INCREMENT PRIMARY KEY,
    cluster_name VARCHAR(150) NOT NULL,
    root_cause_type VARCHAR(100) NOT NULL,
    primary_ip VARCHAR(50),
    entity_target VARCHAR(100),
    correlation_rule VARCHAR(255),
    confidence DOUBLE DEFAULT 0.0,
    attack_chain_stages TEXT,
    incident_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS soar_actions (
    action_id INT AUTO_INCREMENT PRIMARY KEY,
    incident_id INT,
    action_type VARCHAR(100) NOT NULL,
    target_entity VARCHAR(150) NOT NULL,
    execution_mode VARCHAR(50) DEFAULT 'Simulated',
    status VARCHAR(50) DEFAULT 'Pending Confirmation',
    playbook_name VARCHAR(100),
    blast_radius_risk VARCHAR(50) DEFAULT 'Low',
    analyst_id VARCHAR(50) DEFAULT 'SOC_Analyst_1',
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    details TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS analyst_notes (
    note_id INT AUTO_INCREMENT PRIMARY KEY,
    incident_id INT NOT NULL,
    author VARCHAR(50) DEFAULT 'SOC Analyst',
    note_text TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_inc_note (incident_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
