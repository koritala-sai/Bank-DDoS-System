-- Bank DDoS Detection System Database Schema
-- Database Target: MySQL 8.0+

CREATE DATABASE IF NOT EXISTS bank_ddos;
USE bank_ddos;

-- -----------------------------------------------------
-- Table 1: traffic_records
-- Stores processed network traffic metrics and ML predictions
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS traffic_records (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    destination_ip VARCHAR(45) NOT NULL,
    source_port INT NULL,
    destination_port INT NULL,
    protocol VARCHAR(20) NULL,
    flow_duration FLOAT NULL,
    packet_count INT NULL,
    prediction VARCHAR(50) NOT NULL DEFAULT 'Normal',
    risk_level VARCHAR(20) NOT NULL DEFAULT 'LOW',
    confidence FLOAT NULL,
    INDEX idx_timestamp (timestamp),
    INDEX idx_source_ip (source_ip),
    INDEX idx_destination_ip (destination_ip),
    INDEX idx_risk_level (risk_level)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- -----------------------------------------------------
-- Table 2: alerts
-- Stores security alerts generated when DDoS is detected
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    alert_type VARCHAR(50) NOT NULL DEFAULT 'DDoS',
    risk_level VARCHAR(20) NOT NULL DEFAULT 'HIGH',
    message TEXT NOT NULL,
    source_ip VARCHAR(45) NULL,
    destination_ip VARCHAR(45) NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'NEW',
    INDEX idx_timestamp (timestamp),
    INDEX idx_status (status),
    INDEX idx_risk_level (risk_level)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
