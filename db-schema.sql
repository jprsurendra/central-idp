CREATE DATABASE IF NOT EXISTS central_idp_db;
USE central_idp_db;

CREATE TABLE identity_users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    external_id VARCHAR(36) NOT NULL UNIQUE,  -- durable identifier exposed to consumers (e.g. ems-auth); internal 'id' above is never exposed
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    department VARCHAR(100),
    role VARCHAR(50) NOT NULL DEFAULT 'CITIZEN',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_username (username),
    INDEX idx_external_id (external_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed test user — username: testvendor / password: Test@123
-- Hash generated with BCrypt strength 12, matching platform convention.
INSERT INTO identity_users (external_id, username, password_hash, full_name, email, department, role) VALUES
('a17d5415-3fcf-4bb6-bbcb-6c1e8872db72', 'testvendor', '$2b$12$7t0m75ubhx56KyXtk0ICk.rZixtb7x/s6a1L/pV9CDeF8S8bCaD8G', 'Test Vendor', 'testvendor@example.com', 'MSME Services', 'CITIZEN');
