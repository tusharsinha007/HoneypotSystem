-- LLMPot Database Schema
-- SQLite optimized for honeypot session logging and ML analysis

CREATE TABLE IF NOT EXISTS sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT UNIQUE NOT NULL,
    attacker_ip     TEXT NOT NULL,
    attacker_port   INTEGER,
    username        TEXT,
    password        TEXT,
    auth_success    BOOLEAN DEFAULT 0,
    start_time      DATETIME DEFAULT CURRENT_TIMESTAMP,
    end_time        DATETIME,
    duration_seconds REAL DEFAULT 0,
    command_count   INTEGER DEFAULT 0,
    -- GeoIP data
    country         TEXT,
    country_code    TEXT,
    city            TEXT,
    region          TEXT,
    latitude        REAL,
    longitude       REAL,
    isp             TEXT,
    org             TEXT,
    as_number       TEXT,
    -- Analysis
    threat_level    TEXT DEFAULT 'unknown',
    threat_score    REAL DEFAULT 0,
    cluster_id      INTEGER,
    cluster_label   TEXT,
    is_analyzed     BOOLEAN DEFAULT 0
);

CREATE TABLE IF NOT EXISTS commands (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    command         TEXT NOT NULL,
    output          TEXT,
    timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_dangerous    BOOLEAN DEFAULT 0,
    threat_category TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE TABLE IF NOT EXISTS auth_attempts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    attacker_ip     TEXT NOT NULL,
    attacker_port   INTEGER,
    username        TEXT NOT NULL,
    password        TEXT NOT NULL,
    success         BOOLEAN DEFAULT 0,
    timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP,
    session_id      TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE TABLE IF NOT EXISTS ml_models (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    model_name      TEXT NOT NULL,
    model_path      TEXT NOT NULL,
    trained_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    num_samples     INTEGER,
    num_clusters    INTEGER,
    silhouette_score REAL,
    is_active       BOOLEAN DEFAULT 1
);

CREATE TABLE IF NOT EXISTS incident_reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    report_json     TEXT NOT NULL,
    threat_level    TEXT,
    generated_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(attacker_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_start ON sessions(start_time);
CREATE INDEX IF NOT EXISTS idx_sessions_threat ON sessions(threat_level);
CREATE INDEX IF NOT EXISTS idx_sessions_cluster ON sessions(cluster_id);
CREATE INDEX IF NOT EXISTS idx_commands_session ON commands(session_id);
CREATE INDEX IF NOT EXISTS idx_commands_time ON commands(timestamp);
CREATE INDEX IF NOT EXISTS idx_auth_ip ON auth_attempts(attacker_ip);
CREATE INDEX IF NOT EXISTS idx_auth_time ON auth_attempts(timestamp);
CREATE INDEX IF NOT EXISTS idx_auth_username ON auth_attempts(username);
