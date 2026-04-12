"""
LLMPot — Database Manager
Thread-safe SQLite wrapper for all honeypot data operations.
"""

import sqlite3
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Any

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import DB_PATH


class DatabaseManager:
    """Thread-safe SQLite database manager for the honeypot."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, db_path: str = DB_PATH):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, db_path: str = DB_PATH):
        if self._initialized:
            return
        self.db_path = db_path
        self._local = threading.local()
        self._write_lock = threading.Lock()
        self._init_db()
        self._initialized = True

    def _get_conn(self) -> sqlite3.Connection:
        """Get thread-local database connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=30
            )
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
        return self._local.conn

    def _init_db(self):
        """Initialize database schema."""
        schema_path = Path(__file__).parent / "schema.sql"
        with open(schema_path, "r") as f:
            schema_sql = f.read()
        conn = self._get_conn()
        conn.executescript(schema_sql)
        conn.commit()

    def _execute(self, query: str, params: tuple = (), fetch: bool = False,
                 fetchone: bool = False) -> Any:
        """Execute a query with thread safety for writes."""
        conn = self._get_conn()
        if query.strip().upper().startswith("SELECT"):
            cursor = conn.execute(query, params)
            if fetchone:
                return cursor.fetchone()
            if fetch:
                return cursor.fetchall()
            return cursor
        else:
            with self._write_lock:
                cursor = conn.execute(query, params)
                conn.commit()
                return cursor

    # ─── Session Operations ───────────────────────────────────────────────────

    def create_session(self, session_id: str, attacker_ip: str,
                       attacker_port: int, username: str = None,
                       password: str = None, auth_success: bool = False,
                       geo_data: dict = None) -> None:
        """Record a new session."""
        geo = geo_data or {}
        self._execute(
            """INSERT INTO sessions
               (session_id, attacker_ip, attacker_port, username, password,
                auth_success, country, country_code, city, region,
                latitude, longitude, isp, org, as_number)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (session_id, attacker_ip, attacker_port, username, password,
             auth_success,
             geo.get("country"), geo.get("countryCode"), geo.get("city"),
             geo.get("regionName"), geo.get("lat"), geo.get("lon"),
             geo.get("isp"), geo.get("org"), geo.get("as"))
        )

    def end_session(self, session_id: str, command_count: int = 0) -> None:
        """Mark a session as ended."""
        self._execute(
            """UPDATE sessions
               SET end_time = CURRENT_TIMESTAMP,
                   duration_seconds = (julianday(CURRENT_TIMESTAMP) -
                                       julianday(start_time)) * 86400,
                   command_count = ?
               WHERE session_id = ?""",
            (command_count, session_id)
        )

    def get_session(self, session_id: str) -> Optional[dict]:
        """Get a single session."""
        row = self._execute(
            "SELECT * FROM sessions WHERE session_id = ?",
            (session_id,), fetchone=True
        )
        return dict(row) if row else None

    def get_sessions(self, limit: int = 100, offset: int = 0,
                     threat_level: str = None) -> list:
        """Get recent sessions."""
        query = "SELECT * FROM sessions"
        params = []
        if threat_level:
            query += " WHERE threat_level = ?"
            params.append(threat_level)
        query += " ORDER BY start_time DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = self._execute(query, tuple(params), fetch=True)
        return [dict(r) for r in rows]

    def get_session_count(self) -> int:
        """Get total session count."""
        row = self._execute("SELECT COUNT(*) as cnt FROM sessions", fetchone=True)
        return row["cnt"] if row else 0

    def get_unanalyzed_sessions(self, limit: int = 500) -> list:
        """Get sessions that haven't been ML-analyzed yet."""
        rows = self._execute(
            """SELECT * FROM sessions
               WHERE is_analyzed = 0 AND auth_success = 1
               ORDER BY start_time ASC LIMIT ?""",
            (limit,), fetch=True
        )
        return [dict(r) for r in rows]

    def update_session_analysis(self, session_id: str, threat_level: str,
                                threat_score: float, cluster_id: int,
                                cluster_label: str) -> None:
        """Update session with ML analysis results."""
        self._execute(
            """UPDATE sessions
               SET threat_level = ?, threat_score = ?,
                   cluster_id = ?, cluster_label = ?, is_analyzed = 1
               WHERE session_id = ?""",
            (threat_level, threat_score, cluster_id, cluster_label, session_id)
        )

    # ─── Command Operations ──────────────────────────────────────────────────

    def log_command(self, session_id: str, command: str, output: str = "",
                    is_dangerous: bool = False, threat_category: str = None) -> None:
        """Log a command executed in a session."""
        self._execute(
            """INSERT INTO commands
               (session_id, command, output, is_dangerous, threat_category)
               VALUES (?, ?, ?, ?, ?)""",
            (session_id, command, output, is_dangerous, threat_category)
        )

    def get_session_commands(self, session_id: str) -> list:
        """Get all commands for a session."""
        rows = self._execute(
            "SELECT * FROM commands WHERE session_id = ? ORDER BY timestamp ASC",
            (session_id,), fetch=True
        )
        return [dict(r) for r in rows]

    # ─── Auth Operations ─────────────────────────────────────────────────────

    def log_auth_attempt(self, attacker_ip: str, attacker_port: int,
                         username: str, password: str, success: bool,
                         session_id: str = None) -> None:
        """Log an authentication attempt."""
        self._execute(
            """INSERT INTO auth_attempts
               (attacker_ip, attacker_port, username, password, success, session_id)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (attacker_ip, attacker_port, username, password, success, session_id)
        )

    def get_auth_attempts(self, limit: int = 100) -> list:
        """Get recent auth attempts."""
        rows = self._execute(
            "SELECT * FROM auth_attempts ORDER BY timestamp DESC LIMIT ?",
            (limit,), fetch=True
        )
        return [dict(r) for r in rows]

    # ─── ML Model Operations ────────────────────────────────────────────────

    def save_model_record(self, model_name: str, model_path: str,
                          num_samples: int, num_clusters: int,
                          silhouette_score: float) -> None:
        """Record a trained model."""
        # Deactivate previous models
        self._execute("UPDATE ml_models SET is_active = 0 WHERE model_name = ?",
                      (model_name,))
        self._execute(
            """INSERT INTO ml_models
               (model_name, model_path, num_samples, num_clusters,
                silhouette_score, is_active)
               VALUES (?, ?, ?, ?, ?, 1)""",
            (model_name, model_path, num_samples, num_clusters, silhouette_score)
        )

    def save_incident_report(self, session_id: str, report_json: str,
                             threat_level: str) -> None:
        """Save an incident report."""
        self._execute(
            """INSERT INTO incident_reports
               (session_id, report_json, threat_level)
               VALUES (?, ?, ?)""",
            (session_id, report_json, threat_level)
        )

    # ─── Dashboard Queries ───────────────────────────────────────────────────

    def get_stats_summary(self) -> dict:
        """Get overall statistics for dashboard."""
        total = self._execute(
            "SELECT COUNT(*) as cnt FROM sessions", fetchone=True)
        auth_success = self._execute(
            "SELECT COUNT(*) as cnt FROM sessions WHERE auth_success = 1",
            fetchone=True)
        unique_ips = self._execute(
            "SELECT COUNT(DISTINCT attacker_ip) as cnt FROM sessions",
            fetchone=True)
        total_commands = self._execute(
            "SELECT COUNT(*) as cnt FROM commands", fetchone=True)
        dangerous_cmds = self._execute(
            "SELECT COUNT(*) as cnt FROM commands WHERE is_dangerous = 1",
            fetchone=True)
        today = datetime.utcnow().strftime("%Y-%m-%d")
        today_sessions = self._execute(
            "SELECT COUNT(*) as cnt FROM sessions WHERE DATE(start_time) = ?",
            (today,), fetchone=True)

        return {
            "total_sessions": total["cnt"] if total else 0,
            "auth_successes": auth_success["cnt"] if auth_success else 0,
            "unique_attackers": unique_ips["cnt"] if unique_ips else 0,
            "total_commands": total_commands["cnt"] if total_commands else 0,
            "dangerous_commands": dangerous_cmds["cnt"] if dangerous_cmds else 0,
            "today_sessions": today_sessions["cnt"] if today_sessions else 0,
        }

    def get_top_attackers(self, limit: int = 10) -> list:
        """Get most frequent attacker IPs."""
        rows = self._execute(
            """SELECT attacker_ip, country, COUNT(*) as attack_count,
                      MAX(start_time) as last_seen
               FROM sessions GROUP BY attacker_ip
               ORDER BY attack_count DESC LIMIT ?""",
            (limit,), fetch=True
        )
        return [dict(r) for r in rows]

    def get_top_credentials(self, limit: int = 10) -> list:
        """Get most used username/password combos."""
        rows = self._execute(
            """SELECT username, password, COUNT(*) as attempt_count
               FROM auth_attempts
               GROUP BY username, password
               ORDER BY attempt_count DESC LIMIT ?""",
            (limit,), fetch=True
        )
        return [dict(r) for r in rows]

    def get_hourly_trend(self, days: int = 7) -> list:
        """Get hourly attack counts for the past N days."""
        cutoff = (datetime.utcnow() - timedelta(days=days)).strftime(
            "%Y-%m-%d %H:%M:%S")
        rows = self._execute(
            """SELECT strftime('%Y-%m-%d %H:00:00', start_time) as hour,
                      COUNT(*) as count
               FROM sessions
               WHERE start_time >= ?
               GROUP BY hour ORDER BY hour ASC""",
            (cutoff,), fetch=True
        )
        return [dict(r) for r in rows]

    def get_attack_locations(self) -> list:
        """Get all sessions with geo coordinates for the map."""
        rows = self._execute(
            """SELECT attacker_ip, latitude, longitude, country, city,
                      threat_level, COUNT(*) as attack_count
               FROM sessions
               WHERE latitude IS NOT NULL AND longitude IS NOT NULL
               GROUP BY attacker_ip
               ORDER BY attack_count DESC""",
            fetch=True
        )
        return [dict(r) for r in rows]

    def get_command_frequency(self, limit: int = 20) -> list:
        """Get most frequently used commands."""
        rows = self._execute(
            """SELECT command, COUNT(*) as count, 
                      SUM(is_dangerous) as dangerous_count
               FROM commands
               GROUP BY command ORDER BY count DESC LIMIT ?""",
            (limit,), fetch=True
        )
        return [dict(r) for r in rows]

    def get_cluster_distribution(self) -> list:
        """Get session counts per cluster."""
        rows = self._execute(
            """SELECT cluster_id, cluster_label, COUNT(*) as count,
                      AVG(duration_seconds) as avg_duration,
                      AVG(command_count) as avg_commands,
                      AVG(threat_score) as avg_threat_score
               FROM sessions
               WHERE cluster_id IS NOT NULL
               GROUP BY cluster_id ORDER BY cluster_id""",
            fetch=True
        )
        return [dict(r) for r in rows]

    def get_sessions_for_training(self) -> list:
        """Get all authenticated sessions with commands for ML training."""
        rows = self._execute(
            """SELECT s.*, GROUP_CONCAT(c.command, '|||') as all_commands
               FROM sessions s
               LEFT JOIN commands c ON s.session_id = c.session_id
               WHERE s.auth_success = 1
               GROUP BY s.session_id""",
            fetch=True
        )
        return [dict(r) for r in rows]

    def close(self):
        """Close the thread-local connection."""
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None
