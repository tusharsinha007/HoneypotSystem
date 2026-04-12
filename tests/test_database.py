"""
LLMPot — Database Unit Tests
"""

import sys
import os
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from database.db_manager import DatabaseManager


@pytest.fixture
def db(tmp_path):
    """Create a fresh database for each test."""
    db_path = str(tmp_path / "test_honeypot.db")
    # Reset singleton for tests
    DatabaseManager._instance = None
    database = DatabaseManager(db_path)
    yield database
    database.close()
    DatabaseManager._instance = None


class TestDatabaseManager:
    """Test database operations."""

    def test_create_session(self, db):
        db.create_session(
            session_id="test-001",
            attacker_ip="192.168.1.100",
            attacker_port=54321,
            username="root",
            password="root",
            auth_success=True,
        )
        session = db.get_session("test-001")
        assert session is not None
        assert session["attacker_ip"] == "192.168.1.100"
        assert session["username"] == "root"

    def test_session_count(self, db):
        assert db.get_session_count() == 0
        db.create_session("s1", "1.1.1.1", 100)
        db.create_session("s2", "2.2.2.2", 200)
        assert db.get_session_count() == 2

    def test_log_command(self, db):
        db.create_session("cmd-session", "1.1.1.1", 100)
        db.log_command("cmd-session", "whoami", "root", False)
        db.log_command("cmd-session", "rm -rf /", "", True, "destruction")

        cmds = db.get_session_commands("cmd-session")
        assert len(cmds) == 2
        assert cmds[0]["command"] == "whoami"
        assert cmds[1]["is_dangerous"] == 1

    def test_auth_attempts(self, db):
        db.log_auth_attempt("1.1.1.1", 100, "root", "wrong", False)
        db.log_auth_attempt("1.1.1.1", 100, "root", "root", True)

        attempts = db.get_auth_attempts(limit=10)
        assert len(attempts) == 2

    def test_end_session(self, db):
        db.create_session("end-test", "1.1.1.1", 100)
        db.end_session("end-test", command_count=5)

        session = db.get_session("end-test")
        assert session["command_count"] == 5
        assert session["end_time"] is not None

    def test_stats_summary(self, db):
        db.create_session("s1", "1.1.1.1", 100, auth_success=True)
        db.create_session("s2", "2.2.2.2", 200, auth_success=False)

        stats = db.get_stats_summary()
        assert stats["total_sessions"] == 2
        assert stats["auth_successes"] == 1
        assert stats["unique_attackers"] == 2

    def test_top_attackers(self, db):
        for i in range(5):
            db.create_session(f"a-{i}", "1.1.1.1", 100)
        for i in range(3):
            db.create_session(f"b-{i}", "2.2.2.2", 200)

        top = db.get_top_attackers(limit=2)
        assert len(top) == 2
        assert top[0]["attacker_ip"] == "1.1.1.1"
        assert top[0]["attack_count"] == 5

    def test_geo_data(self, db):
        db.create_session(
            "geo-test", "8.8.8.8", 100,
            geo_data={
                "country": "United States",
                "countryCode": "US",
                "city": "Mountain View",
                "lat": 37.3861,
                "lon": -122.0839,
                "isp": "Google",
            }
        )
        session = db.get_session("geo-test")
        assert session["country"] == "United States"
        assert abs(session["latitude"] - 37.3861) < 0.01

    def test_update_analysis(self, db):
        db.create_session("ml-test", "1.1.1.1", 100)
        db.update_session_analysis(
            "ml-test",
            threat_level="high",
            threat_score=85.0,
            cluster_id=2,
            cluster_label="malware_dropper",
        )
        session = db.get_session("ml-test")
        assert session["threat_level"] == "high"
        assert session["cluster_label"] == "malware_dropper"
        assert session["is_analyzed"] == 1
