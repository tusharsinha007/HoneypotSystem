"""
LLMPot — Incident Report Generator
Generates structured JSON reports for analyzed sessions.
"""

import json
from datetime import datetime
from typing import Optional
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from database.db_manager import DatabaseManager
from analysis.threat_detector import ThreatDetector
from analysis.feature_extractor import FeatureExtractor
from analysis.ml_analyzer import MLAnalyzer
from utils.logger import get_logger
from utils.helpers import format_duration

logger = get_logger("report")


class ReportGenerator:
    """Generates incident reports for honeypot sessions."""

    def __init__(self):
        self.db = DatabaseManager()
        self.threat_detector = ThreatDetector()
        self.feature_extractor = FeatureExtractor()
        self.ml_analyzer = MLAnalyzer()

    def generate_report(self, session_id: str) -> Optional[dict]:
        """Generate a comprehensive incident report for a session."""
        session = self.db.get_session(session_id)
        if not session:
            logger.warning(f"Session not found: {session_id}")
            return None

        commands = self.db.get_session_commands(session_id)
        cmd_texts = [c["command"] for c in commands]

        # Threat analysis
        threat_assessment = self.threat_detector.analyze_session_commands(cmd_texts)

        # ML clustering
        cluster_info = None
        if self.ml_analyzer.is_trained and cmd_texts:
            session_for_ml = dict(session)
            session_for_ml["all_commands"] = "|||".join(cmd_texts)
            features = self.feature_extractor.extract_features(session_for_ml)
            if features is not None:
                cluster_info = self.ml_analyzer.predict(features)

        # Build report
        report = {
            "report_id": f"RPT-{session_id[:8].upper()}",
            "generated_at": datetime.utcnow().isoformat(),
            "session": {
                "session_id": session_id,
                "attacker_ip": session.get("attacker_ip"),
                "username": session.get("username"),
                "password": session.get("password"),
                "start_time": session.get("start_time"),
                "end_time": session.get("end_time"),
                "duration": format_duration(session.get("duration_seconds")),
                "duration_seconds": session.get("duration_seconds"),
                "command_count": session.get("command_count"),
            },
            "geolocation": {
                "country": session.get("country"),
                "country_code": session.get("country_code"),
                "city": session.get("city"),
                "region": session.get("region"),
                "latitude": session.get("latitude"),
                "longitude": session.get("longitude"),
                "isp": session.get("isp"),
                "organization": session.get("org"),
                "as_number": session.get("as_number"),
            },
            "threat_assessment": {
                "overall_level": threat_assessment["threat_level"],
                "max_score": threat_assessment["max_threat_score"],
                "dangerous_commands": threat_assessment["dangerous_commands"],
                "total_commands": threat_assessment["total_commands"],
                "categories": threat_assessment["categories"],
            },
            "ml_classification": cluster_info,
            "command_timeline": [
                {
                    "timestamp": cmd.get("timestamp"),
                    "command": cmd.get("command"),
                    "is_dangerous": bool(cmd.get("is_dangerous")),
                    "category": cmd.get("threat_category"),
                }
                for cmd in commands
            ],
            "indicators_of_compromise": self._extract_iocs(cmd_texts),
            "recommendations": self._generate_recommendations(
                threat_assessment, cluster_info
            ),
        }

        # Update session analysis in DB
        threat_level = threat_assessment["threat_level"]
        threat_score = float(threat_assessment["max_threat_score"])
        cluster_id = cluster_info["cluster_id"] if cluster_info else -1
        cluster_label = cluster_info["cluster_label"] if cluster_info else "unknown"

        try:
            self.db.update_session_analysis(
                session_id=session_id,
                threat_level=threat_level,
                threat_score=threat_score,
                cluster_id=cluster_id,
                cluster_label=cluster_label,
            )
            self.db.save_incident_report(
                session_id=session_id,
                report_json=json.dumps(report, indent=2),
                threat_level=threat_level,
            )
        except Exception as e:
            logger.error(f"Failed to save report: {e}")

        return report

    def generate_batch_reports(self, limit: int = 100) -> list:
        """Generate reports for all unanalyzed sessions."""
        sessions = self.db.get_unanalyzed_sessions(limit)
        reports = []

        for session in sessions:
            report = self.generate_report(session["session_id"])
            if report:
                reports.append(report)

        logger.info(f"Generated {len(reports)} incident reports")
        return reports

    @staticmethod
    def _extract_iocs(commands: list) -> dict:
        """Extract Indicators of Compromise from commands."""
        iocs = {
            "urls": [],
            "ips_referenced": [],
            "files_accessed": [],
            "users_created": [],
        }

        import re
        url_pattern = re.compile(r'https?://\S+')
        ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')

        for cmd in commands:
            # URLs
            urls = url_pattern.findall(cmd)
            iocs["urls"].extend(urls)

            # IPs
            ips = ip_pattern.findall(cmd)
            iocs["ips_referenced"].extend(ips)

            # Files
            if cmd.startswith("cat ") or cmd.startswith("head ") or cmd.startswith("tail "):
                parts = cmd.split()
                if len(parts) > 1:
                    iocs["files_accessed"].append(parts[-1])

            # Users
            if "useradd" in cmd:
                parts = cmd.split()
                if len(parts) > 1:
                    iocs["users_created"].append(parts[-1])

        # Deduplicate
        for key in iocs:
            iocs[key] = list(set(iocs[key]))

        return iocs

    @staticmethod
    def _generate_recommendations(threat_assessment: dict,
                                  cluster_info: Optional[dict]) -> list:
        """Generate actionable recommendations based on analysis."""
        recs = []
        level = threat_assessment["threat_level"]
        categories = threat_assessment.get("categories", [])

        if level in ("critical", "high"):
            recs.append("BLOCK this IP address immediately at the firewall level")
            recs.append("Check for similar attack patterns from the same ASN/region")

        if "malware_download" in categories:
            recs.append("Investigate attempted download URLs for known malware")
            recs.append("Check if similar payloads have been seen in threat intel feeds")

        if "reverse_shell" in categories:
            recs.append("CRITICAL: Reverse shell attempt detected — verify no actual compromise")
            recs.append("Monitor destination IP/port for C2 infrastructure")

        if "persistence" in categories:
            recs.append("Attacker attempted to establish persistence (cron/user creation)")
            recs.append("Review system for unauthorized changes")

        if "destruction" in categories:
            recs.append("Destructive commands detected — this is a hostile attacker")
            recs.append("Report to abuse contact for the source IP")

        if cluster_info and cluster_info.get("cluster_label") == "malware_dropper":
            recs.append("ML Classification: Malware dropper profile — high risk")

        if not recs:
            recs.append("Low-risk session — continue monitoring")
            recs.append("Consider adding source IP to watch list")

        return recs
