"""
LLMPot — Feature Extractor
Extracts ML-ready features from session data for clustering.
"""

import numpy as np
from typing import Optional
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils.helpers import password_entropy, password_complexity_score
from analysis.threat_detector import ThreatDetector


class FeatureExtractor:
    """Extracts numerical features from honeypot session data."""

    # Feature names (in order)
    FEATURE_NAMES = [
        "duration_seconds",
        "command_count",
        "unique_commands",
        "dangerous_cmd_count",
        "dangerous_cmd_ratio",
        "avg_cmd_interval",
        "has_download",
        "has_recon",
        "has_persistence",
        "has_destruction",
        "has_reverse_shell",
        "password_entropy",
        "password_complexity",
        "auth_attempts_before_success",
        "max_threat_score",
    ]

    def __init__(self):
        self.threat_detector = ThreatDetector()

    def extract_features(self, session: dict) -> Optional[np.ndarray]:
        """
        Extract a feature vector from a session dictionary.
        
        Expected session keys:
            - duration_seconds, command_count, username, password
            - all_commands (pipe-separated string of commands)
        
        Returns:
            np.ndarray of shape (n_features,)
        """
        try:
            commands = self._parse_commands(session.get("all_commands", ""))
            threat_results = [
                self.threat_detector.analyze_command(cmd) for cmd in commands
            ] if commands else []

            categories = set()
            for r in threat_results:
                if r.get("category"):
                    categories.add(r["category"])

            duration = float(session.get("duration_seconds") or 0)
            cmd_count = int(session.get("command_count") or len(commands))
            unique_cmds = len(set(self._get_base_commands(commands)))

            dangerous_count = sum(1 for r in threat_results if r["is_dangerous"])
            dangerous_ratio = (dangerous_count / max(cmd_count, 1))

            # Average time between commands
            if duration > 0 and cmd_count > 1:
                avg_interval = duration / (cmd_count - 1)
            else:
                avg_interval = 0

            password = session.get("password") or ""

            features = np.array([
                duration,
                cmd_count,
                unique_cmds,
                dangerous_count,
                dangerous_ratio,
                avg_interval,
                1.0 if "malware_download" in categories else 0.0,
                1.0 if "reconnaissance" in categories or "fingerprinting" in categories else 0.0,
                1.0 if "persistence" in categories else 0.0,
                1.0 if "destruction" in categories else 0.0,
                1.0 if "reverse_shell" in categories else 0.0,
                password_entropy(password),
                float(password_complexity_score(password)),
                float(session.get("auth_attempts", 1)),
                float(max((r["score"] for r in threat_results), default=0)),
            ], dtype=np.float64)

            return features

        except Exception as e:
            return None

    def extract_batch(self, sessions: list) -> tuple:
        """
        Extract features from multiple sessions.
        
        Returns:
            (feature_matrix: np.ndarray, valid_session_ids: list)
        """
        features_list = []
        valid_ids = []

        for session in sessions:
            features = self.extract_features(session)
            if features is not None:
                features_list.append(features)
                valid_ids.append(session.get("session_id", "unknown"))

        if not features_list:
            return np.array([]), []

        return np.array(features_list), valid_ids

    @staticmethod
    def _parse_commands(commands_str: str) -> list:
        """Parse pipe-separated command string into list."""
        if not commands_str:
            return []
        return [cmd.strip() for cmd in commands_str.split("|||") if cmd.strip()]

    @staticmethod
    def _get_base_commands(commands: list) -> list:
        """Extract base command names (first word)."""
        base = []
        for cmd in commands:
            parts = cmd.strip().split()
            if parts:
                base.append(parts[0])
        return base
