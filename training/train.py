"""
LLMPot — Model Training Script
Trains K-Means clustering model on session data.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.db_manager import DatabaseManager
from analysis.feature_extractor import FeatureExtractor
from analysis.ml_analyzer import MLAnalyzer
from config import ML_NUM_CLUSTERS
from utils.logger import get_logger

logger = get_logger("train")


def train_model(find_optimal_k: bool = False):
    """Train K-Means model on all available session data."""
    db = DatabaseManager()
    feature_extractor = FeatureExtractor()
    ml_analyzer = MLAnalyzer()

    # Get training data
    logger.info("Loading session data from database...")
    sessions = db.get_sessions_for_training()

    if not sessions:
        logger.warning("No session data available for training.")
        logger.info("Generate synthetic data first: python training/generate_dataset.py")
        return

    logger.info(f"Found {len(sessions)} sessions for training")

    # Extract features
    logger.info("Extracting features...")
    feature_matrix, session_ids = feature_extractor.extract_batch(sessions)

    if len(feature_matrix) == 0:
        logger.error("No features could be extracted. Check session data.")
        return

    logger.info(f"Extracted {len(feature_matrix)} feature vectors "
                f"with {feature_matrix.shape[1]} features each")

    # Find optimal K if requested
    num_clusters = ML_NUM_CLUSTERS
    if find_optimal_k and len(feature_matrix) > 10:
        logger.info("Finding optimal number of clusters...")
        optimal = ml_analyzer.find_optimal_k(feature_matrix)
        logger.info(f"Silhouette scores: {optimal['scores']}")
        logger.info(f"Optimal k: {optimal['best_k']}")
        num_clusters = optimal["best_k"]

    # Train
    result = ml_analyzer.train(feature_matrix, num_clusters)
    if "error" in result:
        logger.error(f"Training failed: {result['error']}")
        return

    # Save model record to DB
    db.save_model_record(
        model_name="kmeans_attack_classifier",
        model_path=result["model_path"],
        num_samples=result["num_samples"],
        num_clusters=result["num_clusters"],
        silhouette_score=result["silhouette_score"],
    )

    # Classify all sessions
    logger.info("Classifying all sessions with new model...")
    predictions = ml_analyzer.predict_batch(feature_matrix)
    classified = 0
    for session_id, prediction in zip(session_ids, predictions):
        if prediction:
            threat_score = 0
            # Quick threat score from commands
            session = next(
                (s for s in sessions if s.get("session_id") == session_id), None
            )
            if session and session.get("all_commands"):
                from analysis.threat_detector import ThreatDetector
                td = ThreatDetector()
                cmds = session["all_commands"].split("|||")
                result_td = td.analyze_session_commands(cmds)
                threat_score = result_td["max_threat_score"]

            db.update_session_analysis(
                session_id=session_id,
                threat_level=_score_to_level(threat_score),
                threat_score=threat_score,
                cluster_id=prediction["cluster_id"],
                cluster_label=prediction["cluster_label"],
            )
            classified += 1

    logger.info(f"✓ Classified {classified} sessions")
    logger.info("Training complete! Model saved and ready for inference.")


def _score_to_level(score: float) -> str:
    """Convert numeric threat score to level string."""
    if score >= 90:
        return "critical"
    elif score >= 70:
        return "high"
    elif score >= 40:
        return "medium"
    elif score >= 10:
        return "low"
    return "safe"


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Train ML model")
    parser.add_argument("--optimal-k", action="store_true",
                        help="Find optimal number of clusters")
    args = parser.parse_args()
    train_model(find_optimal_k=args.optimal_k)
