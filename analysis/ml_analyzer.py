"""
LLMPot — ML Analyzer
K-Means clustering for attack behavior classification.
"""

import os
import sys
import numpy as np
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import ML_MODEL_PATH, ML_SCALER_PATH, ML_NUM_CLUSTERS, CLUSTER_LABELS
from utils.logger import get_logger

logger = get_logger("ml")

try:
    from sklearn.cluster import KMeans
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import silhouette_score
    from sklearn.decomposition import PCA
    import joblib
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    logger.warning("scikit-learn not installed. ML features disabled.")


class MLAnalyzer:
    """K-Means clustering analyzer for attack session classification."""

    def __init__(self):
        self.model = None
        self.scaler = None
        self.pca = None
        self.num_clusters = ML_NUM_CLUSTERS
        self._load_model()

    def _load_model(self):
        """Load trained model and scaler from disk."""
        if not HAS_SKLEARN:
            return

        try:
            if os.path.exists(ML_MODEL_PATH) and os.path.exists(ML_SCALER_PATH):
                self.model = joblib.load(ML_MODEL_PATH)
                self.scaler = joblib.load(ML_SCALER_PATH)
                logger.info(f"Loaded ML model from {ML_MODEL_PATH}")
                logger.info(f"  Clusters: {self.model.n_clusters}")
            else:
                logger.info("No trained model found. Train with: python training/train.py")
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")
            self.model = None
            self.scaler = None

    def train(self, feature_matrix: np.ndarray, num_clusters: int = None) -> dict:
        """
        Train K-Means model on feature matrix.
        
        Args:
            feature_matrix: np.ndarray of shape (n_samples, n_features)
            num_clusters: Override number of clusters
        
        Returns:
            dict with training metrics
        """
        if not HAS_SKLEARN:
            return {"error": "scikit-learn not installed"}

        if len(feature_matrix) < 4:
            return {"error": f"Not enough samples ({len(feature_matrix)}). Need >= 4."}

        k = num_clusters or self.num_clusters
        k = min(k, len(feature_matrix))  # Can't have more clusters than samples

        logger.info(f"Training K-Means with k={k} on {len(feature_matrix)} samples...")

        # Scale features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(feature_matrix)

        # Train K-Means
        self.model = KMeans(
            n_clusters=k,
            init="k-means++",
            n_init=10,
            max_iter=300,
            random_state=42,
        )
        labels = self.model.fit_predict(X_scaled)

        # Evaluate
        sil_score = -1
        if k > 1 and len(feature_matrix) > k:
            sil_score = silhouette_score(X_scaled, labels)

        # Save model
        os.makedirs(os.path.dirname(ML_MODEL_PATH), exist_ok=True)
        joblib.dump(self.model, ML_MODEL_PATH)
        joblib.dump(self.scaler, ML_SCALER_PATH)

        # Cluster stats
        cluster_counts = {}
        for label in labels:
            cluster_counts[int(label)] = cluster_counts.get(int(label), 0) + 1

        result = {
            "num_samples": len(feature_matrix),
            "num_clusters": k,
            "silhouette_score": round(sil_score, 4),
            "cluster_distribution": cluster_counts,
            "inertia": round(self.model.inertia_, 2),
            "model_path": ML_MODEL_PATH,
        }

        logger.info(f"Training complete:")
        logger.info(f"  Silhouette score: {sil_score:.4f}")
        logger.info(f"  Inertia: {self.model.inertia_:.2f}")
        logger.info(f"  Cluster distribution: {cluster_counts}")

        return result

    def predict(self, features: np.ndarray) -> Optional[dict]:
        """
        Predict cluster for a single feature vector.
        
        Returns:
            {
                "cluster_id": int,
                "cluster_label": str,
                "distance_to_center": float,
                "confidence": float
            }
        """
        if self.model is None or self.scaler is None:
            return None

        try:
            # Reshape if single sample
            if features.ndim == 1:
                features = features.reshape(1, -1)

            X_scaled = self.scaler.transform(features)
            cluster_id = int(self.model.predict(X_scaled)[0])

            # Distance to cluster center
            center = self.model.cluster_centers_[cluster_id]
            distance = float(np.linalg.norm(X_scaled[0] - center))

            # Confidence based on distance (closer = higher confidence)
            max_distance = max(
                float(np.linalg.norm(X_scaled[0] - c))
                for c in self.model.cluster_centers_
            )
            confidence = 1.0 - (distance / max(max_distance, 1e-6))
            confidence = max(0.0, min(1.0, confidence))

            label = CLUSTER_LABELS.get(cluster_id, f"cluster_{cluster_id}")

            return {
                "cluster_id": cluster_id,
                "cluster_label": label,
                "distance_to_center": round(distance, 4),
                "confidence": round(confidence, 4),
            }

        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return None

    def predict_batch(self, feature_matrix: np.ndarray) -> list:
        """Predict clusters for multiple samples."""
        if self.model is None or self.scaler is None:
            return []

        results = []
        for features in feature_matrix:
            result = self.predict(features)
            results.append(result)
        return results

    def get_pca_projection(self, feature_matrix: np.ndarray,
                           n_components: int = 2) -> Optional[np.ndarray]:
        """
        Project features to 2D/3D for visualization using PCA.
        
        Returns:
            np.ndarray of shape (n_samples, n_components)
        """
        if not HAS_SKLEARN or self.scaler is None:
            return None

        try:
            X_scaled = self.scaler.transform(feature_matrix)
            n_comp = min(n_components, X_scaled.shape[1], X_scaled.shape[0])
            pca = PCA(n_components=n_comp)
            return pca.fit_transform(X_scaled)
        except Exception as e:
            logger.error(f"PCA error: {e}")
            return None

    def find_optimal_k(self, feature_matrix: np.ndarray,
                       k_range: tuple = (2, 8)) -> dict:
        """
        Find optimal number of clusters using silhouette analysis.
        
        Returns:
            {"best_k": int, "scores": {k: silhouette_score}}
        """
        if not HAS_SKLEARN:
            return {"error": "scikit-learn not installed"}

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(feature_matrix)

        scores = {}
        max_k = min(k_range[1], len(feature_matrix) - 1)

        for k in range(k_range[0], max_k + 1):
            kmeans = KMeans(n_clusters=k, n_init=10, random_state=42)
            labels = kmeans.fit_predict(X_scaled)
            score = silhouette_score(X_scaled, labels)
            scores[k] = round(score, 4)

        best_k = max(scores, key=scores.get) if scores else k_range[0]

        return {
            "best_k": best_k,
            "scores": scores,
        }

    @property
    def is_trained(self) -> bool:
        """Check if a model is loaded and ready."""
        return self.model is not None and self.scaler is not None
