"""
LLMPot Dashboard — ML Clusters
K-Means cluster visualization and analysis.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import streamlit as st
import numpy as np
import pandas as pd
from database.db_manager import DatabaseManager
from analysis.feature_extractor import FeatureExtractor
from analysis.ml_analyzer import MLAnalyzer
from dashboard.components.charts import (
    cluster_scatter_2d, cluster_distribution_chart
)
from dashboard.components.sidebar import render_sidebar
from config import CLUSTER_LABELS

st.set_page_config(page_title="LLMPot — ML Clusters", page_icon="🧠", layout="wide")

css_path = Path(__file__).parent.parent / "styles" / "theme.css"
if css_path.exists():
    with open(css_path) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

auto_refresh = render_sidebar()

st.markdown("""
<h1 style="font-family: 'JetBrains Mono', monospace; color: #e2e8f0;">
    🧠 ML Attack Clusters
</h1>
""", unsafe_allow_html=True)

db = DatabaseManager()
ml = MLAnalyzer()
fe = FeatureExtractor()

if not ml.is_trained:
    st.warning("⚠️ No trained model found. Run training first:")
    st.code("python training/generate_dataset.py\npython training/train.py", language="bash")
    st.stop()

# ─── Cluster Overview ────────────────────────────────────────────────────────
st.markdown("### 📊 Cluster Distribution")

cluster_data = db.get_cluster_distribution()

col1, col2 = st.columns([1, 1])

with col1:
    fig = cluster_distribution_chart(cluster_data)
    st.plotly_chart(fig, use_container_width=True)

with col2:
    if cluster_data:
        for cluster in cluster_data:
            label = cluster.get("cluster_label", f"Cluster {cluster.get('cluster_id')}")
            count = cluster.get("count", 0)
            avg_dur = cluster.get("avg_duration", 0) or 0
            avg_cmds = cluster.get("avg_commands", 0) or 0
            avg_threat = cluster.get("avg_threat_score", 0) or 0

            # Color by cluster
            colors = ["#06b6d4", "#3b82f6", "#8b5cf6", "#ec4899",
                       "#f59e0b", "#10b981", "#ef4444"]
            cid = cluster.get("cluster_id", 0) or 0
            color = colors[cid % len(colors)]

            st.markdown(f"""
            <div style="background: #1a1f2e; border-left: 4px solid {color};
                        border-radius: 8px; padding: 14px 18px; margin-bottom: 10px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span style="color: {color}; font-weight: 700; 
                                     font-family: 'JetBrains Mono', monospace;
                                     text-transform: uppercase; font-size: 0.9rem;">
                            {label}
                        </span>
                        <span style="color: #64748b; margin-left: 12px;">
                            {count} sessions
                        </span>
                    </div>
                    <div style="text-align: right; font-size: 0.85rem;">
                        <span style="color: #94a3b8;">
                            ⏱ {avg_dur:.0f}s avg
                        </span>
                        <span style="color: #94a3b8; margin-left: 12px;">
                            ⌨ {avg_cmds:.1f} cmds
                        </span>
                        <span style="color: #94a3b8; margin-left: 12px;">
                            ⚠ {avg_threat:.0f} threat
                        </span>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

# ─── PCA Scatter Plot ────────────────────────────────────────────────────────
st.markdown("### 🔬 Cluster Visualization (PCA)")

sessions = db.get_sessions_for_training()
if sessions:
    feature_matrix, session_ids = fe.extract_batch(sessions)

    if len(feature_matrix) > 0:
        predictions = ml.predict_batch(feature_matrix)
        labels = [p["cluster_id"] if p else -1 for p in predictions]

        pca_data = ml.get_pca_projection(feature_matrix, n_components=2)

        if pca_data is not None:
            fig = cluster_scatter_2d(pca_data, labels, CLUSTER_LABELS)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Could not generate PCA projection.")

        # Feature importance
        st.markdown("### 📐 Feature Summary")
        feature_df = pd.DataFrame(
            feature_matrix,
            columns=FeatureExtractor.FEATURE_NAMES[:feature_matrix.shape[1]]
        )
        st.dataframe(
            feature_df.describe().round(2),
            use_container_width=True,
        )
    else:
        st.info("Not enough feature data for visualization.")
else:
    st.info("No session data available for clustering.")

# ─── Retrain Button ──────────────────────────────────────────────────────────
st.markdown("---")
st.markdown("### 🔄 Model Management")

col1, col2 = st.columns(2)
with col1:
    if st.button("🧠 Retrain Model", key="retrain"):
        with st.spinner("Training K-Means model..."):
            sessions = db.get_sessions_for_training()
            feature_matrix, _ = fe.extract_batch(sessions)
            if len(feature_matrix) > 0:
                result = ml.train(feature_matrix)
                if "error" not in result:
                    st.success(f"✓ Model trained! Silhouette: {result['silhouette_score']:.4f}")
                    st.rerun()
                else:
                    st.error(f"Training failed: {result['error']}")
            else:
                st.warning("Not enough data to train.")

with col2:
    if st.button("🎲 Generate Synthetic Data", key="generate"):
        with st.spinner("Generating 500 synthetic sessions..."):
            from training.generate_dataset import generate_synthetic_dataset
            count = generate_synthetic_dataset(500)
            st.success(f"✓ Generated {count} sessions")
            st.rerun()
