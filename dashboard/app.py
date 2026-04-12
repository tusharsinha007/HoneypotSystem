"""
LLMPot — SOC Dashboard
Main entry point for the Streamlit monitoring dashboard.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st
from database.db_manager import DatabaseManager
from dashboard.components.metrics import render_metric_row
from dashboard.components.charts import (
    hourly_trend_chart, threat_distribution_pie
)
from dashboard.components.sidebar import render_sidebar

# ─── Page Config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="LLMPot — SOC Dashboard",
    page_icon="🍯",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Load custom CSS ─────────────────────────────────────────────────────────
css_path = Path(__file__).parent / "styles" / "theme.css"
if css_path.exists():
    with open(css_path) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)


def main():
    # Sidebar
    auto_refresh = render_sidebar()

    # Header
    st.markdown("""
    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 1rem;">
        <h1 style="margin: 0; font-family: 'JetBrains Mono', monospace; 
                    color: #e2e8f0; font-size: 2rem;">
            🍯 LLMPot Command Center
        </h1>
        <span style="background: #10b981; color: white; padding: 4px 12px; 
                     border-radius: 20px; font-size: 0.75rem; font-weight: 600;">
            LIVE
        </span>
    </div>
    """, unsafe_allow_html=True)

    # Initialize DB
    db = DatabaseManager()
    stats = db.get_stats_summary()

    # KPI Metrics
    render_metric_row(stats)

    st.markdown("<br>", unsafe_allow_html=True)

    # Main content — two columns
    col1, col2 = st.columns([2, 1])

    with col1:
        # Attack trend
        trend_data = db.get_hourly_trend(days=7)
        fig = hourly_trend_chart(trend_data, "📈 Attack Trend (7 Days)")
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        # Threat distribution
        sessions = db.get_sessions(limit=500)
        fig = threat_distribution_pie(sessions)
        st.plotly_chart(fig, use_container_width=True)

    # Recent attacks table
    st.markdown("### 📋 Recent Activity")
    recent = db.get_sessions(limit=15)
    if recent:
        import pandas as pd
        df = pd.DataFrame(recent)
        display_cols = [
            "start_time", "attacker_ip", "country", "city",
            "username", "password", "command_count", "threat_level",
        ]
        # Only keep columns that exist
        display_cols = [c for c in display_cols if c in df.columns]
        st.dataframe(
            df[display_cols],
            use_container_width=True,
            height=400,
            column_config={
                "start_time": st.column_config.DatetimeColumn("Time", format="MMM DD, HH:mm:ss"),
                "attacker_ip": "Attacker IP",
                "country": "Country",
                "city": "City",
                "username": "Username",
                "password": "Password",
                "command_count": st.column_config.NumberColumn("Commands", format="%d"),
                "threat_level": "Threat",
            },
        )
    else:
        st.info("🔍 No attack data yet. Start the honeypot and wait for connections, "
                "or run the attack simulator.")

    # Auto-refresh
    if auto_refresh:
        import time
        interval = st.session_state.get("refresh_interval", 10)
        time.sleep(interval)
        st.rerun()


if __name__ == "__main__":
    main()
