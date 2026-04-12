"""
LLMPot Dashboard — Analytics
Charts, trends, and statistical analysis.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import streamlit as st
import pandas as pd
from database.db_manager import DatabaseManager
from dashboard.components.charts import (
    hourly_trend_chart, credential_chart, command_frequency_chart,
    threat_distribution_pie, top_items_bar_chart
)
from dashboard.components.sidebar import render_sidebar

st.set_page_config(page_title="LLMPot — Analytics", page_icon="📈", layout="wide")

css_path = Path(__file__).parent.parent / "styles" / "theme.css"
if css_path.exists():
    with open(css_path) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

auto_refresh = render_sidebar()

st.markdown("""
<h1 style="font-family: 'JetBrains Mono', monospace; color: #e2e8f0;">
    📈 Attack Analytics
</h1>
""", unsafe_allow_html=True)

db = DatabaseManager()

# ─── Trend Analysis ──────────────────────────────────────────────────────────
st.markdown("### 📊 Attack Trends")

col1, col2 = st.columns(2)

with col1:
    # 7-day trend
    trend_7 = db.get_hourly_trend(days=7)
    fig = hourly_trend_chart(trend_7, "📈 7-Day Attack Trend")
    st.plotly_chart(fig, use_container_width=True)

with col2:
    # Threat distribution
    sessions = db.get_sessions(limit=1000)
    fig = threat_distribution_pie(sessions)
    st.plotly_chart(fig, use_container_width=True)

# ─── Credential Analysis ────────────────────────────────────────────────────
st.markdown("### 🔐 Credential Analysis")

col1, col2 = st.columns(2)

with col1:
    creds = db.get_top_credentials(limit=15)
    fig = credential_chart(creds)
    st.plotly_chart(fig, use_container_width=True)

with col2:
    # Username breakdown
    if creds:
        usernames = {}
        for c in creds:
            u = c.get("username", "?")
            usernames[u] = usernames.get(u, 0) + c.get("attempt_count", 0)

        username_data = [
            {"username": k, "count": v}
            for k, v in sorted(usernames.items(), key=lambda x: -x[1])[:10]
        ]
        fig = top_items_bar_chart(
            username_data, "username", "count",
            "👤 Top Usernames", "#8b5cf6"
        )
        st.plotly_chart(fig, use_container_width=True)

# ─── Command Analysis ────────────────────────────────────────────────────────
st.markdown("### ⌨️ Command Analysis")

cmd_freq = db.get_command_frequency(limit=20)
fig = command_frequency_chart(cmd_freq)
st.plotly_chart(fig, use_container_width=True)

# ─── Top Attackers ────────────────────────────────────────────────────────────
st.markdown("### 🎯 Top Attacker IPs")

top_attackers = db.get_top_attackers(limit=15)
if top_attackers:
    attacker_data = [
        {"ip": a["attacker_ip"], "attacks": a["attack_count"]}
        for a in top_attackers
    ]
    fig = top_items_bar_chart(
        attacker_data, "ip", "attacks",
        "🎯 Most Active Attackers", "#ef4444"
    )
    st.plotly_chart(fig, use_container_width=True)

# ─── Session Duration Distribution ──────────────────────────────────────────
st.markdown("### ⏱️ Session Duration Distribution")

if sessions:
    durations = [s.get("duration_seconds", 0) for s in sessions
                 if s.get("duration_seconds") is not None and s.get("duration_seconds", 0) > 0]
    if durations:
        import plotly.graph_objects as go
        fig = go.Figure(go.Histogram(
            x=durations,
            nbinsx=30,
            marker=dict(color="#06b6d4", opacity=0.7),
        ))
        fig.update_layout(
            xaxis_title="Duration (seconds)",
            yaxis_title="Session Count",
            height=350,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e2e8f0"),
            xaxis=dict(gridcolor="rgba(42,48,64,0.5)"),
            yaxis=dict(gridcolor="rgba(42,48,64,0.5)"),
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No session duration data available yet.")

if auto_refresh:
    import time
    interval = st.session_state.get("refresh_interval", 10)
    time.sleep(interval)
    st.rerun()
