"""
LLMPot Dashboard — Live Monitor
Real-time scrolling attack feed with live KPIs.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import streamlit as st
import pandas as pd
from datetime import datetime
from database.db_manager import DatabaseManager
from dashboard.components.metrics import render_metric_row, render_threat_badge
from dashboard.components.sidebar import render_sidebar

st.set_page_config(page_title="LLMPot — Live Monitor", page_icon="📡", layout="wide")

# Load theme
css_path = Path(__file__).parent.parent / "styles" / "theme.css"
if css_path.exists():
    with open(css_path) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

auto_refresh = render_sidebar()

st.markdown("""
<h1 style="font-family: 'JetBrains Mono', monospace; color: #e2e8f0;">
    📡 Live Attack Monitor
</h1>
""", unsafe_allow_html=True)

db = DatabaseManager()
stats = db.get_stats_summary()
render_metric_row(stats)

st.markdown("<br>", unsafe_allow_html=True)

# ─── Live Feed ────────────────────────────────────────────────────────────────
col1, col2 = st.columns([3, 1])

with col1:
    st.markdown("### 🔴 Live Attack Feed")

    sessions = db.get_sessions(limit=50)
    if sessions:
        for session in sessions:
            threat_level = session.get("threat_level", "unknown")
            color_map = {
                "critical": "#ef4444", "high": "#f97316",
                "medium": "#f59e0b", "low": "#3b82f6",
                "safe": "#10b981", "unknown": "#64748b",
            }
            border_color = color_map.get(threat_level, "#64748b")

            cmd_count = session.get("command_count", 0)
            country = session.get("country", "—")
            city = session.get("city", "—")

            st.markdown(f"""
            <div style="background: #1a1f2e; border-left: 4px solid {border_color};
                        border-radius: 8px; padding: 12px 16px; margin-bottom: 8px;
                        display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <span style="color: #06b6d4; font-family: 'JetBrains Mono', monospace; 
                                 font-weight: 600;">
                        {session.get('attacker_ip', '?')}
                    </span>
                    <span style="color: #64748b; margin: 0 8px;">→</span>
                    <span style="color: #e2e8f0;">
                        {session.get('username', '?')}:{session.get('password', '?')}
                    </span>
                    <span style="color: #64748b; margin-left: 12px; font-size: 0.85rem;">
                        🌍 {country}, {city}
                    </span>
                </div>
                <div style="display: flex; align-items: center; gap: 12px;">
                    <span style="color: #94a3b8; font-size: 0.8rem;">
                        ⌨️ {cmd_count} cmds
                    </span>
                    {render_threat_badge(threat_level)}
                    <span style="color: #64748b; font-size: 0.75rem;">
                        {session.get('start_time', '')[:19]}
                    </span>
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("Waiting for attack data...")

with col2:
    st.markdown("### 🏆 Top Attackers")
    top_attackers = db.get_top_attackers(limit=8)
    if top_attackers:
        for i, attacker in enumerate(top_attackers, 1):
            st.markdown(f"""
            <div style="background: #1a1f2e; border-radius: 8px; padding: 10px 14px;
                        margin-bottom: 6px; display: flex; justify-content: space-between;">
                <span style="color: #06b6d4; font-family: 'JetBrains Mono', monospace;
                             font-size: 0.85rem;">
                    #{i} {attacker.get('attacker_ip', '?')}
                </span>
                <span style="color: #f59e0b; font-weight: 600;">
                    {attacker.get('attack_count', 0)}
                </span>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No attacker data yet")

    st.markdown("### 🔐 Top Credentials")
    top_creds = db.get_top_credentials(limit=8)
    if top_creds:
        for cred in top_creds:
            st.markdown(f"""
            <div style="background: #1a1f2e; border-radius: 8px; padding: 8px 14px;
                        margin-bottom: 6px; font-family: 'JetBrains Mono', monospace;
                        font-size: 0.8rem;">
                <span style="color: #ef4444;">{cred.get('username', '?')}</span>
                <span style="color: #64748b;"> / </span>
                <span style="color: #f59e0b;">{cred.get('password', '?')}</span>
                <span style="color: #64748b; float: right;">
                    ×{cred.get('attempt_count', 0)}
                </span>
            </div>
            """, unsafe_allow_html=True)

# Auto-refresh
if auto_refresh:
    import time
    interval = st.session_state.get("refresh_interval", 10)
    time.sleep(interval)
    st.rerun()
