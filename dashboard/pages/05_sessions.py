"""
LLMPot Dashboard — Session Explorer
Detailed session inspection and search.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import streamlit as st
import pandas as pd
from database.db_manager import DatabaseManager
from dashboard.components.metrics import render_threat_badge
from dashboard.components.sidebar import render_sidebar

st.set_page_config(page_title="LLMPot — Sessions", page_icon="🔍", layout="wide")

css_path = Path(__file__).parent.parent / "styles" / "theme.css"
if css_path.exists():
    with open(css_path) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

render_sidebar()

st.markdown("""
<h1 style="font-family: 'JetBrains Mono', monospace; color: #e2e8f0;">
    🔍 Session Explorer
</h1>
""", unsafe_allow_html=True)

db = DatabaseManager()

# ─── Filters ─────────────────────────────────────────────────────────────────
col1, col2, col3, col4 = st.columns(4)

with col1:
    threat_filter = st.selectbox(
        "Threat Level",
        ["All", "critical", "high", "medium", "low", "safe", "unknown"],
        key="threat_filter",
    )

with col2:
    ip_search = st.text_input("Search IP", placeholder="e.g. 192.168.1.1",
                              key="ip_search")

with col3:
    limit = st.select_slider("Results", options=[25, 50, 100, 200, 500],
                             value=50, key="result_limit")

with col4:
    sort_by = st.selectbox("Sort by", ["Newest", "Oldest", "Most Commands"],
                           key="sort_by")

# ─── Query Sessions ──────────────────────────────────────────────────────────
threat_level = None if threat_filter == "All" else threat_filter
sessions = db.get_sessions(limit=limit, threat_level=threat_level)

# Apply IP filter
if ip_search:
    sessions = [s for s in sessions if ip_search in s.get("attacker_ip", "")]

# Apply sorting
if sort_by == "Oldest":
    sessions = sorted(sessions, key=lambda x: x.get("start_time", ""))
elif sort_by == "Most Commands":
    sessions = sorted(sessions, key=lambda x: x.get("command_count", 0), reverse=True)

# ─── Session Table ───────────────────────────────────────────────────────────
st.markdown(f"### 📋 Sessions ({len(sessions)} results)")

if sessions:
    df = pd.DataFrame(sessions)
    display_cols = [
        "session_id", "start_time", "attacker_ip", "country", "city",
        "username", "password", "command_count", "duration_seconds",
        "threat_level", "cluster_label",
    ]
    display_cols = [c for c in display_cols if c in df.columns]

    # Truncate session_id for display
    if "session_id" in df.columns:
        df["session_id"] = df["session_id"].apply(lambda x: x[:8] + "..." if x else "")

    st.dataframe(
        df[display_cols],
        use_container_width=True,
        height=400,
        column_config={
            "session_id": "Session",
            "start_time": st.column_config.DatetimeColumn("Time", format="MMM DD HH:mm"),
            "attacker_ip": "IP Address",
            "country": "Country",
            "city": "City",
            "username": "User",
            "password": "Password",
            "command_count": st.column_config.NumberColumn("Cmds"),
            "duration_seconds": st.column_config.NumberColumn("Duration (s)", format="%.1f"),
            "threat_level": "Threat",
            "cluster_label": "Cluster",
        },
    )

    # ─── Session Detail View ─────────────────────────────────────────────────
    st.markdown("### 🔎 Session Detail")

    # Get full session IDs for selection
    full_sessions = db.get_sessions(limit=limit, threat_level=threat_level)
    if ip_search:
        full_sessions = [s for s in full_sessions
                         if ip_search in s.get("attacker_ip", "")]

    session_options = {
        f"{s['session_id'][:8]}… | {s.get('attacker_ip', '?')} | "
        f"{s.get('username', '?')}": s["session_id"]
        for s in full_sessions
    }

    if session_options:
        selected_label = st.selectbox(
            "Select session to inspect",
            options=list(session_options.keys()),
            key="session_select",
        )
        selected_id = session_options[selected_label]

        # Load session details
        session = db.get_session(selected_id)
        commands = db.get_session_commands(selected_id)

        if session:
            col1, col2 = st.columns([1, 1])

            with col1:
                st.markdown("#### 📋 Session Info")
                info_items = [
                    ("Session ID", session.get("session_id", "—")),
                    ("Attacker IP", session.get("attacker_ip", "—")),
                    ("Location", f"{session.get('city', '—')}, "
                                 f"{session.get('country', '—')}"),
                    ("Username", session.get("username", "—")),
                    ("Password", session.get("password", "—")),
                    ("Start Time", session.get("start_time", "—")),
                    ("End Time", session.get("end_time", "—")),
                    ("Duration", f"{session.get('duration_seconds', 0):.1f}s"),
                    ("Commands", str(session.get("command_count", 0))),
                    ("Threat Level", session.get("threat_level", "—")),
                    ("Cluster", session.get("cluster_label", "—")),
                    ("ISP", session.get("isp", "—")),
                ]

                for label, value in info_items:
                    st.markdown(f"""
                    <div style="display: flex; padding: 6px 0; 
                                border-bottom: 1px solid #2a3040;">
                        <span style="color: #64748b; width: 120px; 
                                     font-size: 0.85rem;">{label}</span>
                        <span style="color: #e2e8f0; font-family: 'JetBrains Mono', monospace;
                                     font-size: 0.85rem;">{value}</span>
                    </div>
                    """, unsafe_allow_html=True)

            with col2:
                st.markdown("#### ⌨️ Command Timeline")
                if commands:
                    for cmd in commands:
                        is_danger = cmd.get("is_dangerous", False)
                        color = "#ef4444" if is_danger else "#e2e8f0"
                        icon = "⚠️" if is_danger else "›"
                        cat = cmd.get("threat_category", "")
                        cat_str = f" [{cat}]" if cat else ""

                        st.markdown(f"""
                        <div style="font-family: 'JetBrains Mono', monospace;
                                    font-size: 0.85rem; padding: 4px 0;
                                    border-bottom: 1px solid rgba(42,48,64,0.3);">
                            <span style="color: #64748b; font-size: 0.75rem;">
                                {cmd.get('timestamp', '')[:19]}
                            </span>
                            <br>
                            <span style="color: #06b6d4;">{icon}</span>
                            <span style="color: {color};">{cmd.get('command', '')}</span>
                            <span style="color: #f59e0b; font-size: 0.75rem;">
                                {cat_str}
                            </span>
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.info("No commands recorded for this session.")

    # ─── Export ───────────────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("### 📥 Export Data")

    col1, col2 = st.columns(2)
    with col1:
        csv_data = pd.DataFrame(full_sessions).to_csv(index=False)
        st.download_button(
            "📥 Download Sessions (CSV)",
            data=csv_data,
            file_name="llmpot_sessions.csv",
            mime="text/csv",
        )

    with col2:
        import json
        json_data = json.dumps(full_sessions, indent=2, default=str)
        st.download_button(
            "📥 Download Sessions (JSON)",
            data=json_data,
            file_name="llmpot_sessions.json",
            mime="application/json",
        )
else:
    st.info("No sessions found matching your filters.")
