"""
LLMPot — Dashboard Components: Sidebar
Navigation sidebar configuration.
"""

import streamlit as st


def render_sidebar():
    """Render the dashboard sidebar with branding and controls."""
    with st.sidebar:
        st.markdown("""
        <div style="text-align: center; padding: 1rem 0;">
            <h1 style="font-family: 'JetBrains Mono', monospace; 
                        color: #06b6d4; margin: 0; font-size: 1.8rem;">
                🍯 LLMPot
            </h1>
            <p style="color: #64748b; font-size: 0.85rem; margin-top: 0.25rem;">
                AI-Driven SSH Honeypot
            </p>
        </div>
        <hr style="border-color: #2a3040; margin: 0.5rem 0 1rem 0;">
        """, unsafe_allow_html=True)

        # Status
        st.markdown("""
        <div style="background: #1a1f2e; border: 1px solid #2a3040; 
                    border-radius: 8px; padding: 0.75rem; margin-bottom: 1rem;">
            <div style="display: flex; align-items: center; gap: 8px;">
                <span style="width: 8px; height: 8px; background: #10b981; 
                            border-radius: 50; display: inline-block;"></span>
                <span style="color: #10b981; font-weight: 600; font-size: 0.85rem;">
                    SYSTEM ACTIVE
                </span>
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("### ⚙️ Settings")

        # Auto-refresh toggle
        auto_refresh = st.toggle("Auto-refresh", value=True, key="auto_refresh")

        if auto_refresh:
            refresh_interval = st.select_slider(
                "Refresh interval",
                options=[5, 10, 15, 30, 60],
                value=10,
                format_func=lambda x: f"{x}s",
                key="refresh_interval",
            )
        else:
            if st.button("🔄 Refresh Now", key="manual_refresh"):
                st.rerun()

        st.markdown("---")

        # Quick stats
        st.markdown("### 📊 Quick Links")
        st.page_link("pages/01_live_monitor.py", label="📡 Live Monitor", icon="📡")
        st.page_link("pages/02_attack_map.py", label="🗺️ Attack Map", icon="🗺️")
        st.page_link("pages/03_analytics.py", label="📈 Analytics", icon="📈")
        st.page_link("pages/04_clusters.py", label="🧠 ML Clusters", icon="🧠")
        st.page_link("pages/05_sessions.py", label="🔍 Sessions", icon="🔍")

        st.markdown("---")

        # Info
        st.markdown("""
        <div style="color: #64748b; font-size: 0.75rem; text-align: center;">
            <p>LLMPot v1.0</p>
            <p>⚠️ For research & education only</p>
        </div>
        """, unsafe_allow_html=True)

        return auto_refresh
