"""
LLMPot — Dashboard Components: Metrics
Reusable KPI metric card components.
"""

import streamlit as st


def render_metric_row(stats: dict):
    """Render the top KPI metrics row."""
    col1, col2, col3, col4, col5, col6 = st.columns(6)

    with col1:
        st.metric(
            label="🎯 Total Attacks",
            value=f"{stats.get('total_sessions', 0):,}",
            delta=f"+{stats.get('today_sessions', 0)} today",
        )
    with col2:
        st.metric(
            label="🔓 Auth Successes",
            value=f"{stats.get('auth_successes', 0):,}",
        )
    with col3:
        st.metric(
            label="🌍 Unique IPs",
            value=f"{stats.get('unique_attackers', 0):,}",
        )
    with col4:
        st.metric(
            label="⌨️ Commands",
            value=f"{stats.get('total_commands', 0):,}",
        )
    with col5:
        st.metric(
            label="⚠️ Dangerous Cmds",
            value=f"{stats.get('dangerous_commands', 0):,}",
        )
    with col6:
        st.metric(
            label="📅 Today",
            value=f"{stats.get('today_sessions', 0):,}",
        )


def render_threat_badge(level: str) -> str:
    """Return an HTML badge for a threat level."""
    colors = {
        "critical": "#ef4444",
        "high": "#f97316",
        "medium": "#f59e0b",
        "low": "#3b82f6",
        "safe": "#10b981",
        "unknown": "#64748b",
    }
    color = colors.get(level, "#64748b")
    return (
        f'<span style="background-color: {color}; color: white; '
        f'padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; '
        f'font-weight: 600; text-transform: uppercase;">'
        f'{level}</span>'
    )


def render_status_indicator(is_active: bool = True) -> str:
    """Return HTML for a live/offline status indicator."""
    if is_active:
        return (
            '<span style="display: inline-flex; align-items: center;">'
            '<span style="width: 8px; height: 8px; background: #10b981; '
            'border-radius: 50%; margin-right: 6px; '
            'animation: pulse 2s infinite;"></span>'
            '<span style="color: #10b981; font-weight: 600;">LIVE</span>'
            '</span>'
        )
    return (
        '<span style="display: inline-flex; align-items: center;">'
        '<span style="width: 8px; height: 8px; background: #ef4444; '
        'border-radius: 50%; margin-right: 6px;"></span>'
        '<span style="color: #ef4444; font-weight: 600;">OFFLINE</span>'
        '</span>'
    )
