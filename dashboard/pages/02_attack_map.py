"""
LLMPot Dashboard — Attack Map
GeoIP world map visualization with PyDeck.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import streamlit as st
import pandas as pd
import pydeck as pdk
from database.db_manager import DatabaseManager
from dashboard.components.sidebar import render_sidebar

st.set_page_config(page_title="LLMPot — Attack Map", page_icon="🗺️", layout="wide")

css_path = Path(__file__).parent.parent / "styles" / "theme.css"
if css_path.exists():
    with open(css_path) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

auto_refresh = render_sidebar()

st.markdown("""
<h1 style="font-family: 'JetBrains Mono', monospace; color: #e2e8f0;">
    🗺️ Global Attack Map
</h1>
""", unsafe_allow_html=True)

db = DatabaseManager()
locations = db.get_attack_locations()

if locations:
    df = pd.DataFrame(locations)
    df = df[df["latitude"].notna() & df["longitude"].notna()]
    df = df[(df["latitude"] != 0) | (df["longitude"] != 0)]

    if not df.empty:
        # Map threat levels to colors
        def get_color(threat_level):
            colors = {
                "critical": [239, 68, 68, 200],
                "high": [249, 115, 22, 200],
                "medium": [245, 158, 11, 180],
                "low": [59, 130, 246, 160],
                "safe": [16, 185, 129, 140],
                "unknown": [100, 116, 139, 120],
            }
            return colors.get(threat_level, [100, 116, 139, 120])

        df["color"] = df["threat_level"].apply(get_color)
        df["radius"] = df["attack_count"].apply(
            lambda x: max(30000, min(x * 15000, 500000))
        )

        # Scatterplot layer
        scatter_layer = pdk.Layer(
            "ScatterplotLayer",
            data=df,
            get_position=["longitude", "latitude"],
            get_color="color",
            get_radius="radius",
            pickable=True,
            opacity=0.6,
            filled=True,
            auto_highlight=True,
        )

        # Honeypot location (customize as needed)
        honeypot_lat, honeypot_lon = 20.0, 0.0  # Center of map

        # Arc layer — attack lines from attacker to center
        arc_data = df[["latitude", "longitude", "attack_count", "color"]].copy()
        arc_data["target_lat"] = honeypot_lat
        arc_data["target_lon"] = honeypot_lon

        arc_layer = pdk.Layer(
            "ArcLayer",
            data=arc_data,
            get_source_position=["longitude", "latitude"],
            get_target_position=["target_lon", "target_lat"],
            get_source_color="color",
            get_target_color=[6, 182, 212, 200],
            get_width=2,
            pickable=True,
        )

        # View state
        view_state = pdk.ViewState(
            latitude=20,
            longitude=0,
            zoom=1.5,
            pitch=30,
        )

        # Render map
        deck = pdk.Deck(
            layers=[scatter_layer, arc_layer],
            initial_view_state=view_state,
            tooltip={
                "html": (
                    "<b>IP:</b> {attacker_ip}<br>"
                    "<b>Location:</b> {city}, {country}<br>"
                    "<b>Attacks:</b> {attack_count}<br>"
                    "<b>Threat:</b> {threat_level}"
                ),
                "style": {
                    "backgroundColor": "#1a1f2e",
                    "color": "#e2e8f0",
                    "border": "1px solid #2a3040",
                    "borderRadius": "8px",
                    "padding": "8px",
                },
            },
            map_style="mapbox://styles/mapbox/dark-v11",
        )

        st.pydeck_chart(deck, use_container_width=True, height=600)

        # Stats below map
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("🌍 Countries", df["country"].nunique())
        with col2:
            st.metric("📍 Locations", len(df))
        with col3:
            st.metric("🎯 Total Attacks", int(df["attack_count"].sum()))
        with col4:
            top_country = df.groupby("country")["attack_count"].sum()
            if not top_country.empty:
                st.metric("🏆 Top Country", top_country.idxmax())

        # Country breakdown
        st.markdown("### 🌐 Attacks by Country")
        country_stats = (
            df.groupby("country")["attack_count"]
            .sum()
            .sort_values(ascending=False)
            .head(15)
            .reset_index()
        )
        country_stats.columns = ["Country", "Attacks"]

        import plotly.graph_objects as go
        fig = go.Figure(go.Bar(
            x=country_stats["Attacks"],
            y=country_stats["Country"],
            orientation="h",
            marker=dict(
                color=country_stats["Attacks"],
                colorscale=[[0, "#1a1f2e"], [1, "#06b6d4"]],
            ),
            text=country_stats["Attacks"],
            textposition="auto",
        ))
        fig.update_layout(
            yaxis=dict(autorange="reversed"),
            height=400,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e2e8f0"),
            margin=dict(l=40, r=20, t=20, b=40),
        )
        st.plotly_chart(fig, use_container_width=True)

    else:
        st.info("No geolocation data available. Waiting for attacks with valid IPs...")
else:
    st.info("🌍 No attack data yet. Start the honeypot to begin collecting data.")

if auto_refresh:
    import time
    interval = st.session_state.get("refresh_interval", 10)
    time.sleep(interval)
    st.rerun()
