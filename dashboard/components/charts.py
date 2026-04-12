"""
LLMPot — Dashboard Components: Charts
Reusable Plotly chart components with dark theme.
"""

import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import pandas as pd


# ─── Common Layout ────────────────────────────────────────────────────────────

DARK_THEME = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#e2e8f0", family="Inter, sans-serif"),
    margin=dict(l=40, r=20, t=40, b=40),
    xaxis=dict(
        gridcolor="rgba(42,48,64,0.5)",
        zerolinecolor="rgba(42,48,64,0.5)",
    ),
    yaxis=dict(
        gridcolor="rgba(42,48,64,0.5)",
        zerolinecolor="rgba(42,48,64,0.5)",
    ),
)

COLORS = [
    "#06b6d4", "#3b82f6", "#8b5cf6", "#ec4899",
    "#f59e0b", "#10b981", "#ef4444", "#f97316",
]


def apply_dark_theme(fig):
    """Apply dark theme to a Plotly figure."""
    fig.update_layout(**DARK_THEME)
    return fig


# ─── Chart Functions ──────────────────────────────────────────────────────────

def hourly_trend_chart(data: list, title: str = "Attack Trend") -> go.Figure:
    """Create an area chart of hourly attack counts."""
    if not data:
        return _empty_chart("No trend data available")

    df = pd.DataFrame(data)
    df["hour"] = pd.to_datetime(df["hour"])

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df["hour"], y=df["count"],
        mode="lines+markers",
        fill="tozeroy",
        line=dict(color="#06b6d4", width=2),
        fillcolor="rgba(6, 182, 212, 0.15)",
        marker=dict(size=4, color="#06b6d4"),
        name="Attacks",
    ))

    fig.update_layout(
        title=dict(text=title, font=dict(size=16)),
        xaxis_title="Time",
        yaxis_title="Attack Count",
        height=350,
        hovermode="x unified",
    )
    return apply_dark_theme(fig)


def top_items_bar_chart(data: list, x_key: str, y_key: str,
                        title: str = "", color: str = "#3b82f6",
                        horizontal: bool = True) -> go.Figure:
    """Create a horizontal bar chart for top items."""
    if not data:
        return _empty_chart(f"No data for {title}")

    df = pd.DataFrame(data)

    if horizontal:
        fig = go.Figure(go.Bar(
            x=df[y_key],
            y=df[x_key],
            orientation="h",
            marker=dict(
                color=df[y_key],
                colorscale=[[0, "#1a1f2e"], [1, color]],
            ),
            text=df[y_key],
            textposition="auto",
        ))
        fig.update_layout(yaxis=dict(autorange="reversed"))
    else:
        fig = go.Figure(go.Bar(
            x=df[x_key],
            y=df[y_key],
            marker=dict(color=color, opacity=0.85),
            text=df[y_key],
            textposition="auto",
        ))

    fig.update_layout(
        title=dict(text=title, font=dict(size=16)),
        height=400,
        showlegend=False,
    )
    return apply_dark_theme(fig)


def credential_chart(data: list) -> go.Figure:
    """Create a chart showing top username/password combinations."""
    if not data:
        return _empty_chart("No credential data")

    df = pd.DataFrame(data)
    df["credential"] = df["username"] + " / " + df["password"]

    fig = go.Figure(go.Bar(
        x=df["attempt_count"],
        y=df["credential"],
        orientation="h",
        marker=dict(
            color=df["attempt_count"],
            colorscale=[[0, "#1a1f2e"], [1, "#ef4444"]],
        ),
        text=df["attempt_count"],
        textposition="auto",
    ))

    fig.update_layout(
        title=dict(text="🔐 Top Credentials Used", font=dict(size=16)),
        xaxis_title="Attempts",
        yaxis=dict(autorange="reversed"),
        height=400,
    )
    return apply_dark_theme(fig)


def command_frequency_chart(data: list) -> go.Figure:
    """Create a bar chart of command frequency."""
    if not data:
        return _empty_chart("No command data")

    df = pd.DataFrame(data)

    colors = [
        "#ef4444" if row.get("dangerous_count", 0) > 0 else "#3b82f6"
        for _, row in df.iterrows()
    ]

    fig = go.Figure(go.Bar(
        x=df["command"],
        y=df["count"],
        marker=dict(color=colors, opacity=0.85),
        text=df["count"],
        textposition="auto",
    ))

    fig.update_layout(
        title=dict(text="⌨️ Command Frequency", font=dict(size=16)),
        xaxis_title="Command",
        yaxis_title="Count",
        height=400,
        xaxis=dict(tickangle=-45),
    )
    return apply_dark_theme(fig)


def threat_distribution_pie(sessions: list) -> go.Figure:
    """Create a donut chart of threat level distribution."""
    if not sessions:
        return _empty_chart("No threat data")

    levels = {}
    for s in sessions:
        level = s.get("threat_level", "unknown")
        levels[level] = levels.get(level, 0) + 1

    level_colors = {
        "critical": "#ef4444",
        "high": "#f97316",
        "medium": "#f59e0b",
        "low": "#3b82f6",
        "safe": "#10b981",
        "unknown": "#64748b",
    }

    labels = list(levels.keys())
    values = list(levels.values())
    colors_list = [level_colors.get(l, "#64748b") for l in labels]

    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        hole=0.55,
        marker=dict(colors=colors_list),
        textinfo="label+percent",
        textfont=dict(size=12),
    ))

    fig.update_layout(
        title=dict(text="🛡️ Threat Distribution", font=dict(size=16)),
        height=350,
        showlegend=True,
        legend=dict(font=dict(size=11)),
    )
    return apply_dark_theme(fig)


def cluster_scatter_2d(pca_data, labels, cluster_labels_map: dict = None) -> go.Figure:
    """Create a 2D scatter plot of clusters."""
    if pca_data is None or len(pca_data) == 0:
        return _empty_chart("No cluster data — train the model first")

    df = pd.DataFrame({
        "PC1": pca_data[:, 0],
        "PC2": pca_data[:, 1] if pca_data.shape[1] > 1 else 0,
        "Cluster": labels,
    })

    if cluster_labels_map:
        df["Label"] = [cluster_labels_map.get(c, f"Cluster {c}") for c in labels]
    else:
        df["Label"] = [f"Cluster {c}" for c in labels]

    fig = px.scatter(
        df, x="PC1", y="PC2", color="Label",
        color_discrete_sequence=COLORS,
        title="🧠 Attack Behavior Clusters (PCA Projection)",
    )

    fig.update_traces(marker=dict(size=8, opacity=0.7))
    fig.update_layout(height=500)
    return apply_dark_theme(fig)


def cluster_distribution_chart(data: list) -> go.Figure:
    """Create a bar chart showing cluster distribution."""
    if not data:
        return _empty_chart("No cluster data")

    df = pd.DataFrame(data)
    labels = df.get("cluster_label", df.get("cluster_id", range(len(df))))

    fig = go.Figure(go.Bar(
        x=[str(l) for l in labels],
        y=df["count"],
        marker=dict(color=COLORS[:len(df)], opacity=0.85),
        text=df["count"],
        textposition="auto",
    ))

    fig.update_layout(
        title=dict(text="📊 Cluster Distribution", font=dict(size=16)),
        xaxis_title="Cluster",
        yaxis_title="Sessions",
        height=350,
    )
    return apply_dark_theme(fig)


def _empty_chart(message: str) -> go.Figure:
    """Create an empty chart with a message."""
    fig = go.Figure()
    fig.add_annotation(
        text=message,
        xref="paper", yref="paper",
        x=0.5, y=0.5,
        showarrow=False,
        font=dict(size=16, color="#64748b"),
    )
    fig.update_layout(
        height=300,
        xaxis=dict(visible=False),
        yaxis=dict(visible=False),
    )
    return apply_dark_theme(fig)
