"""
Dash dashboard for CVE Intelligence System.
"""
import dash
from dash import dcc, html, Input, Output, State, callback
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import httpx
import asyncio
from datetime import datetime, timedelta

# Initialize Dash app
app = dash.Dash(__name__)

API_BASE = "http://localhost:8000/api"


# ==================== Helper Functions ====================

def fetch_cves(search: str = "", severity: str = "", skip: int = 0, limit: int = 50):
    """Fetch CVEs from API"""
    params = {"skip": skip, "limit": limit}
    if search:
        params["search"] = search
    if severity:
        params["severity"] = severity

    try:
        response = httpx.get(f"{API_BASE}/cves", params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error fetching CVEs: {e}")
        return []


def fetch_news(category: str = "", source: str = "", skip: int = 0, limit: int = 50):
    """Fetch news from API"""
    params = {"skip": skip, "limit": limit}
    if category:
        params["category"] = category
    if source:
        params["source"] = source

    try:
        response = httpx.get(f"{API_BASE}/news", params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error fetching news: {e}")
        return []


def fetch_stats():
    """Fetch dashboard statistics"""
    try:
        cve_stats = httpx.get(f"{API_BASE}/cves/stats/summary", timeout=10).json()
        news_stats = httpx.get(f"{API_BASE}/news/stats/summary", timeout=10).json()
        agent_status = httpx.get(f"{API_BASE}/agents/status", timeout=10).json()
        return cve_stats, news_stats, agent_status
    except Exception as e:
        print(f"Error fetching stats: {e}")
        return {}, {}, {}


# ==================== Layout ====================

app.layout = html.Div([
    html.Div([
        html.H1("🛡️ CVE Intelligence Dashboard", style={"marginBottom": 20}),
        html.P("Real-time CVE and hacking news intelligence system", style={"color": "#666"})
    ], style={"padding": 20, "backgroundColor": "#f8f9fa", "borderBottom": "2px solid #ddd"}),

    # Statistics Cards
    html.Div(id="stats-container", children=[], style={
        "display": "grid",
        "gridTemplateColumns": "repeat(4, 1fr)",
        "gap": 15,
        "padding": 20,
        "backgroundColor": "#fff"
    }),

    dcc.Tabs(id="tabs", value="tab-cves", children=[
        # ==================== CVE Tab ====================
        dcc.Tab(label="🔴 CVE Database", value="tab-cves", children=[
            html.Div([
                html.Div([
                    html.Div([
                        html.Label("Search CVE:", style={"fontWeight": "bold"}),
                        dcc.Input(
                            id="cve-search-input",
                            type="text",
                            placeholder="Search by CVE ID, title, or description.. .",
                            style={
                                "width": "100%",
                                "padding": 10,
                                "marginBottom": 10,
                                "borderRadius": 4,
                                "border": "1px solid #ddd"
                            }
                        )
                    ], style={"flex": 1, "marginRight": 10}),

                    html.Div([
                        html.Label("Severity:", style={"fontWeight": "bold"}),
                        dcc.Dropdown(
                            id="cve-severity-filter",
                            options=[
                                {"label": "All", "value": ""},
                                {"label": "CRITICAL", "value": "CRITICAL"},
                                {"label": "HIGH", "value": "HIGH"},
                                {"label": "MEDIUM", "value": "MEDIUM"},
                                {"label": "LOW", "value": "LOW"}
                            ],
                            value="",
                            style={"marginBottom": 10}
                        )
                    ], style={"width": 150})
                ], style={"display": "flex", "marginBottom": 15}),

                html.Div(id="cve-table-container", children=[
                    html.P("Loading CVEs.. .", style={"textAlign": "center", "color": "#999"})
                ], style={"marginBottom": 15}),

                html.Div([
                    html.Button("← Previous", id="cve-prev-btn", n_clicks=0),
                    html.Span(id="cve-page-info", style={"margin": "0 10px"}),
                    html.Button("Next →", id="cve-next-btn", n_clicks=0)
                ], style={"textAlign": "center", "marginTop": 15}),

                dcc.Store(id="cve-page-store", data=0)

            ], style={"padding": 20})
        ]),

        # ==================== News Tab ====================
        dcc.Tab(label="📰 Hacking News", value="tab-news", children=[
            html.Div([
                html.Div([
                    html.Div([
                        html.Label("Category:", style={"fontWeight": "bold"}),
                        dcc.Dropdown(
                            id="news-category-filter",
                            options=[
                                {"label": "All", "value": ""},
                                {"label": "Exploit", "value": "exploit"},
                                {"label": "Breach", "value": "breach"},
                                {"label": "Threat", "value": "threat"},
                                {"label": "Tool", "value": "tool"}
                            ],
                            value="",
                            style={"marginBottom": 10}
                        )
                    ], style={"width": 150, "marginRight": 10}),

                    html.Div([
                        html.Label("Source:", style={"fontWeight": "bold"}),
                        dcc.Dropdown(
                            id="news-source-filter",
                            options=[
                                {"label": "All", "value": ""},
                                {"label": "Hacker News", "value": "hacker_news"},
                                {"label": "BleepingComputer", "value": "bleepingcomputer"},
                                {"label": "Darknet", "value": "darknet"}
                            ],
                            value="",
                            style={"marginBottom": 10}
                        )
                    ], style={"width": 150})
                ], style={"display": "flex", "marginBottom": 15}),

                html.Div(id="news-table-container", children=[
                    html.P("Loading news...", style={"textAlign": "center", "color": "#999"})
                ], style={"marginBottom": 15}),

                dcc.Store(id="news-page-store", data=0)

            ], style={"padding": 20})
        ]),

        # ==================== Analytics Tab ====================
        dcc.Tab(label="📊 Analytics", value="tab-analytics", children=[
            html.Div([
                html.Div([
                    html.Div(id="cve-severity-chart", style={"flex": 1}),
                    html.Div(id="news-category-chart", style={"flex": 1})
                ], style={"display": "flex", "gap": 20, "marginBottom": 20}),

                html.Div(id="agent-status-chart", style={"marginBottom": 20})

            ], style={"padding": 20})
        ])
    ], style={"padding": 20}),

    # Auto-refresh interval
    dcc.Interval(id="interval-component", interval=5 * 60 * 1000, n_intervals=0)  # 5 minutes
])


# ==================== Callbacks ====================

@callback(
    Output("stats-container", "children"),
    Input("interval-component", "n_intervals")
)
def update_stats(n):
    """Update statistics cards"""
    cve_stats, news_stats, agent_status = fetch_stats()

    cards = [
        html.Div([
            html.H3(cve_stats.get("total_cves", 0), style={"margin": 0, "color": "#d32f2f"}),
            html.P("Total CVEs", style={"margin": 0, "color": "#999"})
        ], style={
            "backgroundColor": "#ffebee",
            "padding": 20,
            "borderRadius": 8,
            "textAlign": "center",
            "border": "1px solid #ef5350"
        }),

        html.Div([
            html.H3(cve_stats.get("recent_24h", 0), style={"margin": 0, "color": "#f57c00"}),
            html.P("Last 24h", style={"margin": 0, "color": "#999"})
        ], style={
            "backgroundColor": "#fff3e0",
            "padding": 20,
            "borderRadius": 8,
            "textAlign": "center",
            "border": "1px solid #ffb74d"
        }),

        html.Div([
            html.H3(cve_stats.get("by_severity", {}).get("CRITICAL", 0), style={"margin": 0, "color": "#c62828"}),
            html.P("Critical CVEs", style={"margin": 0, "color": "#999"})
        ], style={
            "backgroundColor": "#fcebee",
            "padding": 20,
            "borderRadius": 8,
            "textAlign": "center",
            "border": "1px solid #e53935"
        }),

        html.Div([
            html.H3(news_stats.get("total_news", 0), style={"margin": 0, "color": "#1976d2"}),
            html.P("News Articles", style={"margin": 0, "color": "#999"})
        ], style={
            "backgroundColor": "#e3f2fd",
            "padding": 20,
            "borderRadius": 8,
            "textAlign": "center",
            "border": "1px solid #64b5f6"
        })
    ]

    return cards


@callback(
    [Output("cve-table-container", "children"), Output("cve-page-info", "children")],
    [Input("cve-search-input", "value"),
     Input("cve-severity-filter", "value"),
     Input("cve-next-btn", "n_clicks"),
     Input("cve-prev-btn", "n_clicks")],
    [State("cve-page-store", "data")],
    prevent_initial_call=False
)
def update_cve_table(search, severity, next_clicks, prev_clicks, page):
    """Update CVE table based on filters and pagination"""
    skip = page * 50
    cves = fetch_cves(search=search or "", severity=severity or "", skip=skip, limit=50)

    if not cves:
        return html.P("No CVEs found", style={"textAlign": "center", "color": "#999"}), f"Page {page + 1}"

    rows = [
        html.Tr([
            html.Td(cve["cve_id"], style={"fontWeight": "bold", "color": "#1976d2"}),
            html.Td(cve["title"][:60] + "..." if len(cve["title"]) > 60 else cve["title"]),
            html.Td(cve["severity"], style={
                "backgroundColor": "#ffcdd2" if cve["severity"] == "CRITICAL" else "#ffe0b2" if cve[
                                                                                                    "severity"] == "HIGH" else "#c8e6c9",
                "padding": "5px 10px",
                "borderRadius": 4,
                "textAlign": "center",
                "fontWeight": "bold"
            }),
            html.Td(cve["cvss_score"] or "N/A", style={"textAlign": "center"}),
            html.Td(cve["published_date"][:10], style={"color": "#666"})
        ])
        for cve in cves
    ]

    table = html.Table([
        html.Thead(
            html.Tr([
                html.Th("CVE ID", style={"textAlign": "left", "padding": 10, "borderBottom": "2px solid #ddd"}),
                html.Th("Title", style={"textAlign": "left", "padding": 10, "borderBottom": "2px solid #ddd"}),
                html.Th("Severity", style={"textAlign": "center", "padding": 10, "borderBottom": "2px solid #ddd"}),
                html.Th("CVSS Score", style={"textAlign": "center", "padding": 10, "borderBottom": "2px solid #ddd"}),
                html.Th("Published", style={"textAlign": "left", "padding": 10, "borderBottom": "2px solid #ddd"})
            ])
        ),
        html.Tbody(rows)
    ], style={"width": "100%", "borderCollapse": "collapse"})

    return table, f"Page {page + 1} ({skip}-{skip + len(cves)})"


@callback(
    Output("cve-page-store", "data"),
    [Input("cve-next-btn", "n_clicks"), Input("cve-prev-btn", "n_clicks")],
    [State("cve-page-store", "data")],
    prevent_initial_call=False
)
def update_cve_page(next_clicks, prev_clicks, page):
    """Handle CVE pagination"""
    if next_clicks > 0:
        return page + 1
    elif prev_clicks > 0 and page > 0:
        return page - 1
    return 0


@callback(
    Output("news-table-container", "children"),
    [Input("news-category-filter", "value"), Input("news-source-filter", "value")],
    prevent_initial_call=False
)
def update_news_table(category, source):
    """Update news table"""
    news_items = fetch_news(category=category or "", source=source or "", limit=50)

    if not news_items:
        return html.P("No news found", style={"textAlign": "center", "color": "#999"})

    rows = [
        html.Tr([
            html.Td(item["title"][:80] + "..." if len(item["title"]) > 80 else item["title"]),
            html.Td(item["source"], style={"color": "#666", "fontSize": "0.9em"}),
            html.Td(item["category"], style={"backgroundColor": "#e0e0e0", "padding": "5px 10px", "borderRadius": 4}),
            html.Td(item["relevance_score"], style={"textAlign": "center", "fontWeight": "bold"}),
            html.Td(item["published_date"][:10], style={"color": "#666"})
        ])
        for item in news_items
    ]

    table = html.Table([
        html.Thead(
            html.Tr([
                html.Th("Title", style={"textAlign": "left", "padding": 10, "borderBottom": "2px solid #ddd"}),
                html.Th("Source", style={"textAlign": "left", "padding": 10, "borderBottom": "2px solid #ddd"}),
                html.Th("Category", style={"textAlign": "center", "padding": 10, "borderBottom": "2px solid #ddd"}),
                html.Th("Relevance", style={"textAlign": "center", "padding": 10, "borderBottom": "2px solid #ddd"}),
                html.Th("Date", style={"textAlign": "left", "padding": 10, "borderBottom": "2px solid #ddd"})
            ])
        ),
        html.Tbody(rows)
    ], style={"width": "100%", "borderCollapse": "collapse"})

    return table


@callback(
    [Output("cve-severity-chart", "children"), Output("news-category-chart", "children")],
    Input("interval-component", "n_intervals"),
    prevent_initial_call=False
)
def update_charts(n):
    """Update analytics charts"""
    cve_stats, news_stats, _ = fetch_stats()

    # CVE Severity Chart
    severities = cve_stats.get("by_severity", {})
    severity_fig = go.Figure(data=[
        go.Bar(
            x=list(severities.keys()),
            y=list(severities.values()),
            marker_color=["#c62828", "#f57c00", "#fbc02d", "#388e3c"][: len(severities)]
        )
    ])
    severity_fig.update_layout(
        title="CVEs by Severity",
        xaxis_title="Severity",
        yaxis_title="Count",
        height=400,
        margin=dict(l=0, r=0, t=40, b=0)
    )

    # News Category Chart
    categories = news_stats.get("by_category", {})
    category_fig = go.Figure(data=[
        go.Pie(labels=list(categories.keys()), values=list(categories.values()))
    ])
    category_fig.update_layout(
        title="News by Category",
        height=400,
        margin=dict(l=0, r=0, t=40, b=0)
    )

    return dcc.Graph(figure=severity_fig), dcc.Graph(figure=category_fig)


if __name__ == "__main__":
    app.run_server(debug=True, host="0.0.0.0", port=8050)