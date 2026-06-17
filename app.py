"""
app.py — Streamlit interface for the MITRE ATLAS knowledge graph.
Run with:  streamlit run app.py
"""

import json
import os
import sys

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from neo4j import GraphDatabase

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "queries"))
import assess  # type: ignore
import draft  # type: ignore
import atlas_queries as queries

# ── Page config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="MITRE ATLAS Explorer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Global styles ─────────────────────────────────────────────────────────────

st.markdown(
    """
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">

<style>
/* ── Base typography ── */
html, body, [class*="css"] {
    font-family: 'Inter', sans-serif !important;
}
code, pre, .stCode {
    font-family: 'JetBrains Mono', monospace !important;
}

/* ── Background & app chrome ── */
.stApp { background: #080c18; }
section[data-testid="stSidebar"] {
    background: #0d1020 !important;
    border-right: 1px solid rgba(76, 201, 240, 0.08);
}

/* ── Sidebar brand ── */
.atlas-brand {
    display: flex;
    flex-direction: column;
    padding: 8px 0 4px 0;
}
.atlas-brand h1 {
    font-size: 1.25rem;
    font-weight: 700;
    color: #e8eaf6;
    margin: 0;
    letter-spacing: -0.02em;
}
.atlas-brand span {
    font-size: 0.72rem;
    color: #4cc9f0;
    font-weight: 500;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    margin-top: 2px;
}

/* ── Sidebar nav radio ── */
div[data-testid="stRadio"] > label { display: none; }
div[data-testid="stRadio"] > div {
    gap: 2px !important;
}
div[data-testid="stRadio"] label {
    display: flex !important;
    align-items: center;
    padding: 9px 14px !important;
    border-radius: 8px !important;
    font-size: 0.88rem !important;
    font-weight: 500;
    color: #8b90a8 !important;
    transition: all 0.18s ease;
    cursor: pointer;
    border: 1px solid transparent !important;
}
div[data-testid="stRadio"] label:hover {
    background: rgba(76, 201, 240, 0.07) !important;
    color: #c8ccee !important;
}
div[data-testid="stRadio"] label[data-baseweb="radio"] > div:first-child {
    display: none !important;
}
/* Active item */
div[data-testid="stRadio"] label[aria-checked="true"] {
    background: linear-gradient(135deg, rgba(76,201,240,0.15), rgba(114,9,183,0.1)) !important;
    color: #4cc9f0 !important;
    border-color: rgba(76,201,240,0.25) !important;
}

/* ── Page header gradient ── */
.page-header {
    background: linear-gradient(135deg, rgba(76,201,240,0.08) 0%, rgba(114,9,183,0.06) 50%, rgba(8,12,24,0) 100%);
    border: 1px solid rgba(76,201,240,0.1);
    border-radius: 16px;
    padding: 28px 32px 24px 32px;
    margin-bottom: 28px;
}
.page-header h1 {
    font-size: 1.85rem;
    font-weight: 700;
    color: #e8eaf6;
    margin: 0 0 6px 0;
    letter-spacing: -0.03em;
}
.page-header p {
    font-size: 0.92rem;
    color: #6b7094;
    margin: 0;
    line-height: 1.6;
}

/* ── Metric cards ── */
.metric-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
    gap: 12px;
    margin-bottom: 6px;
}
.metric-card {
    background: #0d1020;
    border: 1px solid rgba(76,201,240,0.1);
    border-radius: 12px;
    padding: 18px 16px 14px 16px;
    transition: border-color 0.2s ease, transform 0.2s ease;
}
.metric-card:hover {
    border-color: rgba(76,201,240,0.35);
    transform: translateY(-2px);
}
.metric-card .label {
    font-size: 0.72rem;
    font-weight: 600;
    color: #4cc9f0;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    margin-bottom: 8px;
}
.metric-card .value {
    font-size: 2rem;
    font-weight: 700;
    color: #e8eaf6;
    line-height: 1;
    letter-spacing: -0.03em;
}
.metric-card .sub {
    font-size: 0.72rem;
    color: #4b5070;
    margin-top: 6px;
}
.metric-card.accent-red  { border-left: 3px solid #e63946; }
.metric-card.accent-cyan  { border-left: 3px solid #4cc9f0; }
.metric-card.accent-purple{ border-left: 3px solid #7209b7; }
.metric-card.accent-green { border-left: 3px solid #06d6a0; }
.metric-card.accent-amber { border-left: 3px solid #f4a261; }

/* ── Section header ── */
.section-header {
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: #4b5070;
    margin: 24px 0 12px 0;
}

/* ── Feature cards ── */
.feature-card {
    background: #0d1020;
    border: 1px solid rgba(76,201,240,0.08);
    border-radius: 12px;
    padding: 20px;
    height: 100%;
    transition: border-color 0.2s ease;
}
.feature-card:hover { border-color: rgba(76,201,240,0.25); }
.feature-card h3 {
    font-size: 0.92rem;
    font-weight: 600;
    color: #e8eaf6;
    margin: 0 0 8px 0;
}
.feature-card p {
    font-size: 0.82rem;
    color: #6b7094;
    margin: 0;
    line-height: 1.55;
}

/* ── Data table ── */
div[data-testid="stDataFrame"] {
    border: 1px solid rgba(76,201,240,0.1);
    border-radius: 10px;
    overflow: hidden;
}

/* ── Info / success / error ── */
div[data-testid="stAlert"] {
    border-radius: 10px;
}

/* ── Tabs ── */
button[data-baseweb="tab"] {
    font-size: 0.85rem !important;
    font-weight: 500 !important;
}

/* ── Expander ── */
details summary {
    font-weight: 500;
    font-size: 0.88rem;
}

/* ── Technique chain pills ── */
.chain-pill {
    display: inline-block;
    background: #0d1020;
    border: 1px solid rgba(76,201,240,0.25);
    border-radius: 6px;
    padding: 4px 12px;
    font-size: 0.8rem;
    color: #4cc9f0;
}

/* ── Rel badge ── */
.rel-badge {
    display: inline-block;
    background: rgba(230,57,70,0.12);
    border: 1px solid rgba(230,57,70,0.25);
    border-radius: 20px;
    padding: 3px 10px;
    font-size: 0.75rem;
    font-weight: 600;
    color: #e63946;
    font-family: 'JetBrains Mono', monospace;
    margin: 3px;
}

/* ── Connection status ── */
.conn-ok  { color: #06d6a0; font-size: 0.8rem; font-weight: 600; }
.conn-err { color: #e63946; font-size: 0.8rem; font-weight: 600; }

/* ── Risk badges ── */
.risk-high   { color: #e63946; font-weight: 700; font-size: 0.8rem; letter-spacing:.04em; }
.risk-medium { color: #f4a261; font-weight: 700; font-size: 0.8rem; letter-spacing:.04em; }
.risk-low    { color: #06d6a0; font-weight: 700; font-size: 0.8rem; letter-spacing:.04em; }

/* ── Input fields ── */
div[data-testid="stTextInput"] div[data-baseweb="input"],
div[data-testid="stTextArea"] div[data-baseweb="textarea"] {
    background: #0d1020 !important;
    border: 1px solid rgba(76,201,240,0.25) !important;
    border-radius: 8px !important;
}
div[data-testid="stTextInput"] input,
div[data-testid="stTextArea"] textarea {
    font-family: 'Inter', sans-serif !important;
    background: transparent !important;
    border: none !important;
}

/* ── Buttons ── */
div[data-testid="stButton"] > button[kind="primary"] {
    background: linear-gradient(135deg, #4cc9f0, #7209b7) !important;
    border: none !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
    letter-spacing: 0.02em;
    transition: opacity 0.18s ease;
}
div[data-testid="stButton"] > button[kind="primary"]:hover {
    opacity: 0.88 !important;
}

/* ── Hide Streamlit chrome (keep sidebar toggle) ── */
footer { visibility: hidden; }
#MainMenu { visibility: hidden; }
/* Only hide the deploy / kebab buttons, NOT the sidebar collapse arrow */
div[data-testid="stToolbar"] > div:nth-child(2) { display: none; }
</style>
""",
    unsafe_allow_html=True,
)

# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown(
        """
        <div class="atlas-brand">
            <h1>ATLAS Explorer</h1>
            <span>MITRE Knowledge Graph</span>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.divider()

    # Transfer pending navigation request before the radio widget is instantiated
    if "_pending_nav" in st.session_state:
        st.session_state["page_nav"] = st.session_state.pop("_pending_nav")

    page = st.radio(
        "nav",
        [
            "Overview",
            "Platform Explorer",
            "Technique Inspector",
            "Coverage Analysis",
            "Tactic Overview",
            "Threat Assessment",
            "Report Generator",
            "OWASP Insights",
        ],
        label_visibility="collapsed",
        key="page_nav",
    )

    st.divider()

    with st.expander("Neo4j connection"):
        neo4j_uri = st.text_input("URI", "bolt://localhost:7687")
        neo4j_user = st.text_input("User", "neo4j")
        neo4j_pass = st.text_input("Password", "atlaspassword", type="password")

# ── Driver ────────────────────────────────────────────────────────────────────


@st.cache_resource
def get_driver(uri, user, pw):
    try:
        d = GraphDatabase.driver(uri, auth=(user, pw))
        d.verify_connectivity()
        return d
    except Exception:
        return None


driver = get_driver(neo4j_uri, neo4j_user, neo4j_pass)

with st.sidebar:
    if driver:
        st.markdown('<p class="conn-ok">● Connected to Neo4j</p>', unsafe_allow_html=True)
    else:
        st.markdown('<p class="conn-err">● Cannot reach Neo4j</p>', unsafe_allow_html=True)
        st.caption("Start the container first:  \n`docker compose up -d`")
        st.stop()

# ── Cached queries ────────────────────────────────────────────────────────────


@st.cache_data(ttl=300)
def get_stats(_driver):
    with _driver.session() as s:
        counts = {}
        for label in [
            "Tactic",
            "Technique",
            "SubTechnique",
            "Mitigation",
            "CaseStudy",
            "Platform",
            "OwaspRisk",
        ]:
            counts[label] = s.run(f"MATCH (n:{label}) RETURN count(n) AS c").single()["c"]
        rels = s.run(
            "MATCH ()-[r]->() RETURN type(r) AS t, count(r) AS c ORDER BY t"
        ).data()
        counts["rels"] = {r["t"]: r["c"] for r in rels}
    return counts


@st.cache_data(ttl=300)
def get_platforms(_driver):
    with _driver.session() as s:
        return [
            r["name"]
            for r in s.run("MATCH (p:Platform) RETURN p.name AS name ORDER BY name")
        ]


@st.cache_data(ttl=300)
def get_technique_options(_driver):
    with _driver.session() as s:
        rows = s.run(
            "MATCH (t:Technique) RETURN t.id AS id, t.name AS name ORDER BY t.id"
        ).data()
        return {f"{r['id']} — {r['name']}": r["id"] for r in rows}


@st.cache_data(ttl=300)
def cached_techniques_by_platform(_driver, platform):
    return queries.techniques_by_platform(_driver, platform)


@st.cache_data(ttl=300)
def cached_threat_profile(_driver, platform):
    return queries.threat_profile(_driver, platform)


@st.cache_data(ttl=300)
def cached_mitigations_for(_driver, tid):
    return queries.mitigations_for_technique(_driver, tid)


@st.cache_data(ttl=300)
def cached_attack_chain(_driver, tid):
    return queries.attack_chain_from(_driver, tid, max_hops=5)


@st.cache_data(ttl=300)
def cached_case_studies_for(_driver, tid):
    return queries.case_studies_for_technique(_driver, tid)


@st.cache_data(ttl=300)
def cached_gaps(_driver, platform):
    return queries.techniques_without_mitigations(_driver, platform=platform or None)


@st.cache_data(ttl=300)
def cached_coverage(_driver, limit):
    return queries.top_mitigations_by_coverage(_driver, limit=limit)


@st.cache_data(ttl=300)
def cached_tactic_overview(_driver):
    return queries.tactic_overview(_driver)


@st.cache_data(ttl=300)
def cached_all_owasp_risks(_driver):
    return queries.all_owasp_risks(_driver)

@st.cache_data(ttl=300)
def cached_owasp_risk_full_context(_driver, owasp_id):
    return queries.owasp_risk_full_context(_driver, owasp_id)

@st.cache_data(ttl=300)
def cached_owasp_risk_tactic_summary(_driver, owasp_id):
    return queries.owasp_risk_tactic_summary(_driver, owasp_id)


@st.cache_data(ttl=300)
def cached_owasp_tactic_span_summary(_driver):
    return queries.owasp_tactic_span_summary(_driver)


# ── Plotly theme helper ───────────────────────────────────────────────────────


def dark_layout(fig, **kwargs):
    fig.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font_color="#e8eaf6",
        font_family="Inter, sans-serif",
        **kwargs,
    )
    return fig


# ── HTML helpers ─────────────────────────────────────────────────────────────


def render_metric_cards(cards):
    """
    cards: list of (label, value, accent, sub) tuples.
    Renders each as an individual st.markdown card inside st.columns.
    """
    cols = st.columns(len(cards))
    for col, (label, value, accent, sub) in zip(cols, cards):
        sub_html = f"<div class='sub'>{sub}</div>" if sub else ""
        col.markdown(
            f"""<div class="metric-card accent-{accent}">
<div class="label">{label}</div>
<div class="value">{value}</div>
{sub_html}
</div>""",
            unsafe_allow_html=True,
        )


def section_header(text):
    st.markdown(f'<div class="section-header">{text}</div>', unsafe_allow_html=True)


def page_header(title, description=""):
    desc_html = f"<p>{description}</p>" if description else ""
    st.markdown(
        f"""
        <div class="page-header">
            <h1>{title}</h1>
            {desc_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


# ── Knowledge Graph Visualisation ─────────────────────────────────────────────


def build_schema_graph(stats):
    """
    Build a Plotly network figure that shows the ATLAS schema:
    node types as large coloured circles, relationship types as labelled edges.
    Positions are fixed so the layout is clean and readable every time.
    """
    import math

    NODE_META = {
        "Tactic":       {"color": "#4cc9f0", "size": 42, "icon": "T", "count_key": "Tactic"},
        "Technique":    {"color": "#7209b7", "size": 52, "icon": "Te", "count_key": "Technique"},
        "SubTechnique": {"color": "#9d4edd", "size": 38, "icon": "S", "count_key": "SubTechnique"},
        "Mitigation":   {"color": "#06d6a0", "size": 44, "icon": "M", "count_key": "Mitigation"},
        "CaseStudy":    {"color": "#f4a261", "size": 40, "icon": "C", "count_key": "CaseStudy"},
        "Platform":     {"color": "#e63946", "size": 36, "icon": "P", "count_key": "Platform"},
        "OwaspRisk":    {"color": "#ff006e", "size": 38, "icon": "O", "count_key": "OwaspRisk"},
    }

    # Hand-tuned positions (x, y) for a balanced layout
    positions = {
        "Tactic":       (0.5,  0.92),
        "Technique":    (0.5,  0.55),
        "SubTechnique": (0.82, 0.55),
        "Mitigation":   (0.18, 0.20),
        "CaseStudy":    (0.82, 0.20),
        "Platform":     (0.5,  0.10),
        "OwaspRisk":    (0.18, 0.55),
    }

    # Relationship schema: (source, target, rel_type)
    RELS = [
        ("Technique",    "Tactic",       "BELONGS_TO"),
        ("SubTechnique", "Technique",    "SUBTECHNIQUE_OF"),
        ("Technique",    "Platform",     "TARGETS"),
        ("Technique",    "Mitigation",   "MITIGATED_BY"),
        ("CaseStudy",    "Technique",    "EMPLOYS"),
        ("Technique",    "Technique",    "FOLLOWED_BY"),
        ("OwaspRisk",    "Technique",    "CORRESPONDS_TO"),
    ]

    rels_data = stats.get("rels", {})

    # ── Edge traces ──
    edge_traces = []
    annots = []

    for src, dst, rel in RELS:
        x0, y0 = positions[src]
        x1, y1 = positions[dst]

        # self-loops: draw a small visual loop and annotation
        if src == dst:
            ls = 0.035 # loop size
            loop_x = [x0, x0 + ls, x0 + ls, x0 - ls, x0 - ls, x0, None]
            loop_y = [y0, y0 + ls, y0 + ls * 2.2, y0 + ls * 2.2, y0 + ls, y0, None]
            
            edge_traces.append(go.Scatter(
                x=loop_x, y=loop_y,
                mode="lines",
                line=dict(color="rgba(76,201,240,0.25)", width=2),
                hoverinfo="none",
                showlegend=False,
            ))

            annots.append(dict(
                x=x0, y=y0 + ls * 2.2,
                text=f"<b>{rel}</b><br><span style='color:#666;font-size:10px'>{rels_data.get(rel, 0):,}</span>",
                showarrow=False,
                font=dict(size=9, color="#4cc9f0"),
                bgcolor="rgba(13,16,32,0.85)",
                bordercolor="rgba(76,201,240,0.25)",
                borderwidth=1,
                borderpad=4,
            ))
            continue

        # midpoint for label
        mx, my = (x0 + x1) / 2, (y0 + y1) / 2

        edge_traces.append(go.Scatter(
            x=[x0, x1, None],
            y=[y0, y1, None],
            mode="lines",
            line=dict(color="rgba(76,201,240,0.2)", width=2),
            hoverinfo="none",
            showlegend=False,
        ))

        count = rels_data.get(rel, 0)
        annots.append(dict(
            x=mx, y=my,
            text=f"<b>{rel}</b><br><span style='font-size:10px;color:#555'>{count:,}</span>",
            showarrow=False,
            font=dict(size=9, color="#8b90a8"),
            bgcolor="rgba(13,16,32,0.85)",
            bordercolor="rgba(76,201,240,0.12)",
            borderwidth=1,
            borderpad=4,
        ))

    # ── Node trace ──
    nx_list, ny_list, sizes, colors, texts, hovers = [], [], [], [], [], []
    for node, meta in NODE_META.items():
        x, y = positions[node]
        count = stats.get(meta["count_key"], 0)
        nx_list.append(x)
        ny_list.append(y)
        sizes.append(meta["size"])
        colors.append(meta["color"])
        texts.append(f"<b>{node}</b>")
        hovers.append(f"<b>{node}</b><br>{count:,} nodes")

    node_trace = go.Scatter(
        x=nx_list,
        y=ny_list,
        mode="markers+text",
        marker=dict(
            size=sizes,
            color=colors,
            line=dict(color="rgba(255,255,255,0.08)", width=2),
            opacity=0.92,
        ),
        text=texts,
        textposition="top center",
        textfont=dict(size=11, color="#e8eaf6", family="Inter, sans-serif"),
        hovertext=hovers,
        hoverinfo="text",
        showlegend=False,
    )

    # ── Count labels inside nodes ──
    count_trace = go.Scatter(
        x=nx_list,
        y=[y - 0.025 for y in ny_list],  # nudge slightly inside marker
        mode="text",
        text=[f"{stats.get(NODE_META[n]['count_key'], 0):,}" for n in NODE_META],
        textfont=dict(size=9, color="rgba(255,255,255,0.6)", family="Inter, sans-serif"),
        hoverinfo="none",
        showlegend=False,
    )

    fig = go.Figure(data=edge_traces + [node_trace, count_trace])
    fig.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=20, r=20, t=20, b=20),
        xaxis=dict(visible=False, range=[-0.05, 1.05]),
        yaxis=dict(visible=False, range=[-0.03, 1.08]),
        annotations=annots,
        height=460,
        font=dict(family="Inter, sans-serif", color="#e8eaf6"),
        hoverlabel=dict(
            bgcolor="#0d1020",
            bordercolor="rgba(76,201,240,0.3)",
            font=dict(size=12, color="#e8eaf6", family="Inter, sans-serif"),
        ),
    )
    return fig


# ═══════════════════════════════════════════════════════════════════════════════
# Pages
# ═══════════════════════════════════════════════════════════════════════════════

# ─── Overview ─────────────────────────────────────────────────────────────────
if page == "Overview":
    page_header(
        "MITRE ATLAS Knowledge Graph",
        "Adversarial Threat Landscape for AI Systems — tactics, techniques, mitigations, "
        "and real-world incidents loaded into Neo4j for graph-powered analysis.",
    )

    stats = get_stats(driver)
    rels  = stats.get("rels", {})

    # ── Node metrics ──
    section_header("Node Inventory")
    render_metric_cards([
        ("Tactics",        stats["Tactic"],        "cyan",   ""),
        ("Techniques",     stats["Technique"],     "purple", ""),
        ("Sub-techniques", stats["SubTechnique"],  "purple", ""),
        ("Mitigations",    stats["Mitigation"],    "green",  ""),
        ("Case Studies",   stats["CaseStudy"],     "amber",  ""),
        ("Platforms",      stats["Platform"],      "red",    ""),
    ])

    # ── Relationship metrics ──
    section_header("Relationship Counts")
    badges_html = "".join(f'<span class="rel-badge">{k}&nbsp;<b style="font-size:1rem;color:#e8eaf6">{v:,}</b></span>' for k, v in rels.items())
    st.markdown(f'<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:20px">{badges_html}</div>', unsafe_allow_html=True)

    # ── Graph visualisation ──
    section_header("Knowledge Graph — Schema View")
    st.markdown(
        '<p style="font-size:0.8rem;color:#4b5070;margin-bottom:12px">'
        "Each node type is sized by relative importance. "
        "Edge labels show relationship types and their counts in the live graph."
        "</p>",
        unsafe_allow_html=True,
    )
    fig = build_schema_graph(stats)
    st.plotly_chart(fig, use_container_width=True)

    # ── Feature cards ──
    section_header("Available Pages")

    PAGE_CARDS = [
        (
            "Platform Explorer",
            "Browse all techniques targeting a specific platform and view a full threat "
            "profile with mitigations and real-world incident counts.",
        ),
        (
            "Technique Inspector",
            "Select any technique to explore its mitigations by lifecycle phase, "
            "downstream attack chains, and documented case studies.",
        ),
        (
            "Coverage Analysis",
            "Identify techniques with no documented mitigation and see which mitigations "
            "provide the broadest coverage across the framework.",
        ),
        (
            "Tactic Overview",
            "Compare technique counts vs. real-world incident counts per tactic "
            "with an interactive grouped bar chart.",
        ),
        (
            "OWASP Insights",
            "Explore how OWASP LLM Top 10 vulnerabilities directly translate to the "
            "adversarial mechanisms in the MITRE ATLAS lifecycle.",
        ),
    ]

    col_l, col_r = st.columns(2)
    for i, (title, desc) in enumerate(PAGE_CARDS):
        col = col_l if i % 2 == 0 else col_r
        with col:
            st.markdown(
                f'<div class="feature-card"><h3>{title}</h3><p>{desc}</p></div>',
                unsafe_allow_html=True,
            )
            if st.button(f"Open {title}", key=f"nav_btn_{i}", use_container_width=True):
                st.session_state["_pending_nav"] = title
                st.rerun()
            st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)


# ─── Platform Explorer ────────────────────────────────────────────────────────
elif page == "Platform Explorer":
    page_header(
        "Platform Explorer",
        "Browse all techniques targeting a specific platform and view a full threat profile.",
    )

    platforms = get_platforms(driver)
    if not platforms:
        st.warning("No platform nodes found in the graph.")
        st.stop()

    platform = st.selectbox("Select a platform", platforms)
    st.divider()

    section_header(f"Techniques targeting {platform}")
    rows = cached_techniques_by_platform(driver, platform)

    if rows:
        df = pd.DataFrame(rows)
        df["tactics"] = df["tactics"].apply(lambda x: ", ".join(x) if x else "—")
        df.columns = ["ID", "Technique", "Tactics"]
        st.dataframe(df, use_container_width=True, hide_index=True)
        st.caption(f"{len(rows)} technique(s) found")
    else:
        st.info("No techniques found for this platform.")

    st.divider()

    section_header(f"Threat Profile — {platform}")
    st.caption("Sorted by number of documented real-world incidents (highest first)")

    profile = cached_threat_profile(driver, platform)

    if not profile:
        st.info("No threat profile data available.")
    else:
        for row in profile:
            inc = row["real_world_incidents"]
            mits = row["mitigations"] or []
            risk_color = "#e63946" if inc > 2 else ("#f4a261" if inc > 0 else "#4b5070")
            risk_label = "HIGH" if inc > 2 else ("MEDIUM" if inc > 0 else "NONE")

            with st.container(border=True):
                left, mid, r1, r2 = st.columns([4, 2, 1, 1])
                left.markdown(
                    f"**{row['technique_name']}**  \n"
                    f'<code style="font-size:0.78rem">{row["technique_id"]}</code>',
                    unsafe_allow_html=True,
                )
                mid.markdown(
                    f"<br><small><i>{row['tactic'] or '—'}</i></small>",
                    unsafe_allow_html=True,
                )
                r1.metric("Mitigations", len(mits))
                r2.markdown(
                    f"<br><span style='color:{risk_color};font-weight:700;font-size:0.8rem'>"
                    f"{'●'} {inc} incident{'s' if inc != 1 else ''}</span>",
                    unsafe_allow_html=True,
                )

                if mits:
                    st.markdown(
                        " ".join(f"`{m}`" for m in mits),
                        help="Documented mitigations for this technique",
                    )

# ─── Technique Inspector ──────────────────────────────────────────────────────
elif page == "Technique Inspector":
    page_header(
        "Technique Inspector",
        "Select any technique to explore its mitigations, downstream attack chains, and case studies.",
    )

    options = get_technique_options(driver)
    if not options:
        st.warning("No techniques found in the graph.")
        st.stop()

    selected = st.selectbox("Search technique by ID or name", list(options.keys()))
    tid = options[selected]

    st.divider()

    tab_mit, tab_chain, tab_cs = st.tabs(["Mitigations", "Attack Chain", "Case Studies"])

    with tab_mit:
        section_header("Mitigations")
        mits = cached_mitigations_for(driver, tid)

        if not mits:
            st.info("No mitigations documented for this technique.")
        else:
            st.caption(f"{len(mits)} mitigation(s) found")
            for m in mits:
                with st.expander(f"**{m['mitigation_name']}**  —  `{m['mitigation_id']}`"):
                    if m["category"]:
                        st.markdown(f"**Category:** {m['category']}")
                    phases = m["lifecycle_phases"] or []
                    if phases:
                        st.markdown("**Lifecycle phases:**")
                        st.markdown("  " + "  ·  ".join(f"`{p}`" for p in phases))

    with tab_chain:
        section_header("Attack Chain")
        st.caption(
            "Techniques commonly observed after this one, derived from case study step sequences"
        )

        chains = cached_attack_chain(driver, tid)

        if not chains:
            st.info("No downstream attack sequences found for this technique.")
        else:
            seen: set[str] = set()
            for row in sorted(chains, key=lambda x: -x["hops"]):
                key = "→".join(row["chain_ids"])
                if key in seen:
                    continue
                seen.add(key)

                steps = row["chain_names"]
                parts = []
                for i, name in enumerate(steps):
                    color = (
                        "#4cc9f0"
                        if i == 0
                        else ("#e63946" if i == len(steps) - 1 else "#e8eaf6")
                    )
                    parts.append(
                        f'<span style="background:#0d1020;border:1px solid {color};'
                        f'border-radius:6px;padding:4px 12px;font-size:0.82rem;color:{color}'
                        f';font-family:Inter,sans-serif">{name}</span>'
                    )
                arrow = ' <span style="color:#2d3150;font-size:1.1rem">→</span> '
                st.markdown(arrow.join(parts), unsafe_allow_html=True)
                st.markdown("")

    with tab_cs:
        section_header("Case Studies")
        cases = cached_case_studies_for(driver, tid)

        if not cases:
            st.info("No case studies found for this technique.")
        else:
            st.caption(f"{len(cases)} case study/studies found")
            for c in cases:
                label = f"[{c['case_study_id']}]  {c['case_study_name']}  ({c['case_study_type']})"
                with st.expander(label):
                    st.markdown(c["procedure"] or "*No procedure text documented.*")

# ─── Coverage Analysis ────────────────────────────────────────────────────────
elif page == "Coverage Analysis":
    page_header(
        "Coverage Analysis",
        "Identify techniques with no documented mitigation and prioritise what to implement first.",
    )

    tab_gaps, tab_top = st.tabs(["Unmitigated Techniques", "Mitigation Coverage"])

    with tab_gaps:
        section_header("Techniques with no documented mitigation")

        platforms = get_platforms(driver)
        plat_filter = st.selectbox("Filter by platform", ["All platforms"] + platforms)
        plat = None if plat_filter == "All platforms" else plat_filter

        gaps = cached_gaps(driver, plat)

        if not gaps:
            st.success("Every technique in this selection has at least one mitigation.")
        else:
            st.error(f"{len(gaps)} technique(s) have no documented mitigation")
            df = pd.DataFrame(gaps)
            df.columns = ["ID", "Technique"]
            st.dataframe(df, use_container_width=True, hide_index=True)

    with tab_top:
        section_header("Which mitigations cover the most techniques?")
        st.caption("Useful for prioritising what to implement first")

        top_n = st.slider("Show top N", 5, 35, 15)
        coverage = cached_coverage(driver, top_n)

        if not coverage:
            st.info("No coverage data available.")
        else:
            df = pd.DataFrame(coverage).rename(
                columns={
                    "mitigation_id": "ID",
                    "mitigation_name": "Mitigation",
                    "category": "Category",
                    "techniques_covered": "Covered",
                }
            )

            fig = px.bar(
                df,
                x="Covered",
                y="Mitigation",
                orientation="h",
                color="Covered",
                color_continuous_scale=[[0, "#1a1d2e"], [0.5, "#7209b7"], [1, "#4cc9f0"]],
                text="Covered",
                height=max(420, top_n * 38),
            )
            fig.update_traces(textposition="outside")
            fig = dark_layout(
                fig,
                coloraxis_showscale=False,
                yaxis={"categoryorder": "total ascending", "tickfont_size": 12},
                xaxis_title="Techniques covered",
                margin={"l": 0, "r": 60, "t": 20, "b": 40},
            )
            st.plotly_chart(fig, use_container_width=True)

            st.dataframe(
                df[["ID", "Mitigation", "Category", "Covered"]],
                use_container_width=True,
                hide_index=True,
            )

# ─── Tactic Overview ──────────────────────────────────────────────────────────
elif page == "Tactic Overview":
    page_header(
        "Tactic Overview",
        "Technique count vs. documented real-world incidents per tactic.",
    )

    rows = cached_tactic_overview(driver)

    if not rows:
        st.info("No tactic data available.")
    else:
        df = pd.DataFrame(rows).rename(
            columns={
                "tactic_id": "ID",
                "tactic_name": "Tactic",
                "technique_count": "Techniques",
                "incident_count": "Incidents",
            }
        )

        melted = df.melt(
            id_vars=["ID", "Tactic"],
            value_vars=["Techniques", "Incidents"],
            var_name="Type",
            value_name="Count",
        )

        fig = px.bar(
            melted,
            x="Tactic",
            y="Count",
            color="Type",
            barmode="group",
            color_discrete_map={"Techniques": "#4cc9f0", "Incidents": "#e63946"},
            text="Count",
            height=460,
        )
        fig.update_traces(textposition="outside")
        fig = dark_layout(
            fig,
            xaxis_tickangle=-30,
            legend_title="",
            bargap=0.2,
            margin={"l": 10, "r": 10, "t": 20, "b": 120},
        )
        st.plotly_chart(fig, use_container_width=True)

        st.divider()

        total_techniques = df["Techniques"].sum()
        total_incidents  = df["Incidents"].sum()
        most_techniques  = df.loc[df["Techniques"].idxmax(), "Tactic"]
        most_incidents   = df.loc[df["Incidents"].idxmax(), "Tactic"]

        render_metric_cards([
            ("Total Techniques", total_techniques, "cyan",   ""),
            ("Total Incidents",  total_incidents,  "red",    ""),
            ("Most Techniques",  most_techniques,  "purple", ""),
            ("Most Incidents",   most_incidents,   "amber",  ""),
        ])

        st.divider()
        st.dataframe(df, use_container_width=True, hide_index=True)

# ─── Threat Assessment ────────────────────────────────────────────────────────
elif page == "Threat Assessment":
    page_header(
        "Threat Assessment",
        "Describe your AI system in plain English. The model reads the live ATLAS catalogue "
        "from Neo4j and returns the most relevant techniques with risk ratings and reasoning.",
    )

    with st.sidebar:
        st.divider()
        with st.container(border=True):
            groq_key = st.text_input(
                "Groq API key",
                type="password",
                value=os.getenv("GROQ_API_KEY", ""),
                help="Get a free key at console.groq.com",
            )
        model = st.selectbox(
            "Model",
            [
                "llama-3.3-70b-versatile",
                "llama-3.1-8b-instant",
                "mixtral-8x7b-32768",
            ],
        )
        max_t = st.slider("Max techniques", 3, 15, 8)

    system_desc = st.text_area(
        "System description",
        placeholder=(
            "e.g. A RAG-based customer support chatbot backed by GPT-4o. "
            "It retrieves context from an internal knowledge base, has access "
            "to a CRM tool, and is accessible to external users via a web form."
        ),
        height=160,
    )

    if st.button("Run Assessment", type="primary", disabled=not system_desc.strip()):
        if not groq_key:
            st.error("Enter your Groq API key in the sidebar.")
        else:
            with st.spinner("Querying Groq..."):
                try:
                    result = assess.assess_threat(
                        system_desc,
                        driver=driver,
                        api_key=groq_key,
                        model=model,
                        max_techniques=max_t,
                    )
                except Exception as e:
                    st.error(f"Assessment failed: {e}")
                    st.stop()

            techniques = result.get("techniques", [])
            summary    = result.get("summary", "")

            section_header("Overall Risk Summary")
            st.info(summary)
            st.divider()

            section_header(f"Relevant Techniques ({len(techniques)})")

            RISK_COLORS = {"high": "#e63946", "medium": "#f4a261", "low": "#06d6a0"}

            for t in techniques:
                risk   = (t.get("risk") or "medium").lower()
                rcolor = RISK_COLORS.get(risk, "#8b90a8")

                with st.container(border=True):
                    left, right = st.columns([5, 1])
                    left.markdown(
                        f"**{t.get('name', '—')}** &nbsp; `{t.get('id', '—')}`  \n"
                        f"<small><i>{t.get('tactic', '—')}</i></small>",
                        unsafe_allow_html=True,
                    )
                    right.markdown(
                        f"<br><span style='color:{rcolor};font-weight:700;font-size:0.82rem;"
                        f"letter-spacing:.05em'>{risk.upper()}</span>",
                        unsafe_allow_html=True,
                    )
                    st.markdown(t.get("reason", ""))

            st.divider()
            st.download_button(
                "Download JSON",
                data=json.dumps(result, indent=2),
                file_name="atlas_assessment.json",
                mime="application/json",
            )

# ─── Report Generator ────────────────────────────────────────────────────────
elif page == "Report Generator":
    page_header(
        "Threat Model Report Generator",
        "Describe your AI system and generate a formal, citable threat-modelling report "
        "grounded in the live ATLAS knowledge graph.",
    )

    with st.sidebar:
        st.divider()
        with st.container(border=True):
            rg_key = st.text_input(
                "Groq API key",
                type="password",
                value=os.getenv("GROQ_API_KEY", ""),
                key="rg_groq_key",
                help="Get a free key at console.groq.com",
            )
        rg_model = st.selectbox(
            "Model",
            [
                "llama-3.3-70b-versatile",
                "llama-3.1-8b-instant",
                "mixtral-8x7b-32768",
            ],
            key="rg_model",
        )
        rg_max_t = st.slider("Max techniques", 3, 12, 8, key="rg_max_t")

    system_desc_rg = st.text_area(
        "System description",
        placeholder=(
            "e.g. A RAG-based customer support chatbot backed by GPT-4o. "
            "It retrieves context from an internal knowledge base, has access "
            "to a CRM tool, and is accessible to external users via a web form."
        ),
        height=160,
        key="rg_desc",
    )

    if st.button("Generate Report", type="primary", disabled=not system_desc_rg.strip()):
        if not rg_key:
            st.error("Enter your Groq API key in the sidebar.")
        else:
            with st.spinner("Generating report (3 steps — this takes ~15 s)..."):
                try:
                    st.session_state["rg_result"] = draft.draft_report(
                        system_desc_rg,
                        driver=driver,
                        api_key=rg_key,
                        model=rg_model,
                        max_techniques=rg_max_t,
                    )
                except Exception as e:
                    st.error(f"Report generation failed: {e}")
                    st.stop()

    if "rg_result" in st.session_state:
        result      = st.session_state["rg_result"]
        techniques  = result["techniques"]
        mitigations = result["mitigations"]
        case_studies = result["case_studies"]
        gaps        = result["gaps"]

        st.divider()

        render_metric_cards([
            ("Techniques",    len(techniques),                               "purple", ""),
            ("Mitigations",   sum(len(v) for v in mitigations.values()),     "green",  ""),
            ("Case Studies",  sum(len(v) for v in case_studies.values()),    "amber",  ""),
            ("Coverage Gaps", len(gaps),                                     "red",    ""),
        ])

        if gaps:
            st.warning(
                f"{len(gaps)} technique(s) have no documented mitigation: "
                + ", ".join(f"`{g}`" for g in gaps)
            )

        st.divider()
        section_header("Report Preview")
        st.markdown(result["markdown"], unsafe_allow_html=False)

        st.divider()
        dl1, dl2, dl3 = st.columns(3)
        dl1.download_button(
            "Download Markdown",
            data=result["markdown"],
            file_name="atlas_threat_model.md",
            mime="text/markdown",
        )
        dl2.download_button(
            "Download JSON",
            data=json.dumps(result, indent=2),
            file_name="atlas_threat_model.json",
            mime="application/json",
        )
        dl3.download_button(
            "Download PDF",
            data=bytes(draft.markdown_to_pdf(result["markdown"])),
            file_name="atlas_threat_model.pdf",
            mime="application/pdf",
        )

# ─── OWASP Insights ───────────────────────────────────────────────────────────
elif page == "OWASP Insights":
    page_header(
        "OWASP Insights",
        "Explore how OWASP LLM Top 10 risks map to adversary tactics and techniques "
        "within the MITRE ATLAS lifecycle."
    )

    all_risks = cached_all_owasp_risks(driver)
    if not all_risks:
        st.warning("No OWASP risk nodes found in the graph. Please ensure ingest_owasp.py was run.")
        st.stop()

    # --- Global Summary ---
    span_summary = cached_owasp_tactic_span_summary(driver)
    if span_summary:
        section_header("Adversarial Breadth per OWASP Risk")
        st.caption("How many distinct ATLAS tactics are spanned by each OWASP risk category:")
        
        df_span = pd.DataFrame(span_summary)
        fig_span = px.bar(
            df_span,
            x="tactic_span",
            y="owasp_name",
            orientation="h",
            color="tactic_span",
            color_continuous_scale=[[0, "#1a1d2e"], [0.5, "#7209b7"], [1, "#4cc9f0"]],
            text="tactic_span",
            labels={"tactic_span": "Tactics Spanned", "owasp_name": "OWASP Risk"},
            height=380,
        )
        fig_span.update_traces(textposition="outside")
        fig_span = dark_layout(
            fig_span,
            coloraxis_showscale=False,
            margin={"l": 0, "r": 50, "t": 20, "b": 40},
        )
        st.plotly_chart(fig_span, use_container_width=True)
        st.divider()

    risk_options = {f"{r['id']} — {r['name']}": r["id"] for r in all_risks}
    selected_risk_label = st.selectbox("Select an OWASP Risk", list(risk_options.keys()))
    owasp_id = risk_options[selected_risk_label]
    
    st.divider()

    # Load context
    with st.spinner("Querying graph..."):
        tactic_summary = cached_owasp_risk_tactic_summary(driver, owasp_id)
        full_context = cached_owasp_risk_full_context(driver, owasp_id)

    if not tactic_summary:
        st.info("This OWASP risk currently has no corresponding ATLAS mappings.")
        st.stop()

    section_header("Adversary Tactics Spanned")
    st.caption("Shows the distinct adversary goals this vulnerability enables across the ATLAS lifecycle:")
    
    # Show metric cards for each tactic
    cols = st.columns(min(len(tactic_summary), 4))
    for i, row in enumerate(tactic_summary):
        with cols[i % len(cols)]:
            st.markdown(
                f"""<div class="metric-card accent-purple">
<div class="label" style="font-size: 0.70rem;">{row['tactic_name']}</div>
<div class="value" style="font-size: 1.4rem;">{row['technique_count']}</div>
<div class="sub">Techniques associated</div>
</div>""",
                unsafe_allow_html=True,
            )
            st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
            
    st.divider()
    section_header(f"Technique Trace ({len(full_context)} Mappings)")
    
    if full_context:
        df = pd.DataFrame(full_context)
        df["tactics"] = df["tactics"].apply(lambda x: ", ".join(x) if x else "—")
        df["mitigations"] = df["mitigations"].apply(lambda x: " · ".join(x) if x else "—")
        df["case_studies"] = df["case_studies"].apply(lambda x: len(x) if x else 0)
        
        # Select and rename columns for display
        display_df = df[["technique_id", "technique_name", "tactics", "mitigations", "case_studies"]].copy()
        display_df.columns = ["Technique ID", "Name", "Tactic", "Mitigations", "Incidents"]
        
        st.dataframe(display_df, use_container_width=True, hide_index=True)
    else:
        st.info("No detailed technique trace found.")
