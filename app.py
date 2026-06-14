"""
app.py — Streamlit interface for the MITRE ATLAS knowledge graph.
Run with: streamlit run app.py
"""

import json
import os
import sys

import pandas as pd
import plotly.express as px
import streamlit as st
from neo4j import GraphDatabase

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "queries"))
import assess

import queries

# ── Page config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="MITRE ATLAS Explorer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
/* metric card accent border */
div[data-testid="metric-container"] {
    background: #1a1d2e;
    border-radius: 8px;
    padding: 16px 20px;
    border-left: 3px solid #4cc9f0;
}
/* rel metric — red accent */
div[data-testid="metric-container"].rel-metric {
    border-left-color: #e63946;
}
/* tighten sidebar nav spacing */
div[data-testid="stRadio"] label { font-size: 0.95rem; }

/* expander header */
details summary { font-weight: 500; }

footer { visibility: hidden; }
</style>
""",
    unsafe_allow_html=True,
)

# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## 🛡️ ATLAS Explorer")
    st.caption("MITRE ATLAS Knowledge Graph")
    st.divider()

    page = st.radio(
        "nav",
        [
            "🏠  Overview",
            "🔍  Platform Explorer",
            "🎯  Technique Inspector",
            "🛡️  Coverage Analysis",
            "📊  Tactic Overview",
            "🤖  Threat Assessment",
        ],
        label_visibility="collapsed",
    )

    st.divider()

    with st.expander("⚙️  Neo4j connection"):
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
        st.success("Connected", icon="🟢")
    else:
        st.error("Cannot reach Neo4j", icon="🔴")
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
        ]:
            counts[label] = s.run(f"MATCH (n:{label}) RETURN count(n) AS c").single()[
                "c"
            ]
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


# ── Plotly theme helper ───────────────────────────────────────────────────────


def apply_dark_layout(fig, **kwargs):
    fig.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font_color="#e8eaf6",
        **kwargs,
    )
    return fig


# ── Pages ─────────────────────────────────────────────────────────────────────

# ─── Overview ─────────────────────────────────────────────────────────────────
if page == "🏠  Overview":
    st.title("MITRE ATLAS Knowledge Graph")
    st.markdown(
        "Adversarial Threat Landscape for AI Systems — a structured knowledge base of "
        "tactics, techniques, mitigations, and real-world incidents targeting AI and ML systems, "
        "loaded into Neo4j for graph-powered analysis."
    )
    st.divider()

    stats = get_stats(driver)
    rels = stats.get("rels", {})

    st.subheader("Nodes")
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Tactics", stats["Tactic"])
    c2.metric("Techniques", stats["Technique"])
    c3.metric("Sub-techniques", stats["SubTechnique"])
    c4.metric("Mitigations", stats["Mitigation"])
    c5.metric("Case Studies", stats["CaseStudy"])
    c6.metric("Platforms", stats["Platform"])

    st.subheader("Relationships")
    r1, r2, r3, r4, r5, r6 = st.columns(6)
    r1.metric("BELONGS_TO", rels.get("BELONGS_TO", 0))
    r2.metric("SUBTECHNIQUE_OF", rels.get("SUBTECHNIQUE_OF", 0))
    r3.metric("TARGETS", rels.get("TARGETS", 0))
    r4.metric("MITIGATED_BY", rels.get("MITIGATED_BY", 0))
    r5.metric("EMPLOYS", rels.get("EMPLOYS", 0))
    r6.metric("FOLLOWED_BY", rels.get("FOLLOWED_BY", 0))

    st.divider()
    st.subheader("Pages")

    col_l, col_r = st.columns(2)
    with col_l:
        st.info(
            "**🔍 Platform Explorer**  \n"
            "Browse all techniques targeting a platform and get a full threat profile "
            "with mitigations and real-world incident counts."
        )
        st.info(
            "**🎯 Technique Inspector**  \n"
            "Pick any technique to explore its mitigations by lifecycle phase, "
            "downstream attack chains, and documented case studies."
        )
    with col_r:
        st.info(
            "**🛡️ Coverage Analysis**  \n"
            "Identify techniques with no mitigation and see which mitigations "
            "give the broadest coverage across the framework."
        )
        st.info(
            "**📊 Tactic Overview**  \n"
            "Compare technique counts vs. real-world incident counts per tactic "
            "with an interactive grouped bar chart."
        )

# ─── Platform Explorer ────────────────────────────────────────────────────────
elif page == "🔍  Platform Explorer":
    st.title("🔍 Platform Explorer")

    platforms = get_platforms(driver)
    if not platforms:
        st.warning("No platform nodes found in the graph.")
        st.stop()

    platform = st.selectbox("Platform", platforms)
    st.divider()

    # Q1
    st.subheader(f"Techniques targeting **{platform}**")
    rows = cached_techniques_by_platform(driver, platform)

    if rows:
        df = pd.DataFrame(rows)
        df["tactics"] = df["tactics"].apply(lambda x: ", ".join(x) if x else "—")
        df.columns = ["ID", "Technique", "Tactics"]
        st.dataframe(df, use_container_width=True, hide_index=True)
        st.caption(f"{len(rows)} technique(s)")
    else:
        st.info("No techniques found for this platform.")

    st.divider()

    # Q8
    st.subheader(f"Threat profile — **{platform}**")
    st.caption("Sorted by number of documented real-world incidents (highest first)")

    profile = cached_threat_profile(driver, platform)

    if not profile:
        st.info("No threat profile data available.")
    else:
        for row in profile:
            inc = row["real_world_incidents"]
            mits = row["mitigations"] or []
            inc_color = "🔴" if inc > 2 else ("🟡" if inc > 0 else "⚪")

            with st.container(border=True):
                left, mid, r1, r2 = st.columns([4, 2, 1, 1])
                left.markdown(f"**{row['technique_name']}**  \n`{row['technique_id']}`")
                mid.markdown(
                    f"<br><small><i>{row['tactic'] or '—'}</i></small>",
                    unsafe_allow_html=True,
                )
                r1.metric("Mitigations", len(mits))
                r2.metric("Incidents", f"{inc_color} {inc}")

                if mits:
                    st.markdown(
                        " ".join(f"`{m}`" for m in mits),
                        help="Documented mitigations for this technique",
                    )

# ─── Technique Inspector ──────────────────────────────────────────────────────
elif page == "🎯  Technique Inspector":
    st.title("🎯 Technique Inspector")

    options = get_technique_options(driver)
    if not options:
        st.warning("No techniques found in the graph.")
        st.stop()

    selected = st.selectbox("Search technique by ID or name", list(options.keys()))
    tid = options[selected]

    st.divider()

    tab_mit, tab_chain, tab_cs = st.tabs(
        ["🛡️  Mitigations", "⛓️  Attack Chain", "📋  Case Studies"]
    )

    with tab_mit:
        st.subheader("Mitigations")
        mits = cached_mitigations_for(driver, tid)

        if not mits:
            st.info("No mitigations documented for this technique.")
        else:
            st.caption(f"{len(mits)} mitigation(s) found")
            for m in mits:
                with st.expander(
                    f"**{m['mitigation_name']}**  —  `{m['mitigation_id']}`"
                ):
                    if m["category"]:
                        st.markdown(f"**Category:** {m['category']}")
                    phases = m["lifecycle_phases"] or []
                    if phases:
                        st.markdown("**Lifecycle phases:**")
                        st.markdown("  " + "  ·  ".join(f"`{p}`" for p in phases))

    with tab_chain:
        st.subheader("Attack Chain")
        st.caption(
            "Techniques commonly observed after this one, derived from case study step sequences"
        )

        chains = cached_attack_chain(driver, tid)

        if not chains:
            st.info("No downstream attack sequences found for this technique.")
        else:
            # Build unique chains, longest first
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
                        f'<span style="background:#1a1d2e;border:1px solid {color};'
                        f'border-radius:6px;padding:4px 10px;font-size:0.85rem;color:{color}">'
                        f"{name}</span>"
                    )
                arrow = ' <span style="color:#555;font-size:1.1rem">→</span> '
                st.markdown(arrow.join(parts), unsafe_allow_html=True)
                st.markdown("")

    with tab_cs:
        st.subheader("Case Studies")
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
elif page == "🛡️  Coverage Analysis":
    st.title("🛡️ Coverage Analysis")

    tab_gaps, tab_top = st.tabs(
        ["⚠️  Unmitigated Techniques", "📈  Mitigation Coverage"]
    )

    with tab_gaps:
        st.subheader("Techniques with no documented mitigation")

        platforms = get_platforms(driver)
        plat_filter = st.selectbox("Filter by platform", ["All platforms"] + platforms)
        plat = None if plat_filter == "All platforms" else plat_filter

        gaps = cached_gaps(driver, plat)

        if not gaps:
            st.success(
                "✅ Every technique in this selection has at least one mitigation."
            )
        else:
            st.error(
                f"⚠️  {len(gaps)} technique(s) have no documented mitigation", icon="⚠️"
            )
            df = pd.DataFrame(gaps)
            df.columns = ["ID", "Technique"]
            st.dataframe(df, use_container_width=True, hide_index=True)

    with tab_top:
        st.subheader("Which mitigations cover the most techniques?")
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
                color_continuous_scale=[[0, "#1a1d2e"], [1, "#4cc9f0"]],
                text="Covered",
                height=max(420, top_n * 38),
            )
            fig.update_traces(textposition="outside")
            fig = apply_dark_layout(
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

# ─── Threat Assessment ───────────────────────────────────────────────────────
elif page == "🤖  Threat Assessment":
    st.title("🤖 Threat Assessment")
    st.markdown(
        "Describe your AI system in plain English. "
        "The model reads the live ATLAS catalogue from Neo4j and returns "
        "the most relevant techniques with risk ratings and reasoning."
    )
    st.divider()

    with st.sidebar:
        st.divider()
        groq_key = st.text_input(
            "🔑 Groq API key",
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

    if st.button("Run assessment", type="primary", disabled=not system_desc.strip()):
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
            summary = result.get("summary", "")

            # summary banner
            st.subheader("Overall risk summary")
            st.info(summary)
            st.divider()

            # technique cards
            st.subheader(f"Relevant techniques ({len(techniques)})")
            risk_color = {"high": "🔴", "medium": "🟡", "low": "🟢"}

            for t in techniques:
                risk = (t.get("risk") or "medium").lower()
                badge = risk_color.get(risk, "⚪")
                with st.container(border=True):
                    left, right = st.columns([5, 1])
                    left.markdown(
                        f"{badge} **{t.get('name', '—')}** &nbsp; `{t.get('id', '—')}`  \n"
                        f"<small><i>{t.get('tactic', '—')}</i></small>",
                        unsafe_allow_html=True,
                    )
                    right.markdown(
                        f"<br><b style='color:{'#e63946' if risk == 'high' else '#f4d03f' if risk == 'medium' else '#06d6a0'}'>"
                        f"{risk.upper()}</b>",
                        unsafe_allow_html=True,
                    )
                    st.markdown(t.get("reason", ""))

            # JSON download
            st.divider()
            st.download_button(
                "Download JSON",
                data=__import__("json").dumps(result, indent=2),
                file_name="atlas_assessment.json",
                mime="application/json",
            )

# ─── Tactic Overview ──────────────────────────────────────────────────────────
elif page == "📊  Tactic Overview":
    st.title("📊 Tactic Overview")
    st.caption("Technique count vs. documented real-world incidents per tactic")

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
        fig = apply_dark_layout(
            fig,
            xaxis_tickangle=-30,
            legend_title="",
            bargap=0.2,
            margin={"l": 10, "r": 10, "t": 20, "b": 120},
        )
        st.plotly_chart(fig, use_container_width=True)

        st.divider()

        # Summary stats
        total_techniques = df["Techniques"].sum()
        total_incidents = df["Incidents"].sum()
        most_techniques = df.loc[df["Techniques"].idxmax(), "Tactic"]
        most_incidents = df.loc[df["Incidents"].idxmax(), "Tactic"]

        s1, s2, s3, s4 = st.columns(4)
        s1.metric("Total techniques", total_techniques)
        s2.metric("Total incidents", total_incidents)
        s3.metric("Most techniques", most_techniques)
        s4.metric("Most incidents", most_incidents)

        st.divider()
        st.dataframe(df, use_container_width=True, hide_index=True)
