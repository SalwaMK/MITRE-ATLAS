"""
draft.py — Generate a formal, citable threat-modelling report via a 3-step LLM pipeline.

Pipeline:
  Step 1: Candidate technique selection  (IDs only)
  Step 2: Graph enrichment               (fetch descriptions, mitigations, case studies)
  Step 3: Report drafting                (LLM writes structured Markdown with [AML.Txxxx] citations)

Usage:
    from neo4j import GraphDatabase
    from draft import draft_report

    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "atlaspassword"))
    report = draft_report("A RAG chatbot with CRM tool access...", driver=driver)
    print(report["markdown"])
    driver.close()
"""

import json
import os
import re
import time
from io import BytesIO
from typing import Optional

from fpdf import FPDF
from groq import Groq


def retry_on_connection(max_retries=3, delay=2):
    def decorator(func):
        def wrapper(*args, **kwargs):
            last_err = None
            for i in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if "connection" in str(e).lower() or "timeout" in str(e).lower():
                        last_err = e
                        time.sleep(delay * (i + 1))
                        continue
                    raise e
            raise last_err
        return wrapper
    return decorator


def markdown_to_pdf(markdown_text: str) -> bytes:
    """Convert a Markdown string to a PDF byte string via fpdf2."""
    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    # Use slightly smaller margins to be safe
    pdf.set_margins(15, 15, 15)
    
    # We use a standard width of 180mm for content on A4 (210 - 15 - 15)
    w = 180

    for line in markdown_text.splitlines():
        # Headings
        if line.startswith("### "):
            pdf.set_font("Helvetica", "B", 12)
            pdf.multi_cell(w, 7, line[4:].strip())
            pdf.ln(1)
        elif line.startswith("## "):
            pdf.set_font("Helvetica", "B", 14)
            pdf.multi_cell(w, 8, line[3:].strip())
            pdf.ln(2)
        elif line.startswith("# "):
            pdf.set_font("Helvetica", "B", 16)
            pdf.multi_cell(w, 10, line[2:].strip())
            pdf.ln(3)
        elif line.startswith("---") or line.startswith("==="):
            pdf.ln(2)
        elif line.strip() == "":
            pdf.ln(3)
        else:
            # Strip inline markdown (* _ ` ~)
            clean = re.sub(r"[*_`~]+", "", line)
            # Strip links [text](url) -> text
            clean = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", clean)
            
            bullet = clean.startswith("- ") or clean.startswith("* ")
            if bullet:
                # Use a simple dash instead of Unicode bullet to avoid font issues 
                # unless we embed a Unicode-capable font.
                clean = "  - " + clean[2:]
            
            pdf.set_font("Helvetica", "", 10)
            # Use explicit width instead of 0 to avoid "Not enough space" math bugs in some fpdf2 versions
            pdf.multi_cell(w, 6, clean)

    return pdf.output()


# ── Step 1 system prompt ──────────────────────────────────────────────────────

_STEP1_SYSTEM = """\
You are a cybersecurity expert specialising in threats to AI/ML systems (MITRE ATLAS).
Given a system description and the full ATLAS technique catalogue, select up to 15
technique IDs most relevant to this system.
Return ONLY valid JSON: {"candidate_ids": ["AML.T0000", ...]}
"""

# ── Step 3 system prompt ──────────────────────────────────────────────────────

_STEP3_SYSTEM = """\
You are a senior cybersecurity consultant. Write a formal threat-modelling report in
Markdown for the described AI system.

Rules:
- Use ONLY the techniques, mitigations, and case studies supplied in the context.
- Cite every technique as [AML.Txxxx] immediately after each claim.
- Cite every mitigation as [AML.Mxxxx] and every case study as [AML.CSxxxx].
- DO NOT invent IDs, names, or descriptions not present in the context.
- Use professional, concise prose. Avoid bullet-point padding.

Report structure (use these exact Markdown headings):
## Executive Summary
## System Overview
## Identified Threats
### <Technique Name> [AML.Txxxx]
(one subsection per technique, with: tactic, risk level, reasoning, relevant case studies)
## Mitigation Recommendations
## Coverage Gaps
## References
(list every cited node with its full name and one-line description)
"""


# ── Graph helpers ─────────────────────────────────────────────────────────────

def _catalogue_short(driver) -> str:
    """Return id+name catalogue for Step 1 candidate selection."""
    with driver.session() as s:
        rows = s.run("""
            MATCH (t)-[:BELONGS_TO]->(ta:Tactic)
            WHERE t:Technique OR t:SubTechnique
            RETURN t.id AS id, t.name AS name, ta.name AS tactic
            ORDER BY ta.name, t.id
        """).data()
    lines, current = [], None
    for r in rows:
        if r["tactic"] != current:
            current = r["tactic"]
            lines.append(f"\n[{current}]")
        lines.append(f"  {r['id']}: {r['name']}")
    return "\n".join(lines)


def _enrich_techniques(driver, ids: list[str]) -> list[dict]:
    """Fetch full descriptions for each candidate technique."""
    with driver.session() as s:
        rows = s.run("""
            MATCH (t)-[:BELONGS_TO]->(ta:Tactic)
            WHERE (t:Technique OR t:SubTechnique) AND t.id IN $ids
            RETURN t.id AS id, t.name AS name,
                   t.description AS description, ta.name AS tactic
        """, ids=ids).data()
    return rows


def _mitigations_for(driver, ids: list[str]) -> dict[str, list[dict]]:
    """Return {technique_id: [{mit_id, mit_name, mit_description}]} for each id."""
    with driver.session() as s:
        rows = s.run("""
            MATCH (t)-[:MITIGATED_BY]->(m:Mitigation)
            WHERE t.id IN $ids
            RETURN t.id AS tid, m.id AS mid, m.name AS mname,
                   m.description AS mdesc
        """, ids=ids).data()
    result: dict[str, list[dict]] = {}
    for r in rows:
        result.setdefault(r["tid"], []).append({
            "id": r["mid"], "name": r["mname"],
            "description": (r["mdesc"] or "").strip()[:200],
        })
    return result


def _case_studies_for(driver, ids: list[str]) -> dict[str, list[dict]]:
    """Return {technique_id: [{cs_id, cs_name, procedure}]} for each id."""
    with driver.session() as s:
        rows = s.run("""
            MATCH (c:CaseStudy)-[e:EMPLOYS]->(t)
            WHERE t.id IN $ids
            RETURN t.id AS tid, c.id AS cs_id, c.name AS cs_name,
                   e.procedure AS procedure
        """, ids=ids).data()
    result: dict[str, list[dict]] = {}
    for r in rows:
        result.setdefault(r["tid"], []).append({
            "id": r["cs_id"], "name": r["cs_name"],
            "procedure": (r["procedure"] or "").strip()[:300],
        })
    return result


def _coverage_gaps(driver, ids: list[str]) -> list[str]:
    """Return technique IDs from the candidate list that have NO mitigation."""
    with driver.session() as s:
        rows = s.run("""
            MATCH (t)
            WHERE (t:Technique OR t:SubTechnique) AND t.id IN $ids
              AND NOT (t)-[:MITIGATED_BY]->(:Mitigation)
            RETURN t.id AS id
        """, ids=ids).data()
    return [r["id"] for r in rows]


# ── Context builder ───────────────────────────────────────────────────────────

def _build_context(
    techniques: list[dict],
    mitigations: dict[str, list[dict]],
    case_studies: dict[str, list[dict]],
    gaps: list[str],
) -> str:
    sections = []
    for t in techniques:
        tid = t["id"]
        block = [
            f"TECHNIQUE: {tid}: {t['name']}",
            f"  Tactic: {t['tactic']}",
            f"  Description: {(t.get('description') or 'N/A').strip()[:400]}",
        ]
        mits = mitigations.get(tid, [])
        if mits:
            block.append("  Mitigations:")
            for m in mits:
                block.append(f"    {m['id']}: {m['name']} — {m['description']}")
        cs_list = case_studies.get(tid, [])
        if cs_list:
            block.append("  Case Studies:")
            for cs in cs_list:
                block.append(f"    {cs['id']}: {cs['name']} | {cs['procedure'][:150]}")
        sections.append("\n".join(block))

    if gaps:
        sections.append("TECHNIQUES WITH NO MITIGATION: " + ", ".join(gaps))

    return "\n\n".join(sections)


# ── Public API ────────────────────────────────────────────────────────────────

def draft_report(
    system_description: str,
    driver=None,
    api_key: Optional[str] = None,
    model: str = "llama-3.3-70b-versatile",
    max_techniques: int = 10,
) -> dict:
    """
    Generate a formal Markdown threat-modelling report with graph citations.

    Returns:
        dict:
            "markdown"   — the full Markdown report (str)
            "techniques" — list of enriched technique dicts
            "mitigations"— dict {tid: [mit_dicts]}
            "case_studies"— dict {tid: [cs_dicts]}
            "gaps"       — list of technique IDs with no mitigation
    """
    key = api_key or os.getenv("GROQ_API_KEY")
    if not key:
        raise ValueError("Groq API key required. Set GROQ_API_KEY or pass api_key=.")

    client = Groq(api_key=key)

    # ── Step 1: Candidate selection ────────────────────────────────────────────
    catalogue = _catalogue_short(driver) if driver else ""
    @retry_on_connection()
    def _call_step1():
        return client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": _STEP1_SYSTEM},
                {"role": "user", "content": (
                    f"ATLAS catalogue:\n{catalogue}\n\n"
                    f"System description:\n{system_description}"
                )},
            ],
            temperature=0.1,
            response_format={"type": "json_object"},
        )

    resp1 = _call_step1()
    candidate_ids: list[str] = json.loads(
        resp1.choices[0].message.content
    ).get("candidate_ids", [])[:max_techniques]

    if not candidate_ids:
        return {
            "markdown": "# Threat Model Report\n\nNo relevant techniques identified.",
            "techniques": [], "mitigations": {}, "case_studies": {}, "gaps": [],
        }

    # ── Step 2: Graph enrichment ───────────────────────────────────────────────
    techniques = _enrich_techniques(driver, candidate_ids) if driver else []
    mitigations = _mitigations_for(driver, candidate_ids) if driver else {}
    case_studies = _case_studies_for(driver, candidate_ids) if driver else {}
    gaps = _coverage_gaps(driver, candidate_ids) if driver else []
    context = _build_context(techniques, mitigations, case_studies, gaps)

    # ── Step 3: Report drafting ────────────────────────────────────────────────
    @retry_on_connection()
    def _call_step3():
        return client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": _STEP3_SYSTEM},
                {"role": "user", "content": (
                    f"System description:\n{system_description}\n\n"
                    f"Graph context:\n{context}"
                )},
            ],
            temperature=0.3,
        )

    resp3 = _call_step3()
    markdown = resp3.choices[0].message.content.strip()

    return {
        "markdown": markdown,
        "techniques": techniques,
        "mitigations": mitigations,
        "case_studies": case_studies,
        "gaps": gaps,
    }
