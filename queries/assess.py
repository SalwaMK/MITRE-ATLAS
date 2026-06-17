"""
assess.py — LLM-powered ATLAS threat assessment via Groq.

Usage:
    from neo4j import GraphDatabase
    from assess import assess_threat

    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "atlaspassword"))

    result = assess_threat(
        "A RAG chatbot with tool access that reads customer emails.",
        driver=driver,
    )
    for t in result["techniques"]:
        print(t["id"], t["risk"].upper(), "-", t["name"])
    print(result["summary"])

    driver.close()

Set GROQ_API_KEY in your environment, or pass api_key= directly.
"""

import json
import os
from typing import Optional

from groq import Groq

_SYSTEM_PROMPT_STEP_1 = """\
You are an AI security expert. Your task is to identify MITRE ATLAS techniques relevant to a GIVEN AI SYSTEM.

CRITICAL RULES:
1. ONLY select IDs that are present in the provided catalogue. 
2. IF the system description is NOT related to AI, Machine Learning, or LLMs (e.g., a static website, a basic calculator, a recipe), you MUST return an empty list: {"candidate_ids": []}.
3. Do NOT select techniques for generic web vulnerabilities (like XSS or SQLi) unless they are specifically listed in the ATLAS catalogue with those IDs.
4. If a technique is only marginally relevant, OMIT IT.

Return ONLY valid JSON: {"candidate_ids": ["AML.T0000", ...]}
"""

_SYSTEM_PROMPT_STEP_2 = """\
You are an AI security expert. Analyze the AI system and the provided ATLAS techniques.

Rules:
- Only reference techniques provided in the context.
- Use the EXACT names and IDs from the context. Do NOT invent new names or meanings for IDs.
- Write 1-2 sentences of specific reasoning: how does this attack apply to THIS specific AI system?
- If a technique is not truly applicable to the system description, OMIT IT.
- If no techniques are applicable, return an empty list for "techniques".
- Return valid JSON only.

Output schema:
{
  "techniques": [
    {
      "id":     "AML.T0051",
      "name":   "LLM Prompt Injection",
      "tactic": "AI Attack Staging",
      "risk":   "high",
      "reason": "The system exposes a user-facing prompt interface ..."
    }
  ],
  "summary": "One paragraph overall risk assessment."
}
risk values: high | medium | low
"""

def _context_from_graph_short(driver) -> str:
    """Pull the live technique catalogue list from Neo4j, without descriptions."""
    with driver.session() as s:
        rows = s.run("""
            MATCH (t)-[:BELONGS_TO]->(ta:Tactic)
            WHERE t:Technique OR t:SubTechnique
            RETURN t.id AS id, t.name AS name, ta.name AS tactic
            ORDER BY ta.name, t.id
        """).data()

    lines: list[str] = []
    current = None
    for row in rows:
        if row["tactic"] != current:
            current = row["tactic"]
            lines.append(f"\n[{current}]")
        lines.append(f"  {row['id']}: {row['name']}")
    return "\n".join(lines)


def _get_detailed_techniques(driver, technique_ids: list[str]) -> str:
    """Fetch full descriptions for the specified technique IDs."""
    if not driver:
        # Fallback if no driver
        return "\n".join(f"- {tid}" for tid in technique_ids)
        
    with driver.session() as s:
        rows = s.run("""
            MATCH (t)
            WHERE (t:Technique OR t:SubTechnique) AND t.id IN $ids
            RETURN t.id AS id, t.name AS name, t.description AS description
        """, ids=technique_ids).data()
        
    lines = []
    for r in rows:
        desc = (r.get('description') or 'No description available.').strip()
        lines.append(f"ID: {r['id']}\nName: {r['name']}\nDescription: {desc}\n")
    return "\n".join(lines)


def assess_threat(
    system_description: str,
    driver=None,
    api_key: Optional[str] = None,
    model: str = "llama-3.3-70b-versatile",
    max_techniques: int = 10,
) -> dict:
    """
    Generate a structured ATLAS threat assessment for an AI system using a 2-step RAG pipeline.
    """
    key = api_key or os.getenv("GROQ_API_KEY")
    if not key:
        raise ValueError("Groq API key required. Pass api_key= or set GROQ_API_KEY.")

    client = Groq(api_key=key)
    
    # ── Step 1: Candidate Selection ────────────────────────────────────────────────────────
    catalogue_short = _context_from_graph_short(driver) if driver else _BUILTIN_CATALOGUE
    user_msg_1 = (
        f"ATLAS technique catalogue:\n{catalogue_short}\n\n"
        f"System description:\n{system_description}\n\n"
        f"Select up to {max_techniques} relevant technique IDs.\n"
    )

    resp_1 = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT_STEP_1},
            {"role": "user", "content": user_msg_1},
        ],
        temperature=0.1,
        response_format={"type": "json_object"},
    )
    
    try:
        candidates = json.loads(resp_1.choices[0].message.content).get("candidate_ids", [])
    except Exception:
        candidates = []
        
    if not candidates:
        return {"techniques": [], "summary": "No relevant techniques identified."}

    # ── Step 2: Detailed Assessment ────────────────────────────────────────────────────────
    detailed_context = _get_detailed_techniques(driver, candidates)
    user_msg_2 = (
        f"Candidate Techniques Context:\n{detailed_context}\n\n"
        f"System description:\n{system_description}\n\n"
        f"Requirement: Return ONLY the relevant techniques for this system (maximum {max_techniques}). "
        "If a technique in the context is not relevant to the description, OMIT IT. "
        "Do not invent new techniques."
    )
    
    resp_2 = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT_STEP_2},
            {"role": "user", "content": user_msg_2},
        ],
        temperature=0.2,
        response_format={"type": "json_object"},
    )

    return json.loads(resp_2.choices[0].message.content)


# Built-in fallback catalogue — used when no Neo4j driver is provided.
# Covers the most commonly applicable ATLAS techniques across all tactics.
_BUILTIN_CATALOGUE = """
[Reconnaissance]
  AML.T0000: Search Open Technical Databases
  AML.T0000.000: Journals and Conference Proceedings
  AML.T0000.001: Pre-Print Repositories
  AML.T0000.002: Technical Blogs
  AML.T0001: Search Open AI Vulnerability Analysis
  AML.T0003: Search Victim-Owned Websites
  AML.T0004: Search Application Repositories
  AML.T0006: Active Scanning
  AML.T0064: Gather RAG-Indexed Targets
  AML.T0087: Gather Victim Identity Information
  AML.T0095: Search Open Websites/Domains
  AML.T0095.000: Code Repositories

[Resource Development]
  AML.T0002: Acquire Public AI Artifacts
  AML.T0002.000: Datasets
  AML.T0002.001: Models
  AML.T0002.002: AI Agent Configuration
  AML.T0008: Acquire Infrastructure
  AML.T0016: Obtain Capabilities
  AML.T0017: Develop Capabilities
  AML.T0017.000: Adversarial AI Attacks
  AML.T0019: Publish Poisoned Datasets
  AML.T0020: Poison Training Data
  AML.T0058: Publish Poisoned Models
  AML.T0060: Publish Hallucinated Entities
  AML.T0065: LLM Prompt Crafting
  AML.T0066: Retrieval Content Crafting
  AML.T0104: Publish Poisoned AI Agent Tool

[AI Model Access]
  AML.T0040: AI Model Inference API Access
  AML.T0041: Physical Environment Access
  AML.T0044: Full AI Model Access
  AML.T0047: AI-Enabled Product or Service

[Initial Access]
  AML.T0010: AI Supply Chain Compromise
  AML.T0010.001: AI Software
  AML.T0010.002: Data
  AML.T0010.003: Model
  AML.T0010.005: AI Agent Tool
  AML.T0012: Valid Accounts
  AML.T0049: Exploit Public-Facing Application
  AML.T0052: Phishing
  AML.T0052.000: Spearphishing via Social Engineering LLM

[AI Attack Staging]
  AML.T0005: Create Proxy AI Model
  AML.T0018: Manipulate AI Model
  AML.T0018.000: Poison AI Model
  AML.T0042: Verify Attack
  AML.T0043: Craft Adversarial Data
  AML.T0043.000: White-Box Optimization
  AML.T0043.001: Black-Box Optimization
  AML.T0043.003: Manual Modification
  AML.T0043.004: Insert Backdoor Trigger
  AML.T0088: Generate Deepfakes
  AML.T0102: Generate Malicious Commands

[Defense Evasion]
  AML.T0015: Evade AI Model
  AML.T0015.000: White-Box Evasion
  AML.T0015.001: Black-Box Evasion
  AML.T0015.002: Physical Evasion
  AML.T0015.003: Digital Evasion
  AML.T0068: Evade AI Safety Guardrails
  AML.T0068.000: Prompt Injection
  AML.T0068.001: Prompt Injection via External Content
  AML.T0068.002: Jailbreak
  AML.T0068.003: Virtualization

[Exfiltration]
  AML.T0024: Exfiltration via AI Inference API
  AML.T0024.000: Invert AI Model
  AML.T0024.001: Extract AI Model
  AML.T0024.002: Membership Inference
  AML.T0037: Exfiltrate via AI Agent Tool

[Impact]
  AML.T0029: Denial of AI Service
  AML.T0031: AI Model Erosion via Training Data Injection
  AML.T0048: AI Model Skewing
  AML.T0048.000: Influence Operations
  AML.T0048.001: Financial Fraud
  AML.T0048.002: AI-Enabled Disinformation
"""
