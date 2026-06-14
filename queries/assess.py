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

_SYSTEM_PROMPT = """\
You are a cybersecurity expert specialising in threats to AI and ML systems,
using the MITRE ATLAS framework.

Given a plain-text description of an AI system, identify the most relevant
ATLAS techniques an adversary could use to attack it.

Rules:
- Only reference technique IDs that appear in the provided catalogue.
- Select techniques directly applicable to the described system architecture.
- Write 1–2 sentences of reasoning per technique.
- Return valid JSON only — no markdown fences, no preamble.

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


def _context_from_graph(driver) -> str:
    """Pull the live technique catalogue from Neo4j, grouped by tactic."""
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


def assess_threat(
    system_description: str,
    driver=None,
    api_key: Optional[str] = None,
    model: str = "llama-3.3-70b-versatile",
    max_techniques: int = 10,
) -> dict:
    """
    Generate a structured ATLAS threat assessment for an AI system.

    Args:
        system_description: Plain-text description of the system to assess.
        driver:             Neo4j driver (recommended). Pulls the full live
                            technique catalogue. Falls back to a built-in list
                            if omitted.
        api_key:            Groq API key. Falls back to GROQ_API_KEY env var.
        model:              Groq model ID.
        max_techniques:     How many techniques to return (max).

    Returns:
        dict:
            "techniques" — list of {id, name, tactic, risk, reason}
            "summary"    — overall risk narrative (str)
    """
    key = api_key or os.getenv("GROQ_API_KEY")
    if not key:
        raise ValueError("Groq API key required. Pass api_key= or set GROQ_API_KEY.")

    catalogue = _context_from_graph(driver) if driver else _BUILTIN_CATALOGUE

    user_msg = (
        f"ATLAS technique catalogue:\n{catalogue}\n\n"
        f"System description:\n{system_description}\n\n"
        f"Return the {max_techniques} most relevant techniques for this system."
    )

    client = Groq(api_key=key)
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        temperature=0.2,
        response_format={"type": "json_object"},
    )

    return json.loads(response.choices[0].message.content)


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
