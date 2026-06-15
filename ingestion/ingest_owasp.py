"""
ingest_owasp.py — Load OWASP LLM Top 10 (2025) enrichment into the ATLAS Neo4j graph.

Run AFTER ingest.py (--reset). This script is purely additive — it never
calls .reset(), so existing ATLAS nodes and relationships are untouched.

Creates:
  (:OwaspRisk {id, name, description})  — 10 nodes, one per OWASP risk
  (OwaspRisk)-[:CORRESPONDS_TO {rationale}]->(Technique|SubTechnique)
                                            — edges for non-empty mappings

Usage:
  python ingestion/ingest_owasp.py \\
      data/owasp_llm_top10_2025.yaml \\
      data/owasp_atlas_mapping.yaml \\
      [--uri bolt://localhost:7687] [--user neo4j] [--password atlaspassword]
"""

import argparse
import os
import sys

import yaml
from neo4j import GraphDatabase


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_yaml(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# OwaspIngester
# ---------------------------------------------------------------------------

class OwaspIngester:
    def __init__(self, uri: str, user: str, password: str):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def _run(self, query: str, **params):
        with self.driver.session() as session:
            session.run(query, **params)

    def create_constraint(self):
        self._run(
            "CREATE CONSTRAINT IF NOT EXISTS FOR (o:OwaspRisk) REQUIRE o.id IS UNIQUE"
        )

    def load_owasp_risks(self, risks: list[dict]) -> None:
        """MERGE OwaspRisk nodes."""
        query = """
        UNWIND $rows AS row
        MERGE (o:OwaspRisk {id: row.id})
        SET o.name        = row.name,
            o.description = row.description
        """
        rows = [
            {
                "id": r["id"],
                "name": r["name"],
                "description": (r.get("description") or "").strip(),
            }
            for r in risks
        ]
        self._run(query, rows=rows)
        print(f"  loaded {len(rows)} OwaspRisk nodes")

    def load_mappings(self, mappings: list[dict]) -> None:
        """
        Create CORRESPONDS_TO edges for non-empty atlas_id lists.
        
        Semantic Meaning of CORRESPONDS_TO:
        This relationship indicates that the source OWASP outcome category (e.g., Sensitive 
        Information Disclosure) can be achieved via the target ATLAS attack mechanism
        (e.g., LLM Data Leakage or Model Inversion). It maps the 'what goes wrong' (OWASP) 
        to the 'how it is technically executed' (ATLAS).
        """
        edge_count = 0
        no_edge_count = 0

        for m in mappings:
            owasp_id = m["owasp_id"]
            atlas_ids = m.get("atlas_ids") or []
            rationale = (m.get("rationale") or "").strip()

            if not atlas_ids:
                no_edge_count += 1
                print(f"  {owasp_id}: no ATLAS counterpart — node created, no edges")
                continue

            query = """
            UNWIND $atlas_ids AS tech_id
            MATCH (o:OwaspRisk {id: $owasp_id})
            MATCH (t {id: tech_id})
            WHERE t:Technique OR t:SubTechnique
            MERGE (o)-[r:CORRESPONDS_TO]->(t)
            SET r.rationale = $rationale
            """
            self._run(query, owasp_id=owasp_id, atlas_ids=atlas_ids, rationale=rationale)
            edge_count += len(atlas_ids)
            print(f"  {owasp_id}: {len(atlas_ids)} CORRESPONDS_TO edge(s) created")

        print(
            f"  total: {edge_count} CORRESPONDS_TO edge(s), "
            f"{no_edge_count} risk(s) with no edges"
        )


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Ingest OWASP LLM Top 10 (2025) enrichment into the ATLAS Neo4j graph"
    )
    parser.add_argument(
        "owasp_yaml",
        default=os.path.join(os.path.dirname(__file__), "..", "data", "owasp_llm_top10_2025.yaml"),
        nargs="?",
        help="Path to owasp_llm_top10_2025.yaml (default: data/owasp_llm_top10_2025.yaml)",
    )
    parser.add_argument(
        "mapping_yaml",
        default=os.path.join(os.path.dirname(__file__), "..", "data", "owasp_atlas_mapping.yaml"),
        nargs="?",
        help="Path to owasp_atlas_mapping.yaml (default: data/owasp_atlas_mapping.yaml)",
    )
    parser.add_argument("--uri", default="bolt://localhost:7687")
    parser.add_argument("--user", default="neo4j")
    parser.add_argument("--password", default="atlaspassword")
    args = parser.parse_args()

    print(f"Loading OWASP risks from {args.owasp_yaml} ...")
    owasp_data = load_yaml(args.owasp_yaml)
    risks = owasp_data.get("owasp_llm_top10") or []

    print(f"Loading ATLAS mappings from {args.mapping_yaml} ...")
    mapping_data = load_yaml(args.mapping_yaml)
    mappings = mapping_data.get("mappings") or []

    print(f"Found {len(risks)} OWASP risks, {len(mappings)} mapping entries")

    ingester = OwaspIngester(args.uri, args.user, args.password)
    try:
        print("Creating OwaspRisk constraint...")
        ingester.create_constraint()

        print("Loading OwaspRisk nodes...")
        ingester.load_owasp_risks(risks)

        print("Loading CORRESPONDS_TO edges...")
        ingester.load_mappings(mappings)

        print("Done.")
    finally:
        ingester.close()


if __name__ == "__main__":
    sys.exit(main())
