"""
validate.py — Run all 8 example queries and print results.
Also doubles as a smoke test for the ingestion.

Usage (real Neo4j):  python validate.py path/to/ATLAS.yaml
Usage (no Docker):   python validate.py ../data/ATLAS_sample.yaml --mock
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "ingestion"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("yaml_path")
    parser.add_argument("--uri", default="bolt://localhost:7687")
    parser.add_argument("--user", default="neo4j")
    parser.add_argument("--password", default="atlaspassword")
    parser.add_argument(
        "--mock", action="store_true", help="Use in-memory mock instead of real Neo4j"
    )
    args = parser.parse_args()

    if args.mock:
        import mock_neo4j as neo4j_module

        sys.modules["neo4j"] = neo4j_module
    else:
        import neo4j as neo4j_module  # noqa: F401

    import ingest

    import queries

    data = ingest.load_atlas_yaml(args.yaml_path)
    sections = ingest.get_sections(data)

    tactics = sections["tactics"]
    techniques = sections["techniques"]
    mitigations = sections["mitigations"]
    case_studies = sections["case_studies"]
    relationships = sections["relationships"]
    fmt = sections["format"]

    GraphDatabase = neo4j_module.GraphDatabase
    driver = GraphDatabase.driver(args.uri, auth=(args.user, args.password))

    ingester = ingest.AtlasIngester(args.uri, args.user, args.password)
    ingester.reset()
    ingester.create_constraints()
    ingester.load_tactics(tactics)
    ingester.load_techniques_and_subtechniques(techniques, relationships, fmt)
    ingester.load_mitigations(mitigations)
    ingester.load_mitigation_edges(relationships, mitigations, fmt)
    ingester.load_case_studies(case_studies, relationships, fmt)
    ingester.load_sequences(relationships, fmt)
    ingester.close()

    print("\n" + "=" * 70)
    print("Q1. Which techniques target Generative AI systems?")
    print("=" * 70)
    for row in queries.techniques_by_platform(driver, "Generative AI"):
        print(
            f"  {row['technique_id']:<14} {row['technique_name']:<45} tactics={row['tactics']}"
        )

    print("\n" + "=" * 70)
    print("Q2. What mitigations exist for LLM Prompt Injection (AML.T0051),")
    print("    and at which lifecycle phase do they apply?")
    print("=" * 70)
    for row in queries.mitigations_for_technique(driver, "AML.T0051"):
        print(f"  {row['mitigation_id']:<10} {row['mitigation_name']:<50}")
        print(
            f"             category={row['category']}  lifecycle={row['lifecycle_phases']}"
        )

    print("\n" + "=" * 70)
    print("Q3. Coverage gap: which Generative-AI techniques have NO mitigation?")
    print("=" * 70)
    gaps = queries.techniques_without_mitigations(driver, platform="Generative AI")
    if gaps:
        for row in gaps:
            print(f"  {row['technique_id']:<14} {row['technique_name']}")
    else:
        print(
            "  (none — every Generative AI technique in this dataset has at least one mitigation)"
        )

    print("\n" + "=" * 70)
    print("Q4. Attack chain starting from 'Discover ML Artifacts' (AML.T0005)")
    print("=" * 70)
    for row in queries.attack_chain_from(driver, "AML.T0005", max_hops=3):
        print(f"  hops={row['hops']}  chain: {' -> '.join(row['chain_names'])}")

    print("\n" + "=" * 70)
    print("Q5. Real-world case studies that employed Indirect Prompt Injection")
    print("    (RAG) — AML.T0054, with documented procedure")
    print("=" * 70)
    for row in queries.case_studies_for_technique(driver, "AML.T0054"):
        print(
            f"  [{row['case_study_id']}] {row['case_study_name']} ({row['case_study_type']})"
        )
        print(f"     procedure: {row['procedure']}")

    print("\n" + "=" * 70)
    print("Q6. Which mitigations cover the most techniques? (prioritisation)")
    print("=" * 70)
    for row in queries.top_mitigations_by_coverage(driver, limit=5):
        print(
            f"  {row['mitigation_id']:<10} {row['mitigation_name']:<45} covers {row['techniques_covered']} technique(s)"
        )

    print("\n" + "=" * 70)
    print("Q7. Tactic overview: technique count + real incident count per tactic")
    print("=" * 70)
    for row in queries.tactic_overview(driver):
        print(
            f"  {row['tactic_id']:<14} {row['tactic_name']:<25} techniques={row['technique_count']:<3} incidents={row['incident_count']}"
        )

    print("\n" + "=" * 70)
    print("Q8. Full threat profile for a Generative AI system")
    print("    (technique, tactic, mitigations, # real incidents)")
    print("=" * 70)
    for row in queries.threat_profile(driver, "Generative AI"):
        print(
            f"  {row['technique_id']:<14} {row['technique_name']:<40} tactic={row['tactic']}"
        )
        print(
            f"     mitigations={row['mitigations']}  real_world_incidents={row['real_world_incidents']}"
        )

    # ------------------------------------------------------------------
    # OWASP LLM Top 10 enrichment (additive — runs after ATLAS ingestion)
    # ------------------------------------------------------------------
    import os as _os
    _root = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..")
    _owasp_yaml    = _os.path.join(_root, "data", "owasp_llm_top10_2025.yaml")
    _mapping_yaml  = _os.path.join(_root, "data", "owasp_atlas_mapping.yaml")

    sys.path.insert(0, _os.path.join(_root, "ingestion"))
    import ingest_owasp

    _owasp_data   = ingest_owasp.load_yaml(_owasp_yaml)
    _mapping_data = ingest_owasp.load_yaml(_mapping_yaml)
    _risks        = _owasp_data.get("owasp_llm_top10") or []
    _mappings     = _mapping_data.get("mappings") or []

    _owasp_ingester = ingest_owasp.OwaspIngester(args.uri, args.user, args.password)
    try:
        _owasp_ingester.create_constraint()
        _owasp_ingester.load_owasp_risks(_risks)
        _owasp_ingester.load_mappings(_mappings)
    finally:
        _owasp_ingester.close()

    print("\n" + "=" * 70)
    print("Q9. OWASP LLM01 (Prompt Injection) -> ATLAS techniques + mitigations + incidents")
    print("=" * 70)
    for row in queries.atlas_for_owasp_risk(driver, "LLM01:2025"):
        print(row)

    driver.close()
    print("\nAll queries executed successfully.")


if __name__ == "__main__":
    sys.exit(main())
