"""
ingest.py — Load MITRE ATLAS data into Neo4j.

Supports ATLAS format-version 6.x (top-level ID-keyed dicts) and the
older matrices[0] list layout. Run with --reset to wipe the graph first.
"""

import argparse
import sys
from typing import Any

import yaml
from neo4j import GraphDatabase


def _first(d: dict, *keys: str, default: Any = None) -> Any:
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default


def load_atlas_yaml(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def get_matrix(data: dict) -> dict:
    """Return the first matrix dict (legacy format helper)."""
    if "matrices" in data and data["matrices"]:
        return data["matrices"][0]
    if "matrix" in data and isinstance(data["matrix"], dict):
        return data["matrix"]
    return data


def detect_format(data: dict) -> str:
    fv = str(data.get("format-version", ""))
    if fv.startswith("6.") or isinstance(data.get("tactics"), dict):
        return "v6"
    return "legacy"


def get_sections(data: dict) -> dict:
    """Normalise both ATLAS formats into flat lists plus a raw relationships dict."""
    fmt = detect_format(data)

    if fmt == "v6":
        tactics = list((data.get("tactics") or {}).values())
        techniques = list((data.get("techniques") or {}).values())
        mitigations = list((data.get("mitigations") or {}).values())
        case_studies = list((data.get("case-studies") or {}).values())
        relationships = data.get("relationships") or {}
    else:
        matrix = get_matrix(data)
        tactics = matrix.get("tactics", []) or []
        techniques = matrix.get("techniques", []) or []
        mitigations = matrix.get("mitigations", []) or []
        case_studies = data.get("case-studies") or matrix.get("case-studies") or []
        relationships = matrix  # legacy loaders pull matrix["relationships"] themselves

    return {
        "tactics": tactics,
        "techniques": techniques,
        "mitigations": mitigations,
        "case_studies": case_studies,
        "relationships": relationships,
        "format": fmt,
    }


class AtlasIngester:
    def __init__(self, uri: str, user: str, password: str):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def reset(self):
        with self.driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")

    def create_constraints(self):
        constraints = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (t:Tactic)       REQUIRE t.id   IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (t:Technique)    REQUIRE t.id   IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (t:SubTechnique) REQUIRE t.id   IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (m:Mitigation)   REQUIRE m.id   IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (c:CaseStudy)    REQUIRE c.id   IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (p:Platform)     REQUIRE p.name IS UNIQUE",
        ]
        with self.driver.session() as session:
            for c in constraints:
                session.run(c)

    def load_tactics(self, tactics: list[dict]):
        query = """
        UNWIND $rows AS row
        MERGE (t:Tactic {id: row.id})
        SET t.name        = row.name,
            t.description = row.description
        """
        rows = [
            {
                "id": t["id"],
                "name": t.get("name"),
                "description": (t.get("description") or "").strip(),
            }
            for t in tactics
        ]
        self._run(query, rows=rows)
        print(f"  loaded {len(rows)} Tactic nodes")

    def load_techniques_and_subtechniques(
        self, techniques: list[dict], relationships: dict, fmt: str
    ):
        top_level: list[dict] = []
        sub_level: list[dict] = []
        platforms: set[str] = set()

        for t in techniques:
            tid = t["id"]

            if fmt == "v6":
                tech_rels = relationships.get(tid, {})
                tactic_ids = [
                    r["target"]
                    for r in tech_rels.get("achieves", [])
                    if r.get("target", "").startswith("AML.TA")
                ]
                specializes = tech_rels.get("specializes", [])
                parent_id = specializes[0]["target"] if specializes else None
            else:
                tactic_ids = t.get("tactics", []) or []
                parent_id = _first(t, "subtechnique-of", "specializes")

            is_sub = (len(tid.split(".")) == 3) or bool(parent_id)

            row = {
                "id": tid,
                "name": t.get("name"),
                "description": (t.get("description") or "").strip(),
                "maturity": t.get("maturity"),
                "platforms": t.get("platforms", []) or [],
                "tactic_ids": tactic_ids,
                "parent_id": parent_id,
            }
            platforms.update(row["platforms"])
            (sub_level if is_sub else top_level).append(row)

        technique_query = """
        UNWIND $rows AS row
        MERGE (t:Technique {id: row.id})
        SET t.name        = row.name,
            t.description = row.description,
            t.maturity    = row.maturity,
            t.platforms   = row.platforms
        WITH t, row
        UNWIND row.tactic_ids AS tac_id
        MATCH (ta:Tactic {id: tac_id})
        MERGE (t)-[:BELONGS_TO]->(ta)
        """

        sub_query = """
        UNWIND $rows AS row
        MERGE (s:SubTechnique {id: row.id})
        SET s.name        = row.name,
            s.description = row.description,
            s.maturity    = row.maturity,
            s.platforms   = row.platforms
        WITH s, row
        MATCH (parent:Technique {id: row.parent_id})
        MERGE (s)-[:SUBTECHNIQUE_OF]->(parent)
        WITH s, row
        UNWIND row.tactic_ids AS tac_id
        MATCH (ta:Tactic {id: tac_id})
        MERGE (s)-[:BELONGS_TO]->(ta)
        """

        platform_query = """
        UNWIND $names AS name
        MERGE (:Platform {name: name})
        """

        target_query = """
        UNWIND $rows AS row
        UNWIND row.platforms AS pname
        MATCH (n {id: row.id})
        MATCH (p:Platform {name: pname})
        MERGE (n)-[:TARGETS]->(p)
        """

        self._run(platform_query, names=sorted(platforms))
        self._run(technique_query, rows=top_level)
        if sub_level:
            self._run(sub_query, rows=sub_level)
        all_rows = top_level + sub_level
        if all_rows:
            self._run(target_query, rows=all_rows)

        print(f"  loaded {len(top_level)} Technique nodes")
        print(f"  loaded {len(sub_level)} SubTechnique nodes")
        print(f"  loaded {len(platforms)} Platform nodes")

    def load_mitigations(self, mitigations: list[dict]):
        query = """
        UNWIND $rows AS row
        MERGE (m:Mitigation {id: row.id})
        SET m.name             = row.name,
            m.description      = row.description,
            m.category         = row.category,
            m.lifecycle_phases = row.lifecycle_phases
        """
        rows = []
        for m in mitigations:
            lifecycle = _first(
                m,
                "lifecycle-phases",
                "ml-lifecycle-phases",
                "lifecycle_phases",
                "ml_lifecycle_phases",
                default=[],
            )
            raw_cat = _first(m, "categories", "category")
            category = ", ".join(raw_cat) if isinstance(raw_cat, list) else raw_cat
            rows.append(
                {
                    "id": m["id"],
                    "name": m.get("name"),
                    "description": (m.get("description") or "").strip(),
                    "category": category,
                    "lifecycle_phases": lifecycle or [],
                }
            )
        self._run(query, rows=rows)
        print(f"  loaded {len(rows)} Mitigation nodes")

    def load_mitigation_edges(
        self, relationships: dict, mitigations: list[dict], fmt: str
    ):
        pairs: list[dict] = []

        if fmt == "v6":
            for m in mitigations:
                mid = m["id"]
                for entry in relationships.get(mid, {}).get("mitigates", []):
                    tech_id = entry.get("target") if isinstance(entry, dict) else entry
                    if tech_id:
                        pairs.append({"mit_id": mid, "tech_id": tech_id})
        else:
            rels = relationships.get("relationships", {}) or {}
            for key, val in rels.items():
                if key == "ATLAS-matrix" or not isinstance(val, dict):
                    continue
                for tech_id in val.get("mitigates", []) or []:
                    pairs.append({"mit_id": key, "tech_id": tech_id})
            if not pairs:
                for m in mitigations:
                    for tech in m.get("techniques", []) or []:
                        tech_id = tech.get("id") if isinstance(tech, dict) else tech
                        if tech_id:
                            pairs.append({"mit_id": m["id"], "tech_id": tech_id})

        query = """
        UNWIND $rows AS row
        MATCH (m:Mitigation {id: row.mit_id})
        MATCH (t {id: row.tech_id})
        WHERE t:Technique OR t:SubTechnique
        MERGE (t)-[:MITIGATED_BY]->(m)
        """
        self._run(query, rows=pairs)
        print(f"  loaded {len(pairs)} MITIGATED_BY relationships")

    def load_case_studies(
        self, case_studies: list[dict], relationships: dict, fmt: str
    ):
        cs_query = """
        UNWIND $rows AS row
        MERGE (c:CaseStudy {id: row.id})
        SET c.name    = row.name,
            c.type    = row.type,
            c.summary = row.summary
        """
        cs_rows = [
            {
                "id": c["id"],
                "name": c.get("name"),
                "type": _first(c, "case-study-type", "type"),
                "summary": (c.get("summary") or c.get("description") or "").strip(),
            }
            for c in case_studies
        ]
        self._run(cs_query, rows=cs_rows)
        print(f"  loaded {len(cs_rows)} CaseStudy nodes")

        employs_rows: list[dict] = []

        if fmt == "v6":
            for c in case_studies:
                cs_id = c["id"]
                for emp in relationships.get(cs_id, {}).get("employs", []):
                    tech_id = emp.get("target")
                    if not tech_id:
                        continue
                    employs_rows.append(
                        {
                            "cs_id": cs_id,
                            "technique_id": tech_id,
                            "tactic_id": emp.get("tactic"),
                            "procedure": (emp.get("description") or "").strip(),
                        }
                    )
        else:
            for c in case_studies:
                for proc in c.get("procedure", []) or []:
                    tech_id = proc.get("technique")
                    if not tech_id:
                        continue
                    employs_rows.append(
                        {
                            "cs_id": c["id"],
                            "technique_id": tech_id,
                            "tactic_id": proc.get("tactic"),
                            "procedure": (proc.get("description") or "").strip(),
                        }
                    )

        employs_query = """
        UNWIND $rows AS row
        MATCH (c:CaseStudy {id: row.cs_id})
        MATCH (t {id: row.technique_id})
        WHERE t:Technique OR t:SubTechnique
        MERGE (c)-[r:EMPLOYS]->(t)
        SET r.procedure = row.procedure,
            r.tactic_id = row.tactic_id
        """
        self._run(employs_query, rows=employs_rows)
        print(f"  loaded {len(employs_rows)} EMPLOYS relationships")

    def load_sequences(self, relationships: dict, fmt: str):
        pairs: set[tuple[str, str]] = set()

        if fmt == "v6":
            # Derive FOLLOWED_BY from case-study step leads-to chains.
            for key, val in relationships.items():
                if not key.startswith("AML.CS"):
                    continue
                employs = val.get("employs", []) or []
                step_to_tech = {
                    e["step-id"]: e["target"]
                    for e in employs
                    if e.get("step-id") and e.get("target")
                }
                for e in employs:
                    from_tech = e.get("target")
                    if not from_tech:
                        continue
                    for next_step in e.get("leads-to", []) or []:
                        to_tech = step_to_tech.get(next_step)
                        if to_tech and from_tech != to_tech:
                            pairs.add((from_tech, to_tech))
        else:
            atlas_rels = relationships.get("relationships", {}) or {}
            sequences = (atlas_rels.get("ATLAS-matrix") or {}).get(
                "sequences", []
            ) or []
            for seq in sequences:
                for a, b in zip(seq, seq[1:]):
                    pairs.add((a, b))

        rows = [{"from_id": a, "to_id": b} for a, b in pairs]

        query = """
        UNWIND $rows AS row
        MATCH (a {id: row.from_id})
        MATCH (b {id: row.to_id})
        WHERE (a:Technique OR a:SubTechnique) AND (b:Technique OR b:SubTechnique)
        MERGE (a)-[:FOLLOWED_BY]->(b)
        """
        self._run(query, rows=rows)
        print(f"  loaded {len(rows)} FOLLOWED_BY relationships")

    def _run(self, query: str, **params):
        with self.driver.session() as session:
            session.run(query, **params)


def main():
    parser = argparse.ArgumentParser(description="Ingest MITRE ATLAS YAML into Neo4j")
    parser.add_argument("yaml_path")
    parser.add_argument("--uri", default="bolt://localhost:7687")
    parser.add_argument("--user", default="neo4j")
    parser.add_argument("--password", default="atlaspassword")
    parser.add_argument(
        "--reset", action="store_true", help="Wipe the graph before loading"
    )
    args = parser.parse_args()

    print(f"Loading {args.yaml_path} ...")
    data = load_atlas_yaml(args.yaml_path)
    sections = get_sections(data)

    tactics = sections["tactics"]
    techniques = sections["techniques"]
    mitigations = sections["mitigations"]
    case_studies = sections["case_studies"]
    relationships = sections["relationships"]
    fmt = sections["format"]

    print(f"Format: {fmt}")
    print(
        f"Found: {len(tactics)} tactics, {len(techniques)} techniques/subtechniques, "
        f"{len(mitigations)} mitigations, {len(case_studies)} case studies"
    )

    ingester = AtlasIngester(args.uri, args.user, args.password)
    try:
        if args.reset:
            print("Resetting graph...")
            ingester.reset()

        print("Creating constraints...")
        ingester.create_constraints()

        print("Loading tactics...")
        ingester.load_tactics(tactics)

        print("Loading techniques and sub-techniques...")
        ingester.load_techniques_and_subtechniques(techniques, relationships, fmt)

        print("Loading mitigations...")
        ingester.load_mitigations(mitigations)

        print("Loading mitigation relationships...")
        ingester.load_mitigation_edges(relationships, mitigations, fmt)

        print("Loading case studies and procedures...")
        ingester.load_case_studies(case_studies, relationships, fmt)

        print("Loading attack sequences...")
        ingester.load_sequences(relationships, fmt)

        print("Done.")
    finally:
        ingester.close()


if __name__ == "__main__":
    sys.exit(main())
