"""
queries.py — Cypher query functions for the ATLAS knowledge graph.

Each function takes a driver as its first argument and returns a list[dict].

    from neo4j import GraphDatabase
    import queries

    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "atlaspassword"))
    for row in queries.techniques_by_platform(driver, "Generative AI"):
        print(row["technique_id"], row["technique_name"])
    driver.close()
"""

from typing import Optional


def _query(driver, cypher: str, **params) -> list[dict]:
    with driver.session() as session:
        result = session.run(cypher, **params)
        return [dict(record) for record in result]


def techniques_by_platform(driver, platform: str) -> list[dict]:
    cypher = """
    MATCH (t)-[:TARGETS]->(p:Platform {name: $platform})
    WHERE t:Technique OR t:SubTechnique
    OPTIONAL MATCH (t)-[:BELONGS_TO]->(ta:Tactic)
    RETURN t.id AS technique_id, t.name AS technique_name,
           collect(DISTINCT ta.name) AS tactics
    ORDER BY technique_id
    """
    return _query(driver, cypher, platform=platform)


def mitigations_for_technique(driver, technique_id: str) -> list[dict]:
    cypher = """
    MATCH (t {id: $technique_id})-[:MITIGATED_BY]->(m:Mitigation)
    WHERE t:Technique OR t:SubTechnique
    RETURN m.id AS mitigation_id, m.name AS mitigation_name,
           m.category AS category, m.lifecycle_phases AS lifecycle_phases
    ORDER BY mitigation_id
    """
    return _query(driver, cypher, technique_id=technique_id)


def techniques_without_mitigations(
    driver, platform: Optional[str] = None
) -> list[dict]:
    if platform:
        cypher = """
        MATCH (t)-[:TARGETS]->(:Platform {name: $platform})
        WHERE (t:Technique OR t:SubTechnique)
          AND NOT (t)-[:MITIGATED_BY]->(:Mitigation)
        RETURN t.id AS technique_id, t.name AS technique_name
        ORDER BY technique_id
        """
        return _query(driver, cypher, platform=platform)

    cypher = """
    MATCH (t)
    WHERE (t:Technique OR t:SubTechnique)
      AND NOT (t)-[:MITIGATED_BY]->(:Mitigation)
    RETURN t.id AS technique_id, t.name AS technique_name
    ORDER BY technique_id
    """
    return _query(driver, cypher)


def attack_chain_from(driver, technique_id: str, max_hops: int = 3) -> list[dict]:
    cypher = f"""
    MATCH path = (start {{id: $technique_id}})-[:FOLLOWED_BY*1..{int(max_hops)}]->(next)
    WHERE (start:Technique OR start:SubTechnique)
    RETURN [n IN nodes(path) | n.id]   AS chain_ids,
           [n IN nodes(path) | n.name] AS chain_names,
           length(path) AS hops
    ORDER BY hops
    """
    return _query(driver, cypher, technique_id=technique_id)


def case_studies_for_technique(driver, technique_id: str) -> list[dict]:
    cypher = """
    MATCH (c:CaseStudy)-[r:EMPLOYS]->(t {id: $technique_id})
    WHERE t:Technique OR t:SubTechnique
    RETURN c.id AS case_study_id, c.name AS case_study_name,
           c.type AS case_study_type, r.procedure AS procedure
    ORDER BY case_study_id
    """
    return _query(driver, cypher, technique_id=technique_id)


def top_mitigations_by_coverage(driver, limit: int = 10) -> list[dict]:
    cypher = """
    MATCH (t)-[:MITIGATED_BY]->(m:Mitigation)
    WHERE t:Technique OR t:SubTechnique
    RETURN m.id AS mitigation_id, m.name AS mitigation_name,
           m.category AS category, count(t) AS techniques_covered
    ORDER BY techniques_covered DESC, mitigation_id
    LIMIT $limit
    """
    return _query(driver, cypher, limit=limit)


def tactic_overview(driver) -> list[dict]:
    cypher = """
    MATCH (t)-[:BELONGS_TO]->(ta:Tactic)
    WHERE t:Technique OR t:SubTechnique
    OPTIONAL MATCH (c:CaseStudy)-[:EMPLOYS]->(t)
    WHERE c.type = 'Incident'
    RETURN ta.id AS tactic_id, ta.name AS tactic_name,
           count(DISTINCT t) AS technique_count,
           count(DISTINCT c) AS incident_count
    ORDER BY tactic_id
    """
    return _query(driver, cypher)


def threat_profile(driver, platform: str) -> list[dict]:
    cypher = """
    MATCH (t)-[:TARGETS]->(:Platform {name: $platform})
    WHERE t:Technique OR t:SubTechnique
    OPTIONAL MATCH (t)-[:BELONGS_TO]->(ta:Tactic)
    OPTIONAL MATCH (t)-[:MITIGATED_BY]->(m:Mitigation)
    OPTIONAL MATCH (c:CaseStudy)-[:EMPLOYS]->(t)
    WHERE c.type = 'Incident'
    RETURN t.id AS technique_id, t.name AS technique_name,
           ta.name AS tactic,
           collect(DISTINCT m.name) AS mitigations,
           count(DISTINCT c) AS real_world_incidents
    ORDER BY real_world_incidents DESC, technique_id
    """
    return _query(driver, cypher, platform=platform)


def atlas_for_owasp_risk(driver, owasp_id: str) -> list[dict]:
    """Given an OWASP LLM Top 10 risk ID, return corresponding ATLAS
    techniques with their mitigations and case studies."""
    cypher = """
    MATCH (o:OwaspRisk {id: $owasp_id})-[r:CORRESPONDS_TO]->(t)
    WHERE t:Technique OR t:SubTechnique
    OPTIONAL MATCH (t)-[:MITIGATED_BY]->(m:Mitigation)
    OPTIONAL MATCH (cs:CaseStudy)-[:EMPLOYS]->(t)
    RETURN o.name AS owasp_risk, t.id AS technique_id, t.name AS technique_name,
           r.rationale AS rationale,
           collect(DISTINCT m.name) AS mitigations,
           collect(DISTINCT cs.name) AS case_studies
    """
    return _query(driver, cypher, owasp_id=owasp_id)


def owasp_risk_full_context(driver, owasp_id: str) -> list[dict]:
    """Given an OWASP LLM Top 10 risk ID, return the full three-layer
    context: the corresponding ATLAS technique(s)/sub-technique(s), the
    tactic(s) each one belongs to (the adversary's goal when using that
    technique), its mitigations, and any real-world case studies.

    This demonstrates the transitive path:
        OwaspRisk -[:CORRESPONDS_TO]-> Technique -[:BELONGS_TO]-> Tactic

    No new edge type is introduced between OwaspRisk and Tactic --
    the tactic context is reached via the existing Technique->Tactic
    relationship, since OWASP risk categories (vulnerability class) and
    ATLAS tactics (adversary goal) are different axes that are already
    bridged by Technique.
    """
    cypher = """
    MATCH (o:OwaspRisk {id: $owasp_id})-[:CORRESPONDS_TO]->(t)
    WHERE t:Technique OR t:SubTechnique
    OPTIONAL MATCH (t)-[:BELONGS_TO]->(ta:Tactic)
    OPTIONAL MATCH (t)-[:MITIGATED_BY]->(m:Mitigation)
    OPTIONAL MATCH (cs:CaseStudy)-[:EMPLOYS]->(t)
    RETURN o.name AS owasp_risk,
           t.id AS technique_id, t.name AS technique_name,
           collect(DISTINCT ta.name) AS tactics,
           collect(DISTINCT m.name) AS mitigations,
           collect(DISTINCT cs.name) AS case_studies
    ORDER BY technique_id
    """
    return _query(driver, cypher, owasp_id=owasp_id)


def owasp_risk_tactic_summary(driver, owasp_id: str) -> list[dict]:
    """Given an OWASP LLM Top 10 risk ID, return the distinct set of
    ATLAS tactics (adversary goals) spanned by its corresponding
    techniques, with a count of techniques per tactic. Useful for
    answering: 'when this OWASP risk manifests via ATLAS techniques,
    what is the attacker actually trying to achieve?'"""
    cypher = """
    MATCH (o:OwaspRisk {id: $owasp_id})-[:CORRESPONDS_TO]->(t)
    WHERE t:Technique OR t:SubTechnique
    MATCH (t)-[:BELONGS_TO]->(ta:Tactic)
    RETURN ta.id AS tactic_id, ta.name AS tactic_name,
           count(DISTINCT t) AS technique_count
    ORDER BY technique_count DESC
    """
    return _query(driver, cypher, owasp_id=owasp_id)


def all_owasp_risks(driver) -> list[dict]:
    """Return all OWASP risks from the graph."""
    cypher = "MATCH (o:OwaspRisk) RETURN o.id AS id, o.name AS name ORDER BY o.id"
    return _query(driver, cypher)
