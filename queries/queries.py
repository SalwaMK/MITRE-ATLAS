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
