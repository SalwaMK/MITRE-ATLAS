"""
mock_neo4j.py — In-memory stand-in for the neo4j driver, used to run
validate.py without a live Neo4j instance. Not a general Cypher engine.
"""

from collections import defaultdict


class MockNode:
    _id_counter = 0

    def __init__(self, labels, props):
        self.labels = set(labels)
        self.props = dict(props)
        MockNode._id_counter += 1
        self.uid = MockNode._id_counter

    def __repr__(self):
        return (
            f"({':'.join(self.labels)} {self.props.get('id', self.props.get('name'))})"
        )


class MockGraph:
    def __init__(self):
        self.nodes = []
        self.rels = []  # [start, type, end, props]

    def reset(self):
        self.nodes = []
        self.rels = []

    def find_node(self, labels, key, value):
        for n in self.nodes:
            if (not labels or n.labels & set(labels)) and n.props.get(key) == value:
                return n
        return None

    def merge_node(self, labels, key, value):
        n = self.find_node(labels, key, value)
        if n is None:
            n = MockNode(labels, {key: value})
            self.nodes.append(n)
        else:
            n.labels |= set(labels)
        return n

    def merge_rel(self, start, rel_type, end, props=None):
        for r in self.rels:
            if r[0] is start and r[1] == rel_type and r[2] is end:
                if props:
                    r[3].update(props)
                return r
        rel = [start, rel_type, end, dict(props or {})]
        self.rels.append(rel)
        return rel


GRAPH = MockGraph()


class MockSession:
    def run(self, query, **params):
        q = " ".join(query.split())
        rows = params.get("rows")
        names = params.get("names")

        if "DETACH DELETE" in q:
            GRAPH.reset()
            return []

        if q.startswith("CREATE CONSTRAINT"):
            return []

        if "MERGE (:Platform {name: name})" in q:
            for name in names:
                GRAPH.merge_node(["Platform"], "name", name)
            return []

        if "MERGE (t:Tactic {id: row.id})" in q:
            for row in rows:
                n = GRAPH.merge_node(["Tactic"], "id", row["id"])
                n.props.update({"name": row["name"], "description": row["description"]})
            return []

        if "MERGE (t:Technique {id: row.id})" in q:
            for row in rows:
                n = GRAPH.merge_node(["Technique"], "id", row["id"])
                n.props.update(
                    {
                        "name": row["name"],
                        "description": row["description"],
                        "maturity": row["maturity"],
                        "platforms": row["platforms"],
                    }
                )
                for tac_id in row["tactic_ids"]:
                    ta = GRAPH.find_node(["Tactic"], "id", tac_id)
                    if ta:
                        GRAPH.merge_rel(n, "BELONGS_TO", ta)
            return []

        if "MERGE (s:SubTechnique {id: row.id})" in q:
            for row in rows:
                n = GRAPH.merge_node(["SubTechnique"], "id", row["id"])
                n.props.update(
                    {
                        "name": row["name"],
                        "description": row["description"],
                        "maturity": row["maturity"],
                        "platforms": row["platforms"],
                    }
                )
                parent = GRAPH.find_node(["Technique"], "id", row["parent_id"])
                if parent:
                    GRAPH.merge_rel(n, "SUBTECHNIQUE_OF", parent)
                for tac_id in row["tactic_ids"]:
                    ta = GRAPH.find_node(["Tactic"], "id", tac_id)
                    if ta:
                        GRAPH.merge_rel(n, "BELONGS_TO", ta)
            return []

        if "MERGE (n)-[:TARGETS]->(p)" in q:
            for row in rows:
                n = GRAPH.find_node(["Technique", "SubTechnique"], "id", row["id"])
                if not n:
                    continue
                for pname in row["platforms"]:
                    p = GRAPH.find_node(["Platform"], "name", pname)
                    if p:
                        GRAPH.merge_rel(n, "TARGETS", p)
            return []

        if "MERGE (m:Mitigation {id: row.id})" in q:
            for row in rows:
                n = GRAPH.merge_node(["Mitigation"], "id", row["id"])
                n.props.update(
                    {
                        "name": row["name"],
                        "description": row["description"],
                        "category": row["category"],
                        "lifecycle_phases": row["lifecycle_phases"],
                    }
                )
            return []

        if "MERGE (t)-[:MITIGATED_BY]->(m)" in q:
            for row in rows:
                m = GRAPH.find_node(["Mitigation"], "id", row["mit_id"])
                t = GRAPH.find_node(["Technique", "SubTechnique"], "id", row["tech_id"])
                if m and t:
                    GRAPH.merge_rel(t, "MITIGATED_BY", m)
            return []

        if "MERGE (a)-[:FOLLOWED_BY]->(b)" in q:
            for row in rows:
                a = GRAPH.find_node(["Technique", "SubTechnique"], "id", row["from_id"])
                b = GRAPH.find_node(["Technique", "SubTechnique"], "id", row["to_id"])
                if a and b:
                    GRAPH.merge_rel(a, "FOLLOWED_BY", b)
            return []

        if "MERGE (c:CaseStudy {id: row.id})" in q:
            for row in rows:
                n = GRAPH.merge_node(["CaseStudy"], "id", row["id"])
                n.props.update(
                    {
                        "name": row["name"],
                        "type": row["type"],
                        "summary": row["summary"],
                    }
                )
            return []

        if "MERGE (c)-[r:EMPLOYS]->(t)" in q:
            for row in rows:
                c = GRAPH.find_node(["CaseStudy"], "id", row["cs_id"])
                t = GRAPH.find_node(
                    ["Technique", "SubTechnique"], "id", row["technique_id"]
                )
                if c and t:
                    GRAPH.merge_rel(
                        c,
                        "EMPLOYS",
                        t,
                        {"procedure": row["procedure"], "tactic_id": row["tactic_id"]},
                    )
            return []

        # queries

        if "MATCH (t)-[:TARGETS]->(p:Platform {name: $platform})" in q:
            platform = params["platform"]
            out = []
            for n in GRAPH.nodes:
                if not (n.labels & {"Technique", "SubTechnique"}):
                    continue
                if any(
                    r[0] is n
                    and r[1] == "TARGETS"
                    and r[2].props.get("name") == platform
                    for r in GRAPH.rels
                ):
                    tactics = [
                        r[2].props.get("name")
                        for r in GRAPH.rels
                        if r[0] is n and r[1] == "BELONGS_TO"
                    ]
                    out.append(
                        {
                            "technique_id": n.props["id"],
                            "technique_name": n.props["name"],
                            "tactics": tactics,
                        }
                    )
            return sorted(out, key=lambda x: x["technique_id"])

        if "MATCH (t {id: $technique_id})-[:MITIGATED_BY]->(m:Mitigation)" in q:
            tid = params["technique_id"]
            t = GRAPH.find_node(["Technique", "SubTechnique"], "id", tid)
            out = []
            if t:
                for r in GRAPH.rels:
                    if r[0] is t and r[1] == "MITIGATED_BY":
                        m = r[2]
                        out.append(
                            {
                                "mitigation_id": m.props["id"],
                                "mitigation_name": m.props["name"],
                                "category": m.props.get("category"),
                                "lifecycle_phases": m.props.get("lifecycle_phases"),
                            }
                        )
            return sorted(out, key=lambda x: x["mitigation_id"])

        if "AND NOT (t)-[:MITIGATED_BY]->(:Mitigation)" in q:
            platform = params.get("platform")
            out = []
            for n in GRAPH.nodes:
                if not (n.labels & {"Technique", "SubTechnique"}):
                    continue
                if platform:
                    if not any(
                        r[0] is n
                        and r[1] == "TARGETS"
                        and r[2].props.get("name") == platform
                        for r in GRAPH.rels
                    ):
                        continue
                if not any(r[0] is n and r[1] == "MITIGATED_BY" for r in GRAPH.rels):
                    out.append(
                        {
                            "technique_id": n.props["id"],
                            "technique_name": n.props["name"],
                        }
                    )
            return sorted(out, key=lambda x: x["technique_id"])

        if "FOLLOWED_BY*1.." in q:
            tid = params["technique_id"]
            start = GRAPH.find_node(["Technique", "SubTechnique"], "id", tid)
            max_hops = int(q.split("FOLLOWED_BY*1..")[1].split("]")[0])
            out = []

            def dfs(node, chain_ids, chain_names, hops):
                if hops >= max_hops:
                    return
                for r in GRAPH.rels:
                    if r[0] is node and r[1] == "FOLLOWED_BY":
                        nxt = r[2]
                        new_ids = chain_ids + [nxt.props["id"]]
                        new_names = chain_names + [nxt.props["name"]]
                        out.append(
                            {
                                "chain_ids": new_ids,
                                "chain_names": new_names,
                                "hops": hops + 1,
                            }
                        )
                        dfs(nxt, new_ids, new_names, hops + 1)

            if start:
                dfs(start, [start.props["id"]], [start.props["name"]], 0)
            return sorted(out, key=lambda x: x["hops"])

        if "MATCH (c:CaseStudy)-[r:EMPLOYS]->(t {id: $technique_id})" in q:
            tid = params["technique_id"]
            t = GRAPH.find_node(["Technique", "SubTechnique"], "id", tid)
            out = []
            if t:
                for r in GRAPH.rels:
                    if r[1] == "EMPLOYS" and r[2] is t:
                        c = r[0]
                        out.append(
                            {
                                "case_study_id": c.props["id"],
                                "case_study_name": c.props["name"],
                                "case_study_type": c.props.get("type"),
                                "procedure": r[3].get("procedure"),
                            }
                        )
            return sorted(out, key=lambda x: x["case_study_id"])

        if "count(t) AS techniques_covered" in q:
            limit = params.get("limit", 10)
            counts = defaultdict(int)
            for r in GRAPH.rels:
                if r[1] == "MITIGATED_BY":
                    counts[r[2]] += 1
            out = []
            for m, cnt in counts.items():
                out.append(
                    {
                        "mitigation_id": m.props["id"],
                        "mitigation_name": m.props["name"],
                        "category": m.props.get("category"),
                        "techniques_covered": cnt,
                    }
                )
            out.sort(key=lambda x: (-x["techniques_covered"], x["mitigation_id"]))
            return out[:limit]

        if "count(DISTINCT t) AS technique_count" in q:
            tac_techs = defaultdict(set)
            for r in GRAPH.rels:
                if r[1] == "BELONGS_TO":
                    tac_techs[r[2]].add(r[0])
            out = []
            for ta, techs in tac_techs.items():
                incident_cs = set()
                for t in techs:
                    for r in GRAPH.rels:
                        if (
                            r[1] == "EMPLOYS"
                            and r[2] is t
                            and r[0].props.get("type") == "Incident"
                        ):
                            incident_cs.add(r[0])
                out.append(
                    {
                        "tactic_id": ta.props["id"],
                        "tactic_name": ta.props["name"],
                        "technique_count": len(techs),
                        "incident_count": len(incident_cs),
                    }
                )
            return sorted(out, key=lambda x: x["tactic_id"])

        if "AS real_world_incidents" in q:
            platform = params["platform"]
            out = []
            for n in GRAPH.nodes:
                if not (n.labels & {"Technique", "SubTechnique"}):
                    continue
                if not any(
                    r[0] is n
                    and r[1] == "TARGETS"
                    and r[2].props.get("name") == platform
                    for r in GRAPH.rels
                ):
                    continue
                tactic = next(
                    (
                        r[2].props.get("name")
                        for r in GRAPH.rels
                        if r[0] is n and r[1] == "BELONGS_TO"
                    ),
                    None,
                )
                mits = [
                    r[2].props.get("name")
                    for r in GRAPH.rels
                    if r[0] is n and r[1] == "MITIGATED_BY"
                ]
                incidents = set(
                    r[0]
                    for r in GRAPH.rels
                    if r[1] == "EMPLOYS"
                    and r[2] is n
                    and r[0].props.get("type") == "Incident"
                )
                out.append(
                    {
                        "technique_id": n.props["id"],
                        "technique_name": n.props["name"],
                        "tactic": tactic,
                        "mitigations": mits,
                        "real_world_incidents": len(incidents),
                    }
                )
            return sorted(
                out, key=lambda x: (-x["real_world_incidents"], x["technique_id"])
            )

        raise NotImplementedError(f"Mock does not support query: {q[:120]}...")


class MockDriverSessionCtx:
    def __enter__(self):
        return MockSession()

    def __exit__(self, *a):
        return False


class MockDriver:
    def session(self):
        return MockDriverSessionCtx()

    def close(self):
        pass


class GraphDatabase:
    @staticmethod
    def driver(uri, auth=None):
        return MockDriver()
