# MITRE ATLAS Knowledge Graph

A queryable Neo4j knowledge graph built from [MITRE ATLAS](https://atlas.mitre.org)
— tactics, techniques, sub-techniques, mitigations, case studies, and the relationships between them.

## What needs to be installed

1. **Docker** (for Neo4j) — https://docs.docker.com/get-docker/
2. **Python 3.10+**
3. Python dependencies:
   ```bash
   pip install -r requirements.txt --break-system-packages
   ```
4. **ATLAS data** — clone the official data repo:
   ```bash
   git clone https://github.com/mitre-atlas/atlas-data.git
   ```
   The file you need is `atlas-data/dist/ATLAS-latest.yaml`.

## 1. Start Neo4j

```bash
docker compose up -d
```

This starts Neo4j with:
- Browser UI at http://localhost:7474
- Bolt endpoint at bolt://localhost:7687
- Credentials: `neo4j` / `atlaspassword`

Wait ~30s for first boot. Check with `docker compose logs -f neo4j` until it
says "Started".

## 2. Ingest ATLAS data

```bash
python ingestion/ingest.py path_to/atlas-data/dist/ATLAS-latest.yaml --reset
```

`--reset` wipes the graph first — safe to re-run anytime.

Expected output:
```
Loading .../atlas-data/dist/ATLAS-latest.yaml ...
Format: v6
Found: 16 tactics, 170 techniques/subtechniques, 35 mitigations, 57 case studies
Creating constraints...
Loading tactics...
  loaded 16 Tactic nodes
Loading techniques and sub-techniques...
  loaded 101 Technique nodes
  loaded 69 SubTechnique nodes
  loaded N Platform nodes
Loading mitigations...
  loaded 35 Mitigation nodes
Loading mitigation relationships...
  loaded 246 MITIGATED_BY relationships
Loading case studies and procedures...
  loaded 57 CaseStudy nodes
  loaded 449 EMPLOYS relationships
Loading attack sequences...
  loaded 328 FOLLOWED_BY relationships
Done.
```

## 3. Run example queries

```bash
cd queries
python validate.py path_to/atlas-data/dist/ATLAS-latest.yaml
```

This re-ingests and then runs 8 example queries demonstrating the kinds of questions the graph answers:

1. Which techniques target Generative AI systems?
2. What mitigations exist for a given technique, and at which lifecycle phase?
3. Coverage gap analysis techniques with no mitigation
4. Multi-hop attack chains (FOLLOWED_BY, derived from case-study step sequences)
5. Real-world case studies + documented procedure for a technique
6. Mitigation prioritisation by coverage
7. Tactic overview (technique + incident counts)
8. Full threat profile for a given platform (combines 1, 2, 5)

## Using queries from a notebook

```python
from neo4j import GraphDatabase
import sys
sys.path.insert(0, "queries")
import queries

driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "atlaspassword"))

for row in queries.techniques_by_platform(driver, "Generative AI"):
    print(row)

driver.close()
```

## Development / testing without Docker

`ingestion/mock_neo4j.py` is a minimal in-memory stand-in for the `neo4j`
driver supporting the exact Cypher subset used here. It's only for local
development convenience and is not part of the deliverable's runtime path.

```bash
cd queries
python validate.py ../data/ATLAS_sample.yaml --mock
```

`data/ATLAS_sample.yaml` is a hand-written sample in **format-version 6.0.0**
(matching the real `ATLAS-latest.yaml` schema exactly), for quick iteration
without the full dataset.

## ATLAS YAML Format (v6)

The ingester supports the current ATLAS format-version 6.x, where all
entities live at the **top level as ID-keyed dicts**:

```
format-version: '6.0.0'
tactics:                      ← dict keyed by AML.TAxxxx
  AML.TA0002: {name, description, id, ...}
techniques:                   ← dict keyed by AML.Txxxx[.yyy]
  AML.T0005:  {name, description, platforms, maturity, id, ...}
  AML.T0051.000: {...}        ← sub-technique (3-part ID)
mitigations:                  ← dict keyed by AML.Mxxxx
  AML.M0001: {name, description, lifecycle-phases: [...], categories: [...], ...}
case-studies:                 ← dict keyed by AML.CSxxxx
  AML.CS0001: {name, description, type, actor, target, ...}
relationships:                ← all edges, keyed by entity ID
  AML.T0005:    {achieves:    [{source, target: AML.TA0002, ...}]}
  AML.T0051.000:{achieves:    [...], specializes: [{target: AML.T0051}]}
  AML.M0001:    {mitigates:   [{target: AML.T0005, description, ...}]}
  AML.CS0001:   {employs:     [{target, tactic, step-id, leads-to, description, ...}]}
  ATLAS-matrix: {sequences:   [{position, target: AML.TAxxxx, ...}]}
```

Key querying pattern (O(1) dict lookup):

```python
# Tactic membership of a technique
tactic_ids = [r["target"] for r in relationships["AML.T0005"]["achieves"]]

# Parent of a sub-technique
parent_id = relationships["AML.T0051.000"]["specializes"][0]["target"]

# Techniques mitigated by a mitigation
tech_ids = [r["target"] for r in relationships["AML.M0001"]["mitigates"]]

# Procedure steps of a case study
steps = relationships["AML.CS0001"]["employs"]
```

## Schema

**Nodes**
- `Tactic {id, name, description}`
- `Technique {id, name, description, maturity, platforms}`
- `SubTechnique {id, name, description, maturity, platforms}`
- `Mitigation {id, name, description, category, lifecycle_phases}`
- `CaseStudy {id, name, type, summary}`
- `Platform {name}`

**Relationships**
- `(Technique|SubTechnique)-[:BELONGS_TO]->(Tactic)`
- `(SubTechnique)-[:SUBTECHNIQUE_OF]->(Technique)`
- `(Technique|SubTechnique)-[:MITIGATED_BY]->(Mitigation)`
- `(Technique|SubTechnique)-[:TARGETS]->(Platform)`
- `(Technique|SubTechnique)-[:FOLLOWED_BY]->(Technique|SubTechnique)` — derived from case-study step `leads-to` chains
- `(CaseStudy)-[:EMPLOYS {procedure, tactic_id}]->(Technique|SubTechnique)` — real-world usage with documented procedure text

## OWASP LLM Top 10 Enrichment

The graph can be enriched with the **OWASP LLM Top 10 (2025)** taxonomy as a
cross-source layer. This adds `OwaspRisk` nodes cross-linked to ATLAS techniques
via `CORRESPONDS_TO` edges, without touching any existing ATLAS data.

### New node and edge types

**Nodes**
- `OwaspRisk {id, name, description}` — one node per OWASP LLM risk (LLM01–LLM10)

**Relationships**
- `(OwaspRisk)-[:CORRESPONDS_TO {rationale}]->(Technique|SubTechnique)` — links each OWASP risk to the ATLAS techniques that cover it, with a human-readable rationale string

> [!NOTE]
> `LLM09:2025` (Misinformation) intentionally has **no outgoing edges** — it has no
> adversarial-technique counterpart in ATLAS. Its `OwaspRisk` node is still created
> so the absence of edges is itself queryable.

### How to run

Run **after** `ingest.py` — this script is purely additive and never resets the graph:

```bash
# 1. Ingest ATLAS data (wipe + reload)
python ingestion/ingest.py path_to/ATLAS-latest.yaml --reset

# 2. Overlay OWASP enrichment (additive)
python ingestion/ingest_owasp.py
```

`ingest_owasp.py` will use `data/owasp_llm_top10_2025.yaml` and
`data/owasp_atlas_mapping.yaml` by default (or pass explicit paths as positional args).
It accepts the same `--uri`, `--user`, `--password` flags as `ingest.py`.

### Q9 — OWASP risk → ATLAS techniques

After enrichment, run the updated validate script to see **Q9** in action:

```bash
cd queries
# With live Neo4j:
python validate.py path_to/ATLAS-latest.yaml

# Or with the in-memory mock (no Docker needed):
python validate.py ../data/ATLAS_sample.yaml --mock
```

Q9 queries `LLM01:2025` (Prompt Injection) and returns all ATLAS techniques that
correspond to it, along with their ATLAS mitigations and real-world case studies.

### Querying from a notebook

```python
from neo4j import GraphDatabase
import sys
sys.path.insert(0, "queries")
import queries

driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "atlaspassword"))

for row in queries.atlas_for_owasp_risk(driver, "LLM01:2025"):
    print(row["technique_id"], row["technique_name"])
    print("  mitigations :", row["mitigations"])
    print("  case studies:", row["case_studies"])

driver.close()
```
