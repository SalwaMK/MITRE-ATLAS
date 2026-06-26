# MITRE ATLAS Knowledge Graph & Explorer

A queryable Neo4j knowledge graph built from [MITRE ATLAS](https://atlas.mitre.org) — tactics, techniques, sub-techniques, mitigations, real-world case studies, and cross-source enrichments like the OWASP LLM Top 10. The project includes an interactive Streamlit application to visually explore and query the graph.

## Demo

<video src="assets/DEMO.mp4" controls width="100%"></video>

## Setup & Installation

1. **Install Docker** (for running Neo4j locally)
2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt --break-system-packages
   ```
3. **Download ATLAS data:**
   ```bash
   git clone https://github.com/mitre-atlas/atlas-data.git
   ```

## How to Run the Project

### 1. Start the Database
Bring up the Neo4j container in the background:
```bash
docker compose up -d
```
*Wait ~30 seconds for Neo4j to fully boot. It exposes a web interface at http://localhost:7474 using credentials `neo4j` / `atlaspassword`.*

### 2. Ingest the Data
Load the core MITRE ATLAS dataset followed by the OWASP LLM Top 10 enrichment layer.

```bash
# 1. Wipe the graph and load the core MITRE ATLAS v6.0 dataset
#    (Replace with your actual path to ATLAS-latest.yaml)
python ingestion/ingest.py data/ATLAS-latest.yaml --reset

# 2. Additive load of OWASP LLM Top 10 (2025) mappings
python ingestion/ingest_owasp.py
```

### 3. Launch the Explorer UI
Start the interactive Streamlit application:
```bash
streamlit run app.py
```
Open your browser to `http://localhost:8501`.

## Features
The **MITRE ATLAS Explorer** provides several ways to interact with the threat landscape graph:
- **Overview Dashboard:** View graph counts and an interactive visual schema of the relationships.
- **Platform Explorer & Technique Inspector:** Browse threats targeting specific platforms (like Generative AI) and drill down into attack chains and precise mitigations.
- **Coverage Analysis & Tactic Overview:** Prioritise mitigations by coverage and compare theoretical technique counts to real documented incidents.
- **Threat Assessment & Report Generator:** Leverage LLM integration (Groq API) to dynamically map system descriptions to ATLAS techniques and generate formal PDF threat reports.
- **OWASP Insights:** Explore the explicit transitive mapping between OWASP LLM Top 10 vulnerabilities and MITRE ATLAS adversary tactics.

## Validating Queries Locally (Offline)
If you want to run quick smoke tests on the data queries without spinning up Neo4j in Docker, the project includes an in-memory mock driver:
```bash
python queries/validate.py data/ATLAS_sample.yaml --mock
```
