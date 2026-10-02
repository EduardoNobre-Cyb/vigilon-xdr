<p align="center">
  <img src="docs/assets/vigilon-banner.svg" alt="Vigilon XDR Platform" width="100%">
</p>

# Vigilon

**Multi-Agent XDR Platform for Unified Log and Endpoint Threat Defense**

Vigilon is a self-built extended detection and response (XDR) platform. Six cooperating agents ingest logs, model the attack surface, classify threats with machine learning, hunt for multi-stage attacks, coordinate responses, and collect live telemetry from Linux and Windows endpoints. Analysts work everything from a single real-time dashboard.

The endpoint detection side was inspired by CrowdStrike's research on machine-learning malware detection in the Falcon platform: behavioural models score every process and network event on the endpoint itself, before anything reaches the analyst.

---

## The agents

| Agent | Role | What it does |
|---|---|---|
| **Vigilon Intake** | Log ingestion | Parses syslog, CSV and JSON logs, normalises timestamps and fields, and enriches events before storage |
| **Vigilon Atlas** | Threat modeling and attack paths | Infers the system architecture from logs, builds an attack graph in Neo4j, maps vulnerabilities to MITRE ATT&CK techniques, and ranks attack paths by feasibility |
| **Vigilon Triage** | Threat classification | Classifies threats with a Word2Vec + metadata + calibrated Gradient Boosting model, with confidence scoring and CVSS-based risk and severity |
| **Vigilon Sentinel** | Threat hunting | Correlates threats by entity, matches IOCs, flags statistical anomalies (z-score baselines), detects multi-stage attack sequences with an ML pattern model, and pulls external intel from AlienVault OTX, MISP and AbuseIPDB |
| **Vigilon Warden** | Response coordination | Applies response rules (monitor, alert, contain, isolate, block, escalate) and notifies the right analysts by email, Slack or Microsoft Teams |
| **Vigilon Sensor** | Endpoint collector (EDR) | Lightweight Linux and Windows agents that score process and network activity with on-device ML models, stream telemetry to the platform, and run analyst actions such as killing a process or quarantining a file |

## Architecture

```mermaid
flowchart LR
    subgraph Endpoints
        L["Vigilon Sensor<br/>Linux · psutil / auditd"]
        W["Vigilon Sensor<br/>Windows · psutil"]
    end

    subgraph Pipeline["Agent pipeline (Redis pub/sub)"]
        I["Intake<br/>log ingestion"] --> A["Atlas<br/>attack graph + MITRE"]
        A -- threat_intelligence --> T["Triage<br/>ML classification"]
        T -- classified_threats --> S["Sentinel<br/>threat hunting"]
        S -- hunting_results --> R["Warden<br/>response"]
    end

    D["Analyst Dashboard<br/>Flask + Socket.IO"]
    D -- log_uploaded --> I
    L <-- "telemetry / actions<br/>(Socket.IO)" --> D
    W <-- "telemetry / actions<br/>(Socket.IO)" --> D
    R -- "email · Slack · Teams" --> N["Analysts"]

    A --- G[("Neo4j")]
    D --- P[("PostgreSQL")]
    Pipeline --- P
```

## Dashboard features

- **Live threat feed** with severity, confidence, MITRE tactic and the response taken
- **Analyst review queue**: claim and lock threats so two analysts never work the same one, approve or override decisions, and feed curated labels back into training
- **EDR console**: connected endpoints, live telemetry, detections, search, and one-click response actions
- **Attack surface**: assets, vulnerabilities and ranked attack paths
- **Agent control**: start and stop agents, check health via Redis heartbeats, and stream their logs live
- **Model registry**: every retrained model is registered with its metrics and must be approved by a human before it is deployed (hot-reloaded without a restart)
- **Analyst management** with roles, notification thresholds, JWT authentication and forced password changes
- **Reviewer analytics** and a full audit trail of response actions and notifications
- **Log upload**, which triggers the whole agent pipeline end to end

## Machine learning

- **Threat classification (Triage):** Word2Vec text embeddings combined with structured metadata features feed a Gradient Boosting classifier with probability calibration. Each model generation (v2 to v8) is kept in `data/models/threat_classifier_v*`.
- **Quality gates:** a new model is only promoted if it meets thresholds for macro-F1, accuracy, average confidence and calibration error (ECE and Brier score). All thresholds are configurable through `THREAT_*` environment variables.
- **Endpoint models (Sensor):** separate process and network behaviour models (Random Forest and Gradient Boosting, with SMOTE to balance the classes), trained on real benign telemetry captured with auditd plus catalogued attack behaviour.
- **Pattern detection (Sentinel):** an ML model over threat-sequence features detects multi-stage attacks, alongside fuzzy matching of tactic sequences.
- **Instrumentation:** inference latency, false-positive rate and model accuracy are tracked at runtime, with OpenTelemetry counters on the agents.

## Tech stack

| Area | Technology |
|---|---|
| Backend and API | Python, Flask, Flask-SocketIO, Flask-JWT-Extended |
| Data | PostgreSQL + SQLAlchemy, Neo4j (attack graphs), Redis (pub/sub and heartbeats) |
| ML | scikit-learn, gensim (Word2Vec), imbalanced-learn, NumPy, pandas, NLTK |
| Threat intel | MITRE ATT&CK (`mitreattack-python`), Vulners CVE API, AlienVault OTX, MISP, AbuseIPDB |
| Endpoint | psutil, Linux auditd, python-socketio client |
| Ops | Docker, APScheduler, OpenTelemetry, Git LFS for model artifacts |

## Getting started

### 1. Start the backing services

```bash
docker run -d --name vigilon-postgres -p 5432:5432 \
  -e POSTGRES_USER=threat_user -e POSTGRES_PASSWORD=threat_password -e POSTGRES_DB=threat_modeling postgres:16
docker run -d --name vigilon-redis -p 6379:6379 redis:7-alpine
docker run -d --name vigilon-neo4j -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/neo4jpassword neo4j:5
```

These are local development credentials. Change them for anything that isn't local.

### 2. Install and configure

```bash
git lfs install && git lfs pull        # model artifacts are stored in Git LFS
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file in the project root (see [Configuration](#configuration)). At minimum, set:

```env
DATABASE_URL=postgresql+psycopg2://threat_user:threat_password@localhost:5432/threat_modeling
JWT_SECRET_KEY=<a long random string>
NEO4J_PASSWORD=neo4jpassword
DEFAULT_PASSWORD=<temporary password for seeded analysts>
```

### 3. Initialise the database and run the dashboard

```bash
python scripts/init_database.py      # creates the tables and seeds analysts and IOCs
python -m dashboard.app              # http://localhost:5000
```

Start the agents from the dashboard's agent panel, or run any of them directly:

```bash
python -m agents.threat_modeling.threat_model_agent --mode listen
python -m agents.classification.classifier_agent --mode listen
python -m agents.threat_hunter.threat_hunter_agent --mode listen
python -m agents.response_coordinator.response_coordinator_agent --mode listen
```

### 4. Connect an endpoint (optional)

```bash
# Linux (use PROCESS_COLLECTOR=auditd for kernel-level exec events; needs root)
BACKEND_URL=http://<platform-host>:5000 python -m agents.endpoint_agent.linux_agent

# Windows (PowerShell)
$env:BACKEND_URL="http://<platform-host>:5000"; python -m agents.endpoint_agent.windows_agent
```

Upload any file from `test-upload-logs/` in the dashboard to watch the full pipeline run.

### Docker image

The root `Dockerfile` builds the dashboard and API. At startup it waits for PostgreSQL, initialises the schema, downloads the NLTK corpora and launches the dashboard (see `docker/entrypoint.sh`).

## Configuration

All configuration comes from environment variables (`.env`). Secrets never live in the code.

| Group | Variables |
|---|---|
| Core | `DATABASE_URL`, `JWT_SECRET_KEY`, `DEFAULT_PASSWORD`, `SKIP_DB_SEED` |
| Services | `REDIS_HOST`, `REDIS_PORT`, `REDIS_DB`, `NEO4J_URI`, `NEO4J_USERNAME`, `NEO4J_PASSWORD` |
| Threat intel | `VULNERS_API_KEY`, `OTX_API_KEY`, `MISP_API_URL`, `MISP_API_KEY`, `ABUSEDB_API_KEY`, `CVE_MIN_YEAR` |
| Notifications | `SMTP_SERVER`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SLACK_ENABLED`, `SLACK_WEBHOOK_URL`, `TEAMS_ENABLED`, `TEAMS_WEBHOOK_URL` |
| Models | `PATTERN_MODEL_PATH`, `EDR_MODEL_DIR`, `THREAT_CALIBRATION_METHOD`, `THREAT_GATE_*`, `THREAT_WINNER_*` |
| Endpoint sensor | `BACKEND_URL`, `PROCESS_COLLECTOR` (`polling` or `auditd`), `ML_FIRST_MODE`, `TELEMETRY_POLL_INTERVAL`, `PROCESS_EVENT_MIN_SCORE` |
| Logging | `LOG_MAX_MB`, `LOG_RETENTION_DAYS` |

All threat-intel and notification integrations are optional. Each one is skipped if its key isn't set.

## Project structure

```
agents/
  log_ingestor/           Vigilon Intake
  threat_modeling/        Vigilon Atlas (+ attack path ranker)
  classification/         Vigilon Triage
  threat_hunter/          Vigilon Sentinel (+ baselines, threat intel)
  response_coordinator/   Vigilon Warden
  endpoint_agent/         Vigilon Sensor (Linux + Windows)
  ml_training/            synthetic data and performance monitoring
dashboard/                Flask + Socket.IO dashboard and REST API
data/
  models/                 SQLAlchemy models, promotion workflow, trained model artifacts (LFS)
  training/EDR/           endpoint telemetry datasets
  mitre/                  MITRE ATT&CK enterprise dataset
shared/                   Redis message bus, agent names, rotating log config
vulnerability_enrichment/ CVE fetcher and scheduler
scripts/                  training, retraining, evaluation and dataset tooling
test-upload-logs/         sample logs for demoing the pipeline
```

## Background

Vigilon began as a college multi-agent log ingestion project. It has since grown into a personal project for self-directed learning: an end-to-end XDR platform covering log analytics, ML threat classification, threat hunting, automated response and endpoint detection.

## License

© 2026 Eduardo Nobre. All rights reserved.
