<p align="center">
  <img src="docs/assets/vigilon-banner.svg" alt="Vigilon XDR Platform" width="100%">
</p>

# Vigilon

**Multi-Agent XDR Platform for Unified Log and Endpoint Threat Defense**

Vigilon is a self-built extended detection and response (XDR) platform. Six cooperating agents ingest logs, model the attack surface, classify threats with machine learning, hunt for multi-stage attacks, coordinate responses, and collect live telemetry from Linux and Windows endpoints. Analysts work everything from a single real-time dashboard.

The endpoint detection side was inspired by CrowdStrike's research on machine-learning malware detection in the Falcon platform: behavioural models score every process and network event on the endpoint itself, before anything reaches the analyst. Since v3.0 the endpoint sensors also scan every new executable and document with static ML models, and can quarantine or delete a malicious file on their own, validated against real malware families.

---

## The agents

| Agent | Role | What it does |
|---|---|---|
| **Vigilon Intake** | Log ingestion | Parses syslog, CSV and JSON logs, normalises timestamps and fields, and enriches events before storage |
| **Vigilon Atlas** | Threat modeling and attack paths | Infers the system architecture from logs, builds an attack graph in Neo4j, maps vulnerabilities to MITRE ATT&CK techniques, and ranks attack paths by feasibility |
| **Vigilon Triage** | Threat classification | Classifies threats with a Word2Vec + metadata + calibrated Gradient Boosting model, with confidence scoring and CVSS-based risk and severity |
| **Vigilon Sentinel** | Threat hunting | Correlates threats by entity, matches IOCs, flags statistical anomalies (z-score baselines), detects multi-stage attacks with an ML pattern model, and pulls external intel from AlienVault OTX, MISP and AbuseIPDB |
| **Vigilon Warden** | Response coordination | Applies response rules (monitor, alert, contain, isolate, block, escalate) and notifies the right analysts by email, Slack or Microsoft Teams |
| **Vigilon Sensor** | Endpoint collector (EDR) | Lightweight Linux and Windows agents with three on-device ML models (**Pulse** for processes, **Beacon** for network connections, **Spectra** for files), automatic quarantine of malicious files, and analyst actions such as killing a process or restoring a quarantined file |

### Sensor models

| Model | What it scores | How |
|---|---|---|
| **Pulse** | Every new process | Behavioural features from the command line, parent chain and file locations (encoded commands, LOLBins, permission changes, shadow-copy deletion, scheduled tasks, ...) |
| **Beacon** | Every outbound connection | Port, address and process context, to catch reverse shells, C2 and SMB lateral movement |
| **Spectra** | Every new or renamed file in watched folders | Static analysis without running the file: PE and ELF headers, sections, entropy and imports for executables, and document structure, embedded JavaScript and URLs, entropy and byte patterns for PDF and Office documents |

On Windows the sensor also scans process memory for executable-and-writable (RWX) regions, a sign of injected or reflectively loaded code. This scanner is rule-based, not ML.

## Architecture

```mermaid
flowchart LR
    subgraph Endpoints
        L["Vigilon Sensor<br/>Linux · auditd / psutil · inotify"]
        W["Vigilon Sensor<br/>Windows · Sysmon / psutil · ReadDirectoryChangesW"]
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
- **Sensor activity feed**: every event a sensor reports, labelled by the model that scored it (Pulse, Beacon, Spectra)
- **Quarantine panel**: every file a sensor quarantined, with the model, score, host and time. **Restore** or **Delete** sends the action to the sensor, and if the sensor is offline it runs when it reconnects
- **Attack surface**: assets, vulnerabilities and ranked attack paths
- **Agent control**: start and stop agents, check health via Redis heartbeats, and stream their logs live
- **Model registry**: every retrained model is registered with its metrics and must be approved by a human before it is deployed (hot-reloaded without a restart)
- **Analyst management** with roles, notification thresholds, JWT authentication, forced password changes and email password reset
- **Sensor health alerts**: a sensor that goes silent is flagged within a minute, so stopping the agent can't hide an attack
- **Reviewer analytics** and a full audit trail of response actions and notifications
- **Log upload**, which triggers the whole agent pipeline end to end

## Machine learning

- **Threat classification (Triage):** Word2Vec text embeddings combined with structured metadata features feed a Gradient Boosting classifier with probability calibration. Each model generation (v2 to v8) is kept in `data/models/threat_classifier_v*`.
- **Quality gates:** a new model is only promoted if it meets thresholds for macro-F1, accuracy, average confidence and calibration error (ECE and Brier score). All thresholds are configurable through `THREAT_*` environment variables.
- **Endpoint behaviour models (Pulse and Beacon):** separate process and network models (Random Forest and Gradient Boosting, with SMOTE to balance the classes). Each operating system has its **own** model set, built with shared feature-extraction code, so tuning the Windows model can never regress the Linux one. Linux benign telemetry is captured with auditd, and Windows benign telemetry with Sysmon on a FLARE-VM analysis machine. The Windows process model was retrained in v3.0 on telemetry from real malware detonations, with 8 new features for ransomware and evasion behaviour (22 in total).
- **Static file models (Spectra):** Random Forest models over 279 static features for executables (PE on Windows, ELF on Linux) and 280 for documents (PDF, Word, Excel, RTF). Trained on real malware from 11 families and on benign system binaries and documents. Nothing is executed: the features come from parsing the file.
- **Pattern detection (Sentinel):** an ML model over threat-sequence features detects multi-stage attacks, alongside fuzzy matching of tactic sequences.
- **Instrumentation:** inference latency, false-positive rate and model accuracy are tracked at runtime, with OpenTelemetry counters on the agents.

## Endpoint detection — live validation

<p align="center">
  <img src="docs/assets/edr-console.png" alt="Vigilon EDR console — live endpoint detections" width="90%">
</p>

### Linux sensor

Vigilon Sensor's Linux endpoint models were validated against a live attack suite in an isolated VM, with the agent running as a production systemd service (kernel-level `auditd` collection, ML-first scoring).

| Metric | Result |
|---|---|
| Live false-positive rate | **0.00%** — 0 benign flags across 12,482 real process decisions |
| In-sample benign FP rate (offline) | 0.056% (9 / 16,010) |
| Attack detection — reverse shells & LOLBins (B1–B10) | **100%** flagged |
| Generalisation to unseen command structures (B11) | 5 / 6 novel forms caught |
| Network reverse-shell detection | ML **0.82**, heuristic 0.74 — validated live |
| Promotion gate | ≤ 5% FP, ≥ 80% detection, process/network F1 ≥ 0.85 |

The models are trained on ~50,000 real benign process events captured on a live Linux host, combined with catalogued attack behaviour grounded in GTFOBins and MITRE ATT&CK — covering **T1059** (command and scripting interpreters), **T1071** (application-layer C2), reverse shells over `/dev/tcp`, `/dev/udp`, socat/php/perl, and living-off-the-land binaries.

Several of these results came from debugging the **telemetry pipeline**, not the model: `auditd` hex-encodes special-character arguments (which were silently truncating payloads before they reached the model), and binaries that log under versioned or aliased names (`nc.traditional`, `socat1`, `python3.13`) had to be normalised before detection worked. In each case the fix was in how events were *captured*, not the ML.

### Windows sensor

The Windows sensor was validated live on a FLARE-VM analysis machine in an isolated host-only network. It collects process and network events from **Sysmon** and scores them with a Windows-specific model.

| Metric | Result |
|---|---|
| Process model (held-out test set, v3.0 retrain) | precision **0.96**, recall **1.00**, F1 0.98, ROC-AUC 0.9999 |
| Live benign check (admin commands, two passes, plus normal desktop use) | **0** process alerts |
| Live attack triggers W1–W10 (encoded PowerShell, download cradles, certutil, regsvr32, shadow-copy deletion, run-key persistence, dropped executables) | **10 / 10** flagged (scores 0.86–0.99) |
| Network reverse shell to the analyst host (W12) | flagged live (ML **0.82**); the analyst's `kill_process` action worked from the dashboard |
| Known weak case (W11) | missed (0.33–0.36) |

Two Windows-specific problems were found and fixed along the way. First, a feature treated any path under `C:\Users\` or `C:\ProgramData\` as a "drop location", which flagged ordinary commands such as listing a user folder (0.74 → 0.13 after the fix). Second, the training data marked every attack binary as previously seen. On a live endpoint an attack is usually seen for the first time, so most attacks scored under the alert threshold until the data was corrected. Network connections to `127.0.0.1` also caused false positives and are now skipped on both sensors.

## Real malware — detection and protection (v3.0)

### Live detonation results (Windows)

Real samples from 12 malware families were detonated one at a time on the FLARE-VM sensor, in an isolated network with the VM restored from a clean snapshot between samples. C2-dependent families were run a second time with INetSim answering their network traffic. A family counts as **detected** if at least one model raised an alert.

| Family | Type | Pulse (process) | Spectra (file) | Beacon (network) | Result |
|---|---|---|---|---|---|
| NjRAT | RAT | **0.98** | **0.95** | 0.18 | **Detected** (3 models) |
| WannaCry | Ransomware | **0.91** | **0.99** (30+ files) | 0.18 | **Detected** (2 models) |
| LockBit | Ransomware | 0.09 | **0.75** | **0.82** (SMB lateral movement) | **Detected** (2 models) |
| BadRabbit | Ransomware | **0.80** | — | — | **Detected** |
| DarkComet | RAT | 0.29 | **0.77** | — | **Detected** |
| AgentTesla | Info-stealer | 0.01 | **0.98** | — | **Detected** (file only) |
| RedLine | Info-stealer | 0.01 | **0.81** | — | **Detected** (file only) |
| StealC | Info-stealer | 0.01 | **0.77** | — | **Detected** (file only) |
| Macro document → Java RAT | Document dropper | 0.35 | 0.71 | — | Partial |
| Emotet | Loader | 0.01 | — | — | Missed |
| TeslaCrypt | Ransomware | 0.02 | — | — | Weak (old family, little activity) |
| FakeAV | Scareware | — | — | — | Crashed on launch (untestable) |

**8 / 12 families detected**, up from 4 / 12 before Spectra and 7 / 12 before the process-model retrain. The retrain moved WannaCry's process score from 0.15 to 0.91 and NjRAT's from 0.85 to 0.98.

The models work as layers. Info-stealers that wait for a C2 server do almost nothing a behavioural model can see, but Spectra flags them the moment they're written to disk. BadRabbit is invisible to static analysis but its scheduled tasks and `rundll32` ordinal calls were caught by Pulse. LockBit was the only family the network model caught.

### Spectra model metrics

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|
| Windows executables (PE) | 0.986 | 0.957 | **1.000** | 0.978 | 0.9998 |
| Documents (PDF / Office / RTF) | 0.969 | 0.913 | 0.875 | 0.894 | 0.980 |
| Linux executables (ELF) | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |

### Automatic response

When Spectra scores a file, the sensor can act on its own, without waiting for an analyst:

| Score | Action |
|---|---|
| ≥ 0.95 | File deleted |
| 0.75 – 0.94 | File moved to the sensor's quarantine folder |
| below 0.75 | Alert only (from 0.70) |

Auto-response runs in `dry_run` mode by default (it only logs what it would do) and is switched on per sensor with `AUTO_RESPONSE_MODE=enforce`. Every quarantined file appears in the dashboard's quarantine panel, so a false positive can be restored in one click. Restore and delete were validated live end to end: dashboard → database → sensor → file moved back or removed → result recorded.

### False-positive tuning

Before enforcing auto-response, both sensors ran through a soak test of normal daily use. The Linux sensor came back clean. The Windows sensor surfaced four kinds of false positive, which were fixed and then re-tested:

- **Partial downloads** (`.crdownload`, `.part`, ...) look like broken binaries. They're skipped, and the finished file is scanned when the browser renames it.
- **Windows Defender signature updates** (`.vdm`) are packed blobs of malware signatures, so they look malicious. They're skipped.
- **Microsoft-signed tools** such as the Sysinternals suite scored up to 0.95. Spectra now checks the Authenticode signature (embedded and catalog-signed): a valid, unrevoked signature from a trusted publisher reduces the score (0.95 → 0.38). Unsigned files are unaffected. The whole Sysinternals suite now extracts with zero alerts.
- **Browser cache copies** of downloaded files are skipped, so each download is scored once.

### Evasion resistance (Windows)

Common ways of blinding a user-mode EDR (unhooking `ntdll.dll`, direct syscalls) don't apply here: Vigilon never hooks anything, and its process and network events come from Sysmon's kernel driver. On top of that:

- **Image tampering detection:** Sysmon event 25 flags process hollowing and module stomping (T1055.012 / T1055.001).
- **Memory anomaly scanning:** RWX regions in running processes are reported. In testing, a benign baseline had 0 critical findings and an NjRAT detonation had 36.
- **Silent-sensor alerts:** if a sensor stops reporting, the dashboard raises an incident within about a minute.

> **Honest limitations.** The 5% false-positive gate is deliberately generous — production EDRs target ~0.1%. Real malware validation so far is **Windows only**: the Linux sensor has the same Spectra, auto-response and file-skip code, but it hasn't been tested against live Linux malware yet. The Linux ELF model's perfect scores come from a small test set (103 files, three botnet families) and will drop as more families are added. The network model is still trained on synthetic connections only, which is why it caught just one family. Behavioural detection of C2-dependent malware is weak without a C2 to talk to — Emotet, with a hard-coded C2 address, was missed entirely. The document model doesn't analyse Office macros yet (the macro and OLE-stream features were empty at training time), which is part of why the macro dropper was only a partial detection. The Windows process model is trained on 1,604 events, far fewer than a production model. Measuring where the system is generous matters more than hiding it.

## Tech stack

| Area | Technology |
|---|---|
| Backend and API | Python, Flask, Flask-SocketIO, Flask-JWT-Extended |
| Data | PostgreSQL + SQLAlchemy, Neo4j (attack graphs), Redis (pub/sub and heartbeats) |
| ML | scikit-learn, gensim (Word2Vec), imbalanced-learn, NumPy, pandas, NLTK |
| Static analysis | pefile (PE), custom ELF parser, pypdf, Authenticode signature checks via PowerShell (Windows) |
| Threat intel | MITRE ATT&CK (`mitreattack-python`), Vulners CVE API, AlienVault OTX, MISP, AbuseIPDB |
| Endpoint | psutil, Linux auditd and inotify, Windows Sysmon and ReadDirectoryChangesW (via pywin32), python-socketio client |
| Ops | Docker, APScheduler, OpenTelemetry, systemd and Windows Task Scheduler for the endpoint sensors |

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

# Windows (Administrator PowerShell; Sysmon must be installed and running)
pip install -r requirements-windows.txt
$env:BACKEND_URL="http://<platform-host>:5000"
$env:PROCESS_COLLECTOR="sysmon"     # read Sysmon events ("polling" falls back to psutil)
python -m agents.endpoint_agent.windows_agent
```

To run a sensor as a service that starts at boot, use the installers in `deploy/edr/` (`install.sh` for systemd, `install.ps1` for a SYSTEM scheduled task).

Upload any file from `test-upload-logs/` in the dashboard to watch the full pipeline run.

> The threat-origins globe needs the free MaxMind **GeoLite2 City** database, which can't be redistributed. Download it from MaxMind and save it as `data/GeoLite2-City.mmdb`.

### Docker image

The root `Dockerfile` builds the dashboard and API. At startup it waits for PostgreSQL, initialises the schema, downloads the NLTK corpora and launches the dashboard (see `docker/entrypoint.sh`).

## Configuration

All configuration comes from environment variables (`.env`). Secrets never live in the code.

| Group | Variables |
|---|---|
| Core | `DATABASE_URL`, `JWT_SECRET_KEY`, `DEFAULT_PASSWORD`, `SKIP_DB_SEED` |
| Services | `REDIS_HOST`, `REDIS_PORT`, `REDIS_DB`, `NEO4J_URI`, `NEO4J_USERNAME`, `NEO4J_PASSWORD` |
| Threat intel | `VULNERS_API_KEY`, `OTX_API_KEY`, `MISP_API_URL`, `MISP_API_KEY`, `ABUSEDB_API_KEY`, `CVE_MIN_YEAR` |
| Notifications | `SMTP_SERVER`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_NAME`, `SLACK_ENABLED`, `SLACK_WEBHOOK_URL`, `TEAMS_ENABLED`, `TEAMS_WEBHOOK_URL` |
| Models | `PATTERN_MODEL_PATH`, `EDR_MODEL_DIR`, `THREAT_CALIBRATION_METHOD`, `THREAT_GATE_*`, `THREAT_WINNER_*` |
| Endpoint sensor | `BACKEND_URL`, `EDR_API_KEY`, `PROCESS_COLLECTOR` (`polling`, `auditd` on Linux, `sysmon` on Windows), `EDR_MODEL_DIR` (defaults to `data/models/EDR` on Linux and `data/models/EDR/windows` on Windows), `AUTO_RESPONSE_MODE` (`dry_run` by default, `enforce` to act), `ML_FIRST_MODE`, `ML_EVENT_MIN_SCORE`, `TELEMETRY_POLL_INTERVAL`, `PROCESS_EVENT_MIN_SCORE`, `PROCESS_EVENT_DEDUP_WINDOW_SEC` |
| Logging | `LOG_MAX_MB`, `LOG_RETENTION_DAYS` |

All threat-intel and notification integrations are optional. Each one is skipped if its key isn't set.

## Project structure

```
agents/
  log_ingestor/              Vigilon Intake
  threat_modeling/           Vigilon Atlas (+ attack path ranker)
  classification/            Vigilon Triage
  threat_hunter/             Vigilon Sentinel (+ baselines, threat intel)
  response_coordinator/      Vigilon Warden
  endpoint_agent/            Vigilon Sensor (Linux + Windows)
  feature_extractor.py       Pulse and Beacon features
  static_feature_extractor.py  Spectra features (PE, ELF, documents) + Authenticode check
  ml_training/               synthetic data and performance monitoring
dashboard/                   Flask + Socket.IO dashboard and REST API
data/
  models/                    SQLAlchemy models, promotion workflow, trained model artifacts
    EDR/                     endpoint models: Linux (root and linux/), Windows (windows/)
  training/EDR/              endpoint telemetry datasets
  training/static/           Spectra feature datasets (sample files are not published)
  mitre/                     MITRE ATT&CK enterprise dataset
shared/                      Redis message bus, agent names, email, rotating log config
vulnerability_enrichment/    CVE fetcher and scheduler
scripts/                     training, retraining, evaluation and dataset tooling
deploy/edr/                  sensor installers: systemd service (Linux), scheduled task (Windows)
test-upload-logs/            sample logs for demoing the pipeline
```

## Background

Vigilon has been built incrementally since **February 2026**, starting as a multi-agent log-analytics pipeline — ingestion, threat modeling, ML classification, threat hunting and automated response. In **June/July 2026** the endpoint-detection work — on-device ML sensors scoring process and network behaviour before anything reaches an analyst — extended it from a log-analytics system into a full **XDR** platform, correlating endpoint, network and log telemetry under one pipeline. In **November 2026** the sensors moved from catalogued attacks to **real malware**: static file analysis, a retrained process model, automatic quarantine and live detonation testing.

It is a self-directed learning project. Every architecture decision — from the VM isolation design to keeping a strict false-positive gate on model promotion — is deliberate and documented, with the goal of understanding how a real EDR/XDR works by building one end to end rather than wiring together off-the-shelf parts.

**Next:** a cloud deployment for a small closed group of testers, with per-user accounts and a one-click sensor installer, followed by live Linux malware testing and a macOS sensor.

## License

© 2026 Eduardo Nobre. All rights reserved.
