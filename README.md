# SentinelAI

**Behavioral Anomaly Detection and Explainable Security Risk Assessment**

SentinelAI is an AI-powered security analytics prototype that learns normal entity behavior, detects deviations from behavioral patterns, and combines machine-learning anomaly detection with deterministic security signals to produce explainable risk scores.

The system focuses on **behavioral context rather than static rules alone**, helping identify suspicious activity such as brute-force authentication, impossible travel, credential stuffing, lateral movement, and device spoofing.

---

## Problem

Traditional security monitoring often relies on predefined signatures and static thresholds. These approaches can struggle when an attacker uses valid credentials or performs actions that appear legitimate in isolation.

SentinelAI approaches the problem by building a behavioral baseline for each entity and asking:

> **Is this activity unusual for this specific entity, and is there enough security evidence to consider it risky?**

---

## Key Features

- Per-entity behavioral profiling
- Secure telemetry ingestion and validation
- Synthetic baseline generation for normal user activity
- Controlled attack injection
- Event-level behavioral feature extraction
- Sequential and time-window features
- Profile-deviation detection
- Isolation Forest anomaly detection
- Hybrid ML + deterministic risk scoring
- Explainable 0–100 security risk scores
- FastAPI-based analysis API
- Interactive Swagger documentation
- Strict typing, validation, linting, and automated tests

---

## Supported Attack Scenarios

SentinelAI currently simulates and evaluates five behavioral attack patterns:

| Attack | Behavioral Pattern |
|---|---|
| Brute Force | Dense failed authentication attempts against one identity |
| Credential Stuffing | One source attempting authentication across multiple identities |
| Impossible Travel | Consecutive activity from geographically impossible locations |
| Lateral Movement | Rapid access to novel and sensitive resources |
| Device Spoofing | Known device identity presenting an unexpected fingerprint |

Attack injection is controlled so malicious events remain a small portion of the synthetic dataset.

---

## System Architecture

```text
                         ┌──────────────────────┐
                         │   Security Events    │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │ Secure Ingestion     │
                         │ Validation/Sanitize  │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │ Behavioral Profiles  │
                         │ Per Entity Baseline  │
                         └──────────┬───────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │      Feature Engineering      │
                    │                               │
                    │ • Event features              │
                    │ • Profile deviations          │
                    │ • Sequential/window features  │
                    └───────────────┬───────────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │   Isolation Forest   │
                         │   Anomaly Evidence   │
                         └──────────┬───────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │      Hybrid Risk Scorer       │
                    │                               │
                    │ ML Evidence + Security Rules  │
                    └───────────────┬───────────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │  Explainability      │
                         │  Risk Score 0–100    │
                         │  Reasons + Severity  │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │     FastAPI API      │
                         │    POST /analyze     │
                         └──────────────────────┘
```

---

## Behavioral Feature Engineering

SentinelAI converts raw telemetry into a **23-feature numeric representation**.

Examples include:

### Event Features

- Hour of day
- Day of week
- Weekend activity
- Authentication failure
- Session duration
- Command count
- Geographic coordinates

### Profile-Deviation Features

- New source IP
- New resource
- New device
- Device fingerprint mismatch
- Access-hour deviation
- Session-duration deviation
- Standardized behavioral deviations

### Sequential Features

- Events within 10 minutes
- Failed logins within 10 minutes
- Unique resources within 30 minutes
- Resource access velocity
- Source-IP identity fanout
- Distance from previous activity
- Implied travel speed

These features allow SentinelAI to reason about both an individual event and its surrounding behavioral context.

---

## Machine Learning

SentinelAI uses an **Isolation Forest** trained on normal behavioral activity.

The model is unsupervised: it learns the structure of normal behavior without requiring attack labels during training.

However, statistical anomaly detection alone can miss security-specific patterns. SentinelAI therefore uses a hybrid approach:

```text
Isolation Forest Evidence
          +
Behavioral Security Signals
          ↓
Hybrid Risk Score
          ↓
Explainable Security Decision
```

The ML model remains an evidence source rather than the sole authority for security decisions.

---

## Evaluation Results

Evaluation was performed on a controlled synthetic dataset containing normal activity and all five supported attack types.

### Isolation Forest vs Hybrid Detection

| Metric | Isolation Forest | Hybrid SentinelAI |
|---|---:|---:|
| Precision | 0.833 | **1.000** |
| Recall | 0.769 | **0.808** |
| F1 Score | 0.800 | **0.894** |
| False Positive Rate | 2.548% | **0.000%** |

### Per-Attack Detection

| Attack | Isolation Forest | Hybrid |
|---|---:|---:|
| Brute Force | 10/11 | 7/11 |
| Credential Stuffing | 6/9 | 8/9 |
| Device Spoofing | 0/1 | **1/1** |
| Impossible Travel | 0/1 | **1/1** |
| Lateral Movement | 4/4 | **4/4** |

These results demonstrate why SentinelAI uses a hybrid architecture.

For example, Isolation Forest did not independently detect the evaluated impossible-travel and device-spoofing events. Behavioral evidence allowed the hybrid detector to recover both cases.

> **Note:** These results are from SentinelAI's controlled synthetic evaluation and should not be interpreted as production-world detection guarantees.

---

## Explainable Risk Scoring

SentinelAI does not return only `normal` or `anomalous`.

Each analyzed event receives:

- Risk score from **0–100**
- Severity level
- Suspicious/not-suspicious decision
- ML anomaly evidence
- Behavioral evidence
- Human-readable reasons

Example:

```text
Risk Score: 55/100
Severity: MEDIUM

Evidence:
- Travel between consecutive events would require 19,137 km/h
- Consecutive activity occurred approximately 9,569 km apart

Isolation Forest flagged: False
Behavioral contribution: 55
```

This demonstrates an important design principle:

> **A statistical anomaly is evidence, not automatically a security incident.**

Likewise, a security-specific behavioral pattern can still be detected even when the unsupervised model does not independently flag it.

---

## API

SentinelAI exposes its detection pipeline through FastAPI.

### Health Check

```http
GET /health
```

Example response:

```json
{
  "status": "healthy",
  "service": "SentinelAI",
  "version": "0.1.0"
}
```

### Analyze Security Event

```http
POST /analyze
```

The endpoint validates an incoming security event and evaluates it using:

```text
Validation
   ↓
Behavioral Context
   ↓
Feature Engineering
   ↓
Isolation Forest
   ↓
Hybrid Risk Scoring
   ↓
Explainability
```

Example response:

```json
{
  "event_id": "EVENT_DEMO_001",
  "entity_id": "USER_00001",
  "risk_score": 21.59,
  "severity": "low",
  "is_suspicious": false,
  "summary": "LOW risk activity observed with a risk score of 22/100. No significant threat indicators were detected.",
  "reasons": [
    "Activity occurred far outside the entity's typical access hours",
    "Isolation Forest classified the event as statistically anomalous"
  ],
  "ml_anomaly_score": 0.0159,
  "ml_flagged": true,
  "ml_contribution": 11.59,
  "behavioral_contribution": 10.0
}
```

In this example, Isolation Forest considers the event statistically unusual, but the combined evidence is insufficient to classify it as suspicious.

---

## Security by Design

Security-related validation is handled before events enter the detection pipeline.

The ingestion layer includes:

- Strict schema validation
- Rejection of unexpected fields
- Payload-size restrictions
- Nested payload depth restrictions
- Control-character sanitization
- IP address validation
- Geographic coordinate validation
- Typed security-domain models

Potentially hostile text is treated as **untrusted telemetry data**, not as executable instructions.

This design also keeps security decisions deterministic and prevents generative AI from controlling risk classification.

---

## Project Structure

```text
src/sentinel/
├── api/                 # FastAPI application and analysis service
├── detection/           # Isolation Forest and hybrid risk scoring
├── domain/              # Security domain models
├── explainability/      # Deterministic security explanations
├── features/            # Behavioral feature engineering
├── ingestion/           # Secure telemetry ingestion
├── profiling/           # Entity behavioral baselines
└── synthetic/           # Normal activity and attack simulation

tests/
├── security/
└── unit/
```

---

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/kunalp-singh/Sentinel-AI.git
cd Sentinel-AI
```

### 2. Create a virtual environment

```bash
python3.11 -m venv .venv
source .venv/bin/activate
```

### 3. Install the project

```bash
pip install -e ".[dev]"
```

### 4. Run quality checks

```bash
ruff check .
pytest
mypy src
```

The current implementation contains **138 automated tests** covering domain validation, secure ingestion, synthetic behavior, attack simulation, feature engineering, profiling, detection, risk scoring, explainability, and API behavior.

---

## Running the API

Start SentinelAI with:

```bash
uvicorn sentinel.api.app:app --reload
```

The API runs locally on port `8000`.

Open the interactive Swagger interface at:

```text
http://127.0.0.1:8000/docs
```

Available endpoints:

```text
GET  /
GET  /health
POST /analyze
```

---

## Technology Stack

- **Python 3.11**
- **FastAPI**
- **Pydantic**
- **scikit-learn**
- **pandas**
- **NumPy**
- **Faker**
- **Pytest**
- **Ruff**
- **mypy**

---

## Design Decisions

### Why Isolation Forest?

Security telemetry contains significantly more normal activity than malicious activity. Isolation Forest provides an unsupervised way to identify statistically unusual behavior without requiring a large labeled attack dataset.

### Why Hybrid Detection?

An anomaly is not necessarily malicious, and some security attacks have strong domain-specific indicators that an unsupervised model may miss.

SentinelAI therefore combines ML anomaly evidence with behavioral security signals.

### Why No LLM in the Detection Path?

Risk scoring and explanations are deterministic.

An LLM could later be added as an optional analyst-summary layer, but it should not determine whether an event is malicious or calculate its security risk score.

This keeps the security decision reproducible and auditable.

---

## Prototype Scope

SentinelAI was designed as a focused prototype rather than a production SIEM platform.

For demonstration, the API initializes synthetic behavioral profiles and an in-memory Isolation Forest model.

A production implementation could extend the architecture with:

- Persistent behavioral profiles
- Streaming telemetry ingestion
- Versioned model storage
- Authentication and authorization
- Alert persistence
- Model drift monitoring
- SIEM/SOC integrations

These are intentionally outside the current prototype scope.

---

## Future Improvements

Potential extensions include:

- Persistent entity profiles
- Online/streaming profile updates
- Model persistence and versioning
- Additional behavioral attack patterns
- Analyst dashboard
- Alert investigation workflow
- Real-world security datasets
- Optional LLM-generated SOC summaries based strictly on deterministic evidence

---

## Disclaimer

SentinelAI is a security research and demonstration prototype. Detection metrics reported here are based on controlled synthetic data and are not production security guarantees.
