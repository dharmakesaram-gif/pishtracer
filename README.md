# 🛡️ PhishTrace — Enterprise AI Email Threat Defense & SOC Intelligence Platform

> **Smart India Hackathon (SIH 26106)** — *AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform*  
> **Theme:** Blockchain & Cybersecurity | **Category:** Software / Enterprise Defense

---

## 🏗️ System Architecture

```
┌──────────────────────────────────────────────┐
│       Chrome Extension v2.0 Sensor           │
│   • Real-Time Gmail Inbox Telemetry          │
│   • Enterprise Defender Warning Banners      │
│   • Local Fallback Engine if Offline         │
│   • 1-Click SOC Dossier Launcher             │
└───────────────────────┬──────────────────────┘
                        │ HTTP / JSON
                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                 PhishTrace FastAPI SOC Engine (Port 8000)                   │
├─────────────────────────────────────────────────────────────────────────────┤
│ 🧠 AI / ML ENSEMBLE CLASSIFIER                                              │
│   • PyTorch 2.14 Dual-Branch Deep Neural Network (PhishNet)                 │
│   • Scikit-Learn Random Forest Classifier (15-dim forensic feature space)   │
│   • Explainable AI (XAI) Multi-Heuristic Linguistic Scorer                  │
├─────────────────────────────────────────────────────────────────────────────┤
│ 🔬 EMAIL FORENSICS & ATTACHMENT DETONATION                                  │
│   • RFC 5322 MIME & EML / MSG Multipart Parser                              │
│   • Deep Header Analysis: SPF, DKIM, DMARC Alignment Verification           │
│   • Attachment Detonation: SHA-256 / MD5, double-extension & macro checker  │
│   • URL Defanging (hxxps[://]) & IP-Host Vulnerability Scanner              │
├─────────────────────────────────────────────────────────────────────────────┤
│ 🌍 GEOLOCATION & THREAT INFRASTRUCTURE                                      │
│   • Origin IP Relay Chain Hop Isolation                                     │
│   • MaxMind GeoLite2 Geolocation & ASN Mapping                              │
│   • Infrastructure Classification (Tor Exit Nodes, VPNs, Bulletproof VPS)   │
│   • Threat Intel Feeds (AbuseIPDB, Google Safe Browsing, WHOIS Age)         │
├─────────────────────────────────────────────────────────────────────────────┤
│ 🕸️ THREAT CORRELATION & CAMPAIGN CLUSTERING                                │
│   • NetworkX Graph Engine for Coordinated Attack Fingerprinting             │
│   • Infrastructure, Sender Domain & Temporal Burst Clustering               │
├─────────────────────────────────────────────────────────────────────────────┤
│ ⚡ SOAR AUTOMATED RESPONSE PLAYBOOKS                                         │
│   • Automated Message Quarantine & Tenant-Wide Revocation                   │
│   • Network Defense Sinkhole Rules: BIND RPZ, Linux iptables, Cisco ACL    │
│   • OASIS STIX 2.1 Cyber Threat Intelligence JSON Bundle Export             │
│   • Enterprise SIEM Syslog Feeds: Splunk CIM & Elasticsearch ECS            │
│   • Publication-Grade Multi-Page PDF Forensic Reports (ReportLab)           │
│   • Cryptographic SHA-256 Tamper-Evident Evidence Hash (Chain of Custody)   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start (Production & Development)

### Option A: Run via Docker (Recommended)

```bash
docker compose up --build
```
- Access the SOC Radar at: **`http://localhost:8000/dashboard/`**
- Interactive API Swagger Docs at: **`http://localhost:8000/docs`**

---

### Option B: Local Python Installation

#### 1. Setup Backend
```bash
cd backend
pip install -r requirements.txt
pip install torch --index-url https://download.pytorch.org/whl/cpu
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

#### 2. Seed Realistic Threat Samples (Optional)
```bash
python seed_demo.py
```

#### 3. Install Chrome Extension v2.0
1. Open Google Chrome and go to `chrome://extensions/`.
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select the repository root folder (`phishtrace-extension`).
4. Open Gmail (`mail.google.com`) and open any email — PhishTrace automatically scans it in real-time!

---

## 🔬 Core Capabilities & Differentiators

### 1. Tri-Modal Hybrid AI Engine
- **PyTorch Dual-Branch Deep Neural Network (`PhishNet`)**: Combines a 15-dimensional dense feature extractor (`Linear -> BatchNorm -> LeakyReLU -> Dropout`) with an NLP token embedding bag (`EmbeddingBag -> Linear -> LeakyReLU`) and a deep fusion classification head.
- **Random Forest Ensemble**: 50 decision trees evaluating behavioral and structural dimensions.
- **Explainable AI (XAI)**: Generates human-readable evidence summaries so security analysts understand *why* a message was intercepted.

### 2. RFC 5322 EML File Drag-and-Drop Ingestion
- SOC analysts can drag and drop raw `.eml` or `.msg` files directly into the web dashboard.
- Automatically decompiles MIME boundaries, decodes quoted-printable/base64 bodies, extracts all attachments, and computes cryptographic SHA-256 / MD5 hashes.
- Flags double extensions (e.g. `Invoice.pdf.exe`) and macro payloads (`.docm`, `.xlsm`, `.iso`).

### 3. Automated SOAR Defense Playbooks
- **1-Click Message Quarantine**: Isolates malicious messages from user mailboxes with audit tracking.
- **Firewall & DNS Sinkhole Generator**: Generates copyable rules for BIND RPZ, Linux `iptables`, Windows PowerShell Firewall, and Cisco ASA ACLs.
- **OASIS STIX 2.1 Threat Bundle**: Exports cyber threat indicators conforming to international threat intelligence sharing standards (US-CERT, NATO, ISACs).
- **SIEM Integrations**: One-click export for **Splunk CIM** and **Elasticsearch ECS**.

### 4. Forensic Evidence Integrity
- Every analysis generates a deterministic **SHA-256 cryptographic hash** of all extracted indicators, timestamp, and results to satisfy legal chain-of-custody requirements under CERT-In and judicial compliance.

---

## 📡 REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/analyze` | Deep AI threat scan on JSON email payload |
| `POST` | `/api/analyze/eml` | Ingest and decompile raw `.eml` / `.msg` file with attachment detonation |
| `GET` | `/api/scans` | Paginated live stream of intercepted threats |
| `GET` | `/api/scans/{id}` | Full incident dossier details |
| `GET` | `/api/scans/{id}/report?format=pdf` | Multi-page forensic PDF report download |
| `GET` | `/api/scans/{id}/report?format=json` | Structured JSON evidence export |
| `GET` | `/api/scans/{id}/stix` | OASIS STIX 2.1 Threat Intelligence Bundle |
| `GET` | `/api/scans/{id}/siem?format=splunk` | Splunk CIM / Elasticsearch syslog event |
| `POST` | `/api/soar/quarantine/{id}` | Execute SOAR message quarantine playbook |
| `GET` | `/api/soar/block-rules/{id}` | Generate firewall & DNS sinkhole rules |
| `GET` | `/api/campaigns` | NetworkX clustered coordinated attack campaigns |
| `GET` | `/api/stats` | SOC radar metrics & global geolocation distribution |

---

## 🛠️ Technology Stack

- **Extension**: Chrome Extension MV3, Vanilla JS, CSS Glassmorphism
- **Backend API**: Python 3.12, FastAPI, Uvicorn, SQLAlchemy (Async), aiosqlite
- **Deep Learning**: PyTorch 2.14 (`torch.nn`, Adam Optimizer, BCELoss)
- **Machine Learning**: Scikit-Learn (`RandomForestClassifier`), Joblib
- **Threat Intel & Geo**: MaxMind GeoLite2, AbuseIPDB, Google Safe Browsing
- **Graph Correlation**: NetworkX
- **Document Generation**: ReportLab
- **Standards**: OASIS STIX 2.1, Splunk CIM, Elastic Common Schema (ECS), RFC 5322 MIME
- **Deployment**: Docker, Docker Compose

---

## 📜 License

Built for the **Smart India Hackathon 2026** — Problem Statement **SIH 26106**.  
Developed by Dharma Kesaram (`dharmakesaram-gif`).
