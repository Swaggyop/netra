<p align="center">
  <img src="https://img.shields.io/badge/NETRA-v2.0-000000?style=for-the-badge&labelColor=000000&color=111111" alt="NETRA v2.0"/>
  <img src="https://img.shields.io/badge/SIH_2025-Problem_26151-000000?style=for-the-badge&labelColor=000000&color=222222" alt="SIH 2025"/>
  <img src="https://img.shields.io/badge/Python-3.12+-000000?style=for-the-badge&logo=python&logoColor=white&labelColor=000000&color=111111" alt="Python 3.12+"/>
  <img src="https://img.shields.io/badge/Next.js-16-000000?style=for-the-badge&logo=nextdotjs&logoColor=white&labelColor=000000&color=111111" alt="Next.js 16"/>
  <img src="https://img.shields.io/badge/License-MIT-000000?style=for-the-badge&labelColor=000000&color=222222" alt="MIT License"/>
</p>

<br/>

<h1 align="center">
  <code>Ψ</code> NETRA
</h1>

<p align="center">
  <strong>Networked Entity Tracking & Reconnaissance Architecture</strong>
</p>

<p align="center">
  <em>Automated Dark Web Intelligence & Threat Disruption Platform for Law Enforcement</em>
</p>

<p align="center">
  <code>━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</code>
</p>

<p align="center">
  <sub>
    22 live crawlers · 23,000+ intelligence items · Real-time graph analysis · Court-ready exports
  </sub>
</p>

<br/>

---

## Table of Contents

```
 00 ─── Overview
 01 ─── Problem Statement
 02 ─── Architecture
 03 ─── Data Flow Pipeline
 04 ─── System Components
 05 ─── Intelligence Adapters (22 Crawlers)
 06 ─── API Reference
 07 ─── Frontend Pages
 08 ─── Database Schema
 09 ─── Security & Compliance
 10 ─── Quick Start
 11 ─── Environment Variables
 12 ─── Make Targets
 13 ─── Project Structure
 14 ─── Tech Stack
 15 ─── Data Sources & References
 16 ─── License
```

---

## `00` Overview

**NETRA** is an end-to-end dark web intelligence platform that automates the entire threat intelligence lifecycle — from raw data collection on Tor hidden services, ransomware trackers, and blockchain explorers to structured analysis, persona linking, and court-admissible evidence generation.

Built for Indian law enforcement agencies (CERT-In, NIA, State Cyber Cells), NETRA operates exclusively on **open-source intelligence (OSINT)** and public APIs. No unauthorized access is ever performed.

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│    "Eyes where darkness hides"                              │
│                                                             │
│    NETRA sees what traditional tools can't:                 │
│    ▸ Anonymous dark web actors                              │
│    ▸ Cryptocurrency money flows                             │
│    ▸ Hidden service infrastructure                          │
│    ▸ Cross-platform persona links                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Key Capabilities

| Capability | Description |
|:-----------|:------------|
| **22 Live Crawlers** | Zero-cost public data adapters — no API keys required |
| **Real-time Monitoring** | WebSocket event feed with severity-scored alerts |
| **Graph Intelligence** | Neo4j-powered relationship mapping (actors ↔ wallets ↔ infrastructure) |
| **Persona Linking** | Bayesian evidence model connecting anonymous handles across platforms |
| **Blockchain Analysis** | BTC/ETH address tracking, transaction flow, wallet clustering |
| **Court-ready Exports** | PDF, CSV, JSON evidence packages (IT Act §65B compliant) |
| **Dockerized Deployment** | Single `docker compose up` — 6 services, under ₹5,000/month |

---

## `01` Problem Statement

> **SIH 2025 — Problem ID: 26151**

India faces an escalating dark web threat landscape:

```
  16,00,000+   cybercrime complaints annually (NCRP 2023-24)
  67%          of ransomware attacks involve dark web forums (CERT-In)
  $1.7B        dark web marketplace revenue in 2023 (Chainalysis)
  14 months    average law enforcement dark web investigation (Europol)
```

**The gap:** No unified Indian platform exists to correlate dark web actors, cryptocurrency wallets, and hidden infrastructure in real-time. Existing tools (Recorded Future, DarkOwl) cost $200K-$500K/year and aren't built for Indian law enforcement workflows.

**NETRA bridges this gap** at a fraction of the cost, with India-first compliance (IT Act, CERT-In, NCIIPC).

---

## `02` Architecture

```mermaid
graph TB
    subgraph Sources["DATA SOURCES"]
        direction LR
        S1["Tor Network"]
        S2["Ransomware Trackers"]
        S3["Blockchain Explorers"]
        S4["OSINT Feeds"]
        S5["Cert Transparency"]
    end

    subgraph Collection["COLLECTION LAYER"]
        CW["Celery Workers\n22 Adapters"]
        CB["Celery Beat\nScheduler"]
    end

    subgraph Storage["STORAGE LAYER"]
        direction LR
        PG[("PostgreSQL 16\nActors, Entities\nAudit Logs")]
        RD[("Redis 7\nReal-time Events\nTask Broker")]
        N4[("Neo4j 5\nKnowledge Graph\nRelationships")]
    end

    subgraph Backend["APPLICATION LAYER"]
        API["FastAPI Backend\nREST + WebSocket\nJWT Auth, RBAC"]
    end

    subgraph Frontend["PRESENTATION LAYER"]
        UI["Next.js 16 Dashboard\nReact 19 + Cytoscape.js\nReal-time Graph Explorer"]
    end

    S1 & S2 & S3 & S4 & S5 --> CW
    CB -.->|schedule| CW
    CW --> PG & RD & N4
    PG & RD & N4 --> API
    API --> UI
    API -.->|WebSocket| UI

    style Sources fill:#1a1a1a,stroke:#333,color:#fff
    style Collection fill:#111,stroke:#444,color:#fff
    style Storage fill:#0d0d0d,stroke:#333,color:#fff
    style Backend fill:#111,stroke:#444,color:#fff
    style Frontend fill:#1a1a1a,stroke:#333,color:#fff
```

### Docker Service Topology

```mermaid
graph LR
    subgraph Docker["docker-compose.yml"]
        PG["postgres:16-alpine\n:5433"]
        N4["neo4j:5-community\n:7474 :7687"]
        RD["redis:7-alpine\n:6379"]
        API["api / uvicorn\n:8000"]
        WK["worker / celery"]
        FE["frontend / next.js\n:3000"]
    end

    API --> PG & N4 & RD
    WK --> PG & N4 & RD
    FE -->|HTTP + WS| API
    WK -.->|broker| RD

    style Docker fill:#0a0a0a,stroke:#333,color:#ccc
    style PG fill:#336791,stroke:#fff,color:#fff
    style N4 fill:#008CC1,stroke:#fff,color:#fff
    style RD fill:#DC382D,stroke:#fff,color:#fff
    style API fill:#009688,stroke:#fff,color:#fff
    style WK fill:#6a1b9a,stroke:#fff,color:#fff
    style FE fill:#000,stroke:#fff,color:#fff
```

---

## `03` Data Flow Pipeline

```mermaid
flowchart TD
    subgraph P1["PHASE 1: COLLECTION"]
        BEAT["Celery Beat\nScheduler"] -->|dispatch| WORKER["Celery Workers"]
        WORKER --> A1["ransomware_tracker.py\nRansomWatch, RansomLook"]
        WORKER --> A2["abuse_ch.py\nFeodo, URLhaus, ThreatFox"]
        WORKER --> A3["tor_network.py\nOnionoo relays/bridges"]
        WORKER --> A4["onion_probe.py\n.onion reachability + TLS"]
        WORKER --> A5["onion_crawler.py\nAhmia BFS crawler"]
        WORKER --> A6["blockchain.py\nMempool, Blockchain.com"]
        WORKER --> A7["cert_transparency.py\ncrt.sh, CertStream"]
        WORKER --> A8["osint_feeds.py\nOTX, PhishTank"]
        WORKER --> A9["detection_rules.py\nSigma, CISA KEV"]
        WORKER --> A10["supplementary.py\nDShield, GreyNoise"]
    end

    subgraph P2["PHASE 2: PROCESSING"]
        NER["Entity Extraction\nspaCy NER"] --> DEDUP["Deduplication\nmmh3 hashing"]
        DEDUP --> SCORE["Severity Scoring\n0-100 scale"]
        SCORE --> LINK["Persona Linking\nBayesian LLR"]
    end

    subgraph P3["PHASE 3: STORAGE"]
        direction LR
        PG[("PostgreSQL\nActors, Entities\nPersonaLinks, Audit")]
        RD[("Redis\nEvents, Runs\nPub/Sub")]
        N4[("Neo4j\nGraph Nodes\nEdges")]
    end

    subgraph P4["PHASE 4: DELIVERY"]
        REST["REST API\n/actors /search /alerts"]
        WS["WebSocket\nws://feed"]
        EXP["Exports\nPDF / CSV / JSON"]
        GRAPH["Graph API\nCytoscape data"]
    end

    A1 & A2 & A3 & A4 & A5 & A6 & A7 & A8 & A9 & A10 --> NER
    LINK --> PG & RD & N4
    PG & RD & N4 --> REST & WS & EXP & GRAPH

    style P1 fill:#0d0d0d,stroke:#333,color:#ccc
    style P2 fill:#111,stroke:#444,color:#ccc
    style P3 fill:#0d0d0d,stroke:#333,color:#ccc
    style P4 fill:#111,stroke:#444,color:#ccc
```

### Entity Types Extracted

```mermaid
mindmap
  root((Entity\nExtraction))
    Crypto
      BTC addresses
      ETH addresses
      Wallet clusters
    Network
      .onion URLs
      IP addresses
      Domains
    Identity
      Handles / usernames
      Email addresses
      PGP fingerprints
    Infrastructure
      TLS certificates
      Server banners
      Favicon hashes
```

---

## `04` System Components

### Backend (`backend/app/`)

```
backend/app/
├── main.py              # FastAPI application factory, CORS, lifespan
├── config.py            # Pydantic settings (env-driven configuration)
│
├── api/                 # REST + WebSocket endpoints
│   ├── auth.py          # JWT login, registration, token refresh
│   ├── actors.py        # CRUD actors, graph queries, persona links
│   ├── pipeline.py      # Trigger collections, blockchain/onion lookups
│   ├── routes.py        # Search, alerts, timeline, watchlist, infra
│   ├── exports.py       # PDF/CSV/JSON export with raw PDF generator
│   ├── health.py        # System health, Redis/Neo4j/Postgres checks
│   ├── sources.py       # Data source registry and status
│   ├── websocket.py     # Real-time event feed via WebSocket
│   └── deps.py          # Dependency injection (DB sessions, auth)
│
├── adapters/            # 22 intelligence collection adapters
│   ├── base.py          # Abstract base adapter interface
│   ├── http_client.py   # Shared HTTP client with retry/backoff
│   ├── ransomware_tracker.py
│   ├── abuse_ch.py
│   ├── tor_network.py
│   ├── onion_probe.py
│   ├── onion_crawler.py
│   ├── blockchain.py
│   ├── cert_transparency.py
│   ├── osint_feeds.py
│   ├── detection_rules.py
│   ├── source_provenance.py
│   ├── supplementary.py
│   ├── archives.py
│   └── replay.py        # Replay recorded data for demos
│
├── models/              # SQLAlchemy ORM models
│   ├── actors.py        # Actor, ActorEntity, PersonaLink, LinkEvidence, AuditLog
│   ├── entities.py      # Entity (wallets, handles, IPs, PGP keys, onions)
│   └── base.py          # Declarative base
│
├── core/                # Security, auth, events
│   ├── security.py      # JWT, bcrypt, RBAC, AuditAction enum
│   └── events.py        # Startup/shutdown lifecycle hooks
│
├── graph/               # Neo4j graph operations
│   └── schema.py        # Graph session, actor ego-graph queries
│
├── extraction/          # NLP entity extraction
│   └── ner.py           # spaCy NER pipeline
│
├── analytics/           # Scoring and analysis
│   └── scoring.py       # Severity scoring, confidence bands
│
└── workers/             # Celery async workers
    ├── celery_app.py    # Celery configuration
    └── tasks.py         # Collection & processing tasks
```

### Frontend (`frontend/src/`)

```
frontend/src/
├── app/
│   ├── layout.tsx       # Root layout with Material Symbols
│   ├── page.tsx         # Redirect to /dashboard
│   ├── globals.css      # NETRA design system (tokens, typography)
│   ├── login/           # JWT authentication page
│   ├── dashboard/       # Real-time overview, KPIs, live feed
│   ├── actors/          # Actor registry + detail dossier view
│   ├── graph/           # Cytoscape.js interactive graph explorer
│   ├── alerts/          # Severity-triaged alert inbox
│   ├── pipeline/        # Collection triggers, blockchain/onion lookups
│   └── search/          # Full-text entity search
│
├── components/
│   ├── AppLayout.tsx    # Sidebar + TopBar wrapper
│   ├── Sidebar.tsx      # Navigation + New Dossier modal
│   └── TopBar.tsx       # Search, export dropdown, notifications
│
└── lib/
    └── api.ts           # Type-safe API client (actors, pipeline, exports)
```

---

## `05` Intelligence Adapters (22 Crawlers)

All adapters are zero-cost, requiring no API keys or paid subscriptions.

| # | Adapter | Source | Data Collected |
|:--|:--------|:-------|:---------------|
| 1 | `ransomware_tracker` | RansomWatch | Ransomware group names, leak sites, victim data |
| 2 | `ransomware_tracker` | RansomLook | Negotiation leaks, group profiles |
| 3 | `abuse_ch` | Feodo Tracker | Botnet C2 server IPs and ports |
| 4 | `abuse_ch` | URLhaus | Malware distribution URLs |
| 5 | `abuse_ch` | ThreatFox | IOCs (IPs, domains, hashes) |
| 6 | `abuse_ch` | MalBazaar | Malware sample metadata |
| 7 | `tor_network` | Onionoo | Tor relay/bridge fingerprints, bandwidth, flags |
| 8 | `onion_probe` | Direct .onion | HTTP status, TLS certs, server banners, favicon hashes |
| 9 | `onion_crawler` | Ahmia + BFS | Dark web page content, links, screenshots |
| 10 | `blockchain` | Mempool.space | BTC transactions, address balances, fee estimates |
| 11 | `blockchain` | Blockchain.com | BTC address history, multi-address lookup |
| 12 | `cert_transparency` | crt.sh | Certificate issuance for domain/actor infrastructure |
| 13 | `cert_transparency` | CertStream | Real-time CT log stream |
| 14 | `osint_feeds` | AlienVault OTX | Threat pulses, IOC feeds |
| 15 | `osint_feeds` | PhishTank | Verified phishing URLs |
| 16 | `detection_rules` | Sigma Rules | SIEM detection rules for alert generation |
| 17 | `detection_rules` | CISA KEV | Known exploited vulnerabilities |
| 18 | `supplementary` | DShield (SANS) | Top attacking IPs |
| 19 | `supplementary` | GreyNoise | Internet scanner/noise classification |
| 20 | `supplementary` | BGP Ranking (CIRCL) | ASN reputation scoring |
| 21 | `source_provenance` | Internal | Data lineage, source reliability scoring (A-E bands) |
| 22 | `archives` | Wayback Machine | Historical snapshots of dark web pages |

---

## `06` API Reference

**Base URL:** `http://localhost:8000/api/v1`

### Authentication

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `POST` | `/auth/login` | JWT login → `{ access_token }` |
| `POST` | `/auth/register` | Create analyst account |
| `POST` | `/auth/refresh` | Refresh JWT token |

### Actors

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/actors` | List actors (filterable by status, category, search) |
| `POST` | `/actors` | Create new actor dossier |
| `GET` | `/actors/{id}` | Full actor profile with entities & links |
| `PATCH` | `/actors/{id}` | Update actor fields |
| `GET` | `/actors/{id}/graph` | Ego-graph (depth-configurable) |
| `GET` | `/actors/graph/overview` | Full knowledge graph for explorer |
| `GET` | `/actors/links/{id}/evidence` | Evidence chain for persona link |
| `POST` | `/actors/links/{id}/review` | Analyst confirms/rejects link |

### Pipeline & Collection

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `POST` | `/pipeline/collect` | Trigger single source collection |
| `POST` | `/pipeline/collect/all` | Trigger all 22 adapters |
| `POST` | `/pipeline/lookup/blockchain` | BTC/ETH address lookup |
| `POST` | `/pipeline/lookup/probe` | .onion URL probe |
| `POST` | `/pipeline/lookup/crawl` | Ahmia keyword crawl |
| `GET` | `/pipeline/status` | Collection run status |

### Search & Alerts

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/search?q=` | Full-text search across actors & entities |
| `GET` | `/alerts` | Severity-scored alert feed |
| `POST` | `/alerts/{id}/triage` | Mark alert as triaged/escalated |
| `GET` | `/timeline/{actor_id}` | Actor activity timeline |

### Exports

| Method | Endpoint | Formats |
|:-------|:---------|:--------|
| `POST` | `/exports/intel` | JSON, CSV, **PDF** — full intelligence package |
| `POST` | `/exports/batch` | JSON, CSV — all actors |
| `POST` | `/exports/dossier` | JSON, CSV, **PDF** — single actor dossier |

### System

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/health` | Service health (Postgres, Redis, Neo4j) |
| `GET` | `/sources` | Data source registry & status |
| `WS` | `/ws/feed` | Real-time event stream (WebSocket) |

> **Interactive docs:** http://localhost:8000/docs (Swagger UI)

---

## `07` Frontend Pages

| Route | Page | Description |
|:------|:-----|:------------|
| `/login` | Authentication | JWT login with encrypted session |
| `/dashboard` | Overview | KPIs, live event feed, system status, alert summary |
| `/actors` | Actor Registry | Searchable/filterable actor list with threat scores |
| `/actors/[id]` | Actor Dossier | Full profile — entities, timeline, infra, rebrand links, evidence |
| `/graph` | Graph Explorer | Interactive Cytoscape.js knowledge graph with node inspection |
| `/alerts` | Alert Inbox | Severity-triaged alerts with triage actions |
| `/pipeline` | Pipeline Control | Trigger collections, blockchain lookup, onion probe, crawl |
| `/search` | Entity Search | Full-text search across all intelligence |

### User Journey

```mermaid
graph LR
    LOGIN["/login"] --> DASH["/dashboard"]
    DASH --> ACTORS["/actors"]
    DASH --> GRAPH["/graph"]
    DASH --> ALERTS["/alerts"]
    DASH --> PIPE["/pipeline"]
    DASH --> SEARCH["/search"]
    ACTORS --> DOSSIER["/actors/[id]"]
    DOSSIER --> GRAPH
    PIPE -->|Blockchain Lookup| ACTORS
    PIPE -->|Onion Probe| ACTORS
    ALERTS -->|Triage| DOSSIER
    SEARCH --> DOSSIER

    style LOGIN fill:#1a1a1a,stroke:#555,color:#fff
    style DASH fill:#111,stroke:#fff,color:#fff
    style ACTORS fill:#1a1a1a,stroke:#555,color:#ccc
    style DOSSIER fill:#1a1a1a,stroke:#555,color:#ccc
    style GRAPH fill:#1a1a1a,stroke:#555,color:#ccc
    style ALERTS fill:#1a1a1a,stroke:#555,color:#ccc
    style PIPE fill:#1a1a1a,stroke:#555,color:#ccc
    style SEARCH fill:#1a1a1a,stroke:#555,color:#ccc
```

---

## `08` Database Schema

### PostgreSQL Schema

```mermaid
erDiagram
    ACTORS {
        string actor_id PK
        string label
        string category
        string status
        datetime first_seen
        datetime last_seen
        datetime last_scan_at
    }
    ENTITIES {
        string entity_id PK
        string kind
        string value
        float confidence
        datetime first_seen
        datetime last_seen
    }
    ACTOR_ENTITIES {
        string actor_id FK
        string entity_id FK
    }
    PERSONA_LINKS {
        string link_id PK
        string actor_a FK
        string actor_b FK
        float score
        string band
        string analyst_status
    }
    LINK_EVIDENCE {
        int id PK
        string link_id FK
        string evidence_type
        float llr
        string raw_value
    }
    AUDIT_LOG {
        int id PK
        string actor
        string action
        string target
        datetime at
        json detail
    }
    USERS {
        string user_id PK
        string email
        string hashed_pw
        string role
    }

    ACTORS ||--o{ ACTOR_ENTITIES : has
    ENTITIES ||--o{ ACTOR_ENTITIES : belongs_to
    ACTORS ||--o{ PERSONA_LINKS : linked_as_A
    ACTORS ||--o{ PERSONA_LINKS : linked_as_B
    PERSONA_LINKS ||--o{ LINK_EVIDENCE : supported_by
```

### Neo4j Graph Schema

```mermaid
graph LR
    A1((Actor)) -->|USES| E1["btc_address"]
    A1 -->|USES| E2["onion_url"]
    A1 -->|USES| E3["pgp_fingerprint"]
    A1 -->|USES| E4["handle"]
    A1 -->|USES| E5["email"]
    A1 -->|USES| E6["ip_address"]
    A1 -->|USES| E7["eth_address"]

    A1 ---|"LINKED_TO\nscore: 87.4\nband: A"| A2((Actor))

    E1 -->|TRANSFERS_TO| E8["btc_address"]
    E6 -->|HOSTS| E2
    E9["domain"] -->|RESOLVES_TO| E6

    style A1 fill:#1a1a1a,stroke:#fff,color:#fff
    style A2 fill:#1a1a1a,stroke:#fff,color:#fff
    style E1 fill:#f7931a,stroke:#333,color:#000
    style E7 fill:#627eea,stroke:#333,color:#fff
    style E2 fill:#7D4698,stroke:#333,color:#fff
    style E3 fill:#2ecc71,stroke:#333,color:#000
```

### Persona Link Scoring (Bayesian LLR)

```mermaid
graph LR
    subgraph Evidence["Evidence Types"]
        direction TB
        VH1["PGP Fingerprint"] ---|Very High| S
        VH2["SSH Key"] ---|Very High| S
        H1["Wallet Cluster"] ---|High| S
        H2["Wallet Transfer"] ---|High| S
        H3["Cert SAN"] ---|High| S
        M1["Favicon Hash"] ---|Medium| S
        M2["Handle Exact"] ---|Medium| S
        L1["Handle Similar"] ---|Low| S
        L2["Stylometry"] ---|Low| S
        L3["Temporal Overlap"] ---|Low| S
    end

    S["Bayesian LLR\nScoring Engine"] --> B

    subgraph Bands["Confidence Bands"]
        B["Score"] --> BA["A: 80+"]
        B --> BB["B: 60-79"]
        B --> BC["C: 40-59"]
        B --> BD["D: 20-39"]
        B --> BE["E: below 20"]
    end

    style Evidence fill:#0d0d0d,stroke:#333,color:#ccc
    style Bands fill:#111,stroke:#444,color:#ccc
    style BA fill:#2ecc71,stroke:#333,color:#000
    style BB fill:#3498db,stroke:#333,color:#fff
    style BC fill:#f39c12,stroke:#333,color:#000
    style BD fill:#e74c3c,stroke:#333,color:#fff
    style BE fill:#555,stroke:#333,color:#fff
```

---

## `09` Security & Compliance

### Authentication & Authorization Flow

```mermaid
sequenceDiagram
    participant U as Analyst
    participant FE as Next.js Frontend
    participant API as FastAPI Backend
    participant DB as PostgreSQL
    participant R as Redis

    U->>FE: Login (email + password)
    FE->>API: POST /api/v1/auth/login
    API->>DB: Verify credentials (bcrypt)
    DB-->>API: User record
    API->>API: Generate JWT (python-jose)
    API->>DB: Write audit_log (LOGIN)
    API-->>FE: { access_token, expires_in }
    FE->>FE: Store token (sessionStorage)

    U->>FE: Request /dashboard
    FE->>API: GET /api/v1/health (Authorization: Bearer)
    API->>API: Validate JWT + check role
    API->>R: Rate limit check (SlowAPI)
    R-->>API: OK
    API-->>FE: 200 + data
    FE-->>U: Render dashboard
```

### OWASP Top 10 Coverage

| OWASP ID | Threat | NETRA Mitigation |
|:---------|:-------|:-----------------|
| A01 | Broken Access Control | RBAC with JWT, role-based route guards |
| A02 | Cryptographic Failures | bcrypt password hashing, JOSE/JWE tokens |
| A03 | Injection | SQLAlchemy ORM (parameterized), Pydantic validation |
| A04 | Insecure Design | Threat-modeled architecture, principle of least privilege |
| A05 | Security Misconfiguration | Docker security_opt, no-new-privileges |
| A07 | Auth Failures | Rate limiting (SlowAPI), account lockout |
| A09 | Logging & Monitoring | Immutable audit_log table, structured logging |

### Legal Compliance

```mermaid
graph LR
    subgraph Indian["Indian Law"]
        IT["IT Act 2000\nSections 66, 69, 79"]
        IT65["IT Act Section 65B\nDigital Evidence"]
        CERT["CERT-In Directions 2022\n6-hour Reporting"]
        NCIIPC_["NCIIPC Guidelines\nCritical Infra"]
        RBI["RBI Cyber Framework\nBanking Sector"]
        MHA["MHA I4C Scheme\nCybercrime Coord."]
    end

    subgraph Intl["International"]
        NIST["NIST CSF v2.0\nRisk Assessment"]
        STIX["STIX/TAXII 2.1\nThreat Sharing"]
        MITRE["MITRE ATT&CK\nAdversary TTPs"]
        BUDA["Budapest Convention\nCross-border Evidence"]
    end

    NETRA((NETRA)) --> IT & IT65 & CERT & NCIIPC_ & RBI & MHA
    NETRA --> NIST & STIX & MITRE & BUDA

    style Indian fill:#0d0d0d,stroke:#333,color:#ccc
    style Intl fill:#111,stroke:#444,color:#ccc
    style NETRA fill:#1a1a1a,stroke:#fff,color:#fff
```

---

## `10` Quick Start

### Prerequisites

- Docker & Docker Compose
- Node.js 18+ (for frontend development)
- Python 3.12+ (for backend development)

### One-Command Launch

```bash
# Clone
git clone https://github.com/Swaggyop/netra.git
cd netra

# Configure
cp .env.example .env
# Edit .env with your secrets

# Launch all 6 services
make up

# Run database migrations
make migrate

# Seed demo data
make seed

# Generate synthetic intelligence data
make generate

# Start frontend
cd frontend && npm install && npm run dev
```

### Full Demo (single command)

```bash
make demo    # runs: up → migrate → seed → generate → replay
```

### Access Points

| Service | URL |
|:--------|:----|
| **Dashboard** | http://localhost:3000 |
| **API Docs** | http://localhost:8000/docs |
| **Neo4j Browser** | http://localhost:7474 |
| **WebSocket Feed** | ws://localhost:8000/ws/feed |

### Default Credentials

```
Username: admin@netra.local
Password: netra_admin_2024
```

---

## `11` Environment Variables

```bash
# ── Application ──────────────────────────────
APP_NAME=netra
APP_ENV=development          # development | staging | production
SECRET_KEY=<random-64-chars>
ALLOWED_HOSTS=localhost,127.0.0.1

# ── PostgreSQL ───────────────────────────────
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_DB=netra
POSTGRES_USER=netra
POSTGRES_PASSWORD=<your-password>

# ── Neo4j ────────────────────────────────────
NEO4J_URI=bolt://neo4j:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=<your-password>

# ── Redis ────────────────────────────────────
REDIS_URL=redis://redis:6379/0
CELERY_BROKER_URL=redis://redis:6379/1
CELERY_RESULT_BACKEND=redis://redis:6379/2

# ── MinIO (Object Storage) ───────────────────
MINIO_ENDPOINT=minio:9000
MINIO_ACCESS_KEY=netra
MINIO_SECRET_KEY=<your-password>

# ── Tor (Optional) ──────────────────────────
TOR_SOCKS_PROXY=socks5://tor:9050
TOR_CONTROL_PORT=9051
```

---

## `12` Make Targets

```bash
make up              # Start all Docker services
make down            # Stop all services
make restart         # Restart API, worker, beat
make logs            # Tail logs for api, worker, beat
make migrate         # Run Alembic migrations
make seed            # Seed database with initial data
make generate        # Generate synthetic intelligence data
make replay          # Replay recorded data at 100x speed
make demo            # Full demo setup (up + migrate + seed + generate + replay)
make test            # Run pytest with coverage
make lint            # Run ruff + mypy
make format          # Auto-format with ruff
make security-scan   # pip-audit + security linting
make clean           # Remove containers, volumes, and __pycache__
make lab-up          # Start lab environment (extended services)
make lab-down        # Stop lab environment
```

---

## `13` Project Structure

```
netra/
├── backend/
│   ├── app/
│   │   ├── adapters/       # 22 intelligence collection adapters
│   │   ├── analytics/      # Scoring, confidence bands
│   │   ├── api/            # FastAPI routes + WebSocket
│   │   ├── core/           # Security, JWT, audit, lifecycle
│   │   ├── exports/        # Report generation
│   │   ├── extraction/     # NLP entity extraction (spaCy)
│   │   ├── graph/          # Neo4j operations
│   │   ├── models/         # SQLAlchemy ORM
│   │   ├── workers/        # Celery tasks
│   │   ├── main.py         # Application entry point
│   │   └── config.py       # Environment configuration
│   ├── Dockerfile
│   └── tests/
│
├── frontend/
│   ├── src/
│   │   ├── app/            # Next.js pages (7 routes)
│   │   ├── components/     # Sidebar, TopBar, AppLayout
│   │   └── lib/            # Type-safe API client
│   ├── package.json
│   └── next.config.ts
│
├── datagen/                # Synthetic data generation
├── ppt_assets/             # SIH presentation materials
├── docker-compose.yml      # 6-service orchestration
├── Makefile                # Developer workflow automation
├── pyproject.toml          # Python dependencies
├── alembic.ini             # Database migration config
└── .env.example            # Environment template
```

---

## `14` Tech Stack

### Backend

| Layer | Technology | Version | Purpose |
|:------|:-----------|:--------|:--------|
| API Framework | FastAPI | 0.115+ | Async REST API + WebSocket |
| Task Queue | Celery | 5.4+ | Distributed async workers |
| Broker/Cache | Redis | 7 | Task broker, event pub/sub, caching |
| Relational DB | PostgreSQL | 16 | Actors, entities, audit logs |
| Graph DB | Neo4j | 5 | Relationship mapping, traversals |
| ORM | SQLAlchemy | 2.0+ | Async PostgreSQL access |
| HTTP Client | httpx | 0.27+ | Tor-compatible SOCKS5 requests |
| NLP | spaCy | 3.8+ | Named entity recognition |
| ML | scikit-learn | 1.5+ | Stylometry analysis |
| Embeddings | sentence-transformers | 3.2+ | Semantic similarity |
| Auth | python-jose + passlib | — | JWT + bcrypt |
| Security | SlowAPI + bleach | — | Rate limiting, XSS prevention |
| Logging | structlog | 24.4+ | Structured JSON logging |
| Migrations | Alembic | 1.14+ | Database schema versioning |

### Frontend

| Layer | Technology | Version | Purpose |
|:------|:-----------|:--------|:--------|
| Framework | Next.js | 16 | Server/client React framework |
| UI Library | React | 19 | Component rendering |
| Graph Viz | Cytoscape.js | 3.x | Interactive knowledge graph |
| Styling | Tailwind CSS v4 | — | Utility-first CSS |
| Icons | Material Symbols | — | Google icon set |
| Fonts | Inter + JetBrains Mono | — | UI + code typography |

### Infrastructure

| Component | Technology | Purpose |
|:----------|:-----------|:--------|
| Containerization | Docker + Compose | Service orchestration |
| Object Storage | MinIO | S3-compatible file storage |
| Event Streaming | Redpanda (Kafka API) | Event bus (optional) |
| Tor Proxy | Tor SOCKS5 | .onion access |

---

## `15` Data Sources & References

### Academic Research

| Paper | Publication |
|:------|:-----------|
| Dark Web Content Analysis and Classification | IEEE Access, 2023 |
| Automated Analysis of Dark Web Marketplaces | Digital Investigation, 2017 |
| Proactively Identifying Emerging Hacker Threats | MIS Quarterly, 2020 |
| Darknet and Deepnet Mining for Threat Intelligence | IEEE ISI, 2016 |
| DarkEmbed: Exploit Prediction from Dark Web Posts | ACM CIKM, 2019 |
| ENISA Threat Landscape | ENISA, 2024 |

### Live Data Sources

| Source | URL |
|:-------|:----|
| Tor Project / Onionoo | https://onionoo.torproject.org |
| RansomWatch | https://ransomwatch.telemetry.ltd |
| RansomLook | https://www.ransomlook.io |
| Abuse.ch (Feodo/URLhaus/ThreatFox) | https://abuse.ch |
| CISA KEV | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| crt.sh / CertStream | https://crt.sh |
| Mempool.space | https://mempool.space/api |
| Sigma Rules | https://github.com/SigmaHQ/sigma |
| Ahmia.fi | https://ahmia.fi |
| AlienVault OTX | https://otx.alienvault.com |

### Compliance Frameworks

| Framework | Body |
|:----------|:-----|
| IT Act, 2000 (§66, §69, §65B) | Government of India |
| CERT-In Directions, 2022 | CERT-In |
| National Cyber Security Policy, 2013 | Government of India |
| NCIIPC Guidelines | NTRO |
| NIST Cybersecurity Framework v2.0 | NIST |
| STIX/TAXII 2.1 | OASIS |
| MITRE ATT&CK | MITRE Corporation |
| Budapest Convention on Cybercrime | Council of Europe |

---

## `16` License

```
MIT License

Copyright (c) 2026 Saswat Kumar

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
```

---

<p align="center">
  <code>━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</code>
</p>

<p align="center">
  <strong>NETRA</strong> — Networked Entity Tracking & Reconnaissance Architecture
</p>

<p align="center">
  <sub>
    Built for India's cyber defense · SIH 2025 · Problem ID 26151
  </sub>
</p>

<p align="center">
  <em>"Eyes where darkness hides"</em>
</p>

<p align="center">
  <code>━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</code>
</p>
