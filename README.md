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

```
┌──────────────────────────────────────────────────────────────────────┐
│                         NETRA ARCHITECTURE                          │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  │
│  │ Tor     │  │Ransomware│  │Blockchain│  │ OSINT   │  │ Cert    │  │
│  │ Network │  │ Trackers │  │ Explorers│  │ Feeds   │  │ Transp. │  │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘  │
│       │            │            │            │            │         │
│       └────────────┴─────┬──────┴────────────┴────────────┘         │
│                          │                                           │
│                 ┌────────▼────────┐                                  │
│                 │  22 ADAPTERS    │  ◄── Celery Workers              │
│                 │  (Collection)   │      Async Task Queue            │
│                 └────────┬────────┘                                  │
│                          │                                           │
│              ┌───────────┼───────────┐                               │
│              │           │           │                               │
│     ┌────────▼──┐  ┌─────▼─────┐  ┌─▼──────────┐                   │
│     │PostgreSQL │  │   Redis   │  │   Neo4j    │                    │
│     │ Structured│  │ Real-time │  │   Graph    │                    │
│     │  Records  │  │  Events   │  │ Relations  │                    │
│     └────────┬──┘  └─────┬─────┘  └─┬──────────┘                   │
│              │           │          │                                │
│              └───────────┼──────────┘                                │
│                          │                                           │
│                 ┌────────▼────────┐                                  │
│                 │   FastAPI       │  ◄── REST + WebSocket            │
│                 │   Backend       │      JWT Auth, RBAC              │
│                 └────────┬────────┘                                  │
│                          │                                           │
│                 ┌────────▼────────┐                                  │
│                 │   Next.js 16    │  ◄── React 19, Cytoscape.js     │
│                 │   Dashboard     │      Real-time Graph Explorer    │
│                 └─────────────────┘                                  │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### Docker Services (6 containers)

| Service | Image | Port | Role |
|:--------|:------|:-----|:-----|
| `postgres` | `postgres:16-alpine` | 5433 | Structured data — actors, entities, audit logs |
| `neo4j` | `neo4j:5-community` | 7474, 7687 | Knowledge graph — relationships & traversals |
| `redis` | `redis:7-alpine` | 6379 | Celery broker, real-time event cache, WebSocket pub/sub |
| `api` | FastAPI (uvicorn) | 8000 | REST API, WebSocket, auth, exports |
| `worker` | Celery worker | — | Async collection tasks, data processing |
| `frontend` | Next.js 16 | 3000 | Dashboard, graph explorer, pipeline controls |

---

## `03` Data Flow Pipeline

```
 ┌──────────────────────────────────────────────────────────────────┐
 │                    NETRA DATA FLOW PIPELINE                     │
 └──────────────────────────────────────────────────────────────────┘

 PHASE 1: COLLECTION
 ───────────────────
   Celery Beat (scheduler)
       │
       ▼
   Celery Worker dispatches adapter tasks
       │
       ├── ransomware_tracker.py  ──► RansomWatch, RansomLook APIs
       ├── abuse_ch.py            ──► Feodo Tracker, URLhaus, ThreatFox
       ├── tor_network.py         ──► Onionoo relay/bridge data
       ├── onion_probe.py         ──► .onion reachability + TLS fingerprints
       ├── onion_crawler.py       ──► Ahmia BFS crawler, content extraction
       ├── blockchain.py          ──► Mempool.space, Blockchain.com
       ├── cert_transparency.py   ──► crt.sh, CertStream
       ├── osint_feeds.py         ──► AlienVault OTX, PhishTank
       ├── detection_rules.py     ──► Sigma Rules, CISA KEV
       ├── source_provenance.py   ──► Data lineage & reliability scoring
       └── supplementary.py       ──► DShield, GreyNoise, BGP ranking

 PHASE 2: PROCESSING
 ───────────────────
   Raw data  ──►  Entity Extraction (spaCy NER)
                      │
                      ├── BTC/ETH addresses
                      ├── .onion URLs
                      ├── Email addresses
                      ├── PGP fingerprints
                      ├── IP addresses / domains
                      └── Handles / usernames
                      │
                      ▼
                  Deduplication (mmh3 hashing)
                      │
                      ▼
                  Severity Scoring (0-100)
                      │
                      ▼
                  Persona Linking (Bayesian LLR)

 PHASE 3: STORAGE
 ────────────────
   PostgreSQL  ◄──  Actors, Entities, ActorEntity joins,
                    PersonaLinks, LinkEvidence, AuditLog
                    
   Neo4j       ◄──  Actor nodes, Entity nodes,
                    USES/LINKED_TO/TRANSFERS_TO edges
                    
   Redis       ◄──  Real-time event stream,
                    Collection run metadata,
                    WebSocket pub/sub channels

 PHASE 4: DELIVERY
 ─────────────────
   REST API    ──►  /api/v1/actors, /search, /alerts, /pipeline
   WebSocket   ──►  ws://localhost:8000/ws/feed (live events)
   Exports     ──►  PDF / CSV / JSON evidence packages
   Graph API   ──►  /api/v1/actors/graph/overview (Cytoscape data)
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

---

## `08` Database Schema

### PostgreSQL Tables

```
actors              Actor profiles (id, label, category, status, first/last_seen)
entities            Extracted entities (wallets, handles, IPs, PGP, onions)
actor_entities      Many-to-many join (actor ↔ entity)
persona_links       Cross-platform identity links with Bayesian scores
link_evidence       Individual evidence items supporting persona links
audit_log           Immutable audit trail (OWASP A09 compliance)
users               JWT-authenticated user accounts with RBAC
```

### Neo4j Graph Schema

```
 (Actor)──[:USES]──►(Entity)
    │                   │
    │                   ├── kind: btc_address
    │                   ├── kind: eth_address
    │                   ├── kind: onion_url
    │                   ├── kind: pgp_fingerprint
    │                   ├── kind: handle
    │                   ├── kind: email
    │                   └── kind: ip_address
    │
    └──[:LINKED_TO { score, band, evidence_count }]──►(Actor)

 (Entity)──[:TRANSFERS_TO]──►(Entity)    # wallet-to-wallet flows
 (Entity)──[:HOSTS]──►(Entity)           # IP hosts onion service
 (Entity)──[:RESOLVES_TO]──►(Entity)     # domain resolution
```

### Persona Link Scoring (Bayesian LLR)

| Evidence Type | Weight | Description |
|:-------------|:-------|:------------|
| `pgp_fingerprint` | Very High | Same PGP key across platforms |
| `ssh_key` | Very High | Same SSH host key |
| `wallet_cluster` | High | Same wallet cluster |
| `wallet_transfer` | High | Direct wallet-to-wallet transfer |
| `cert_san` | High | TLS cert names clearnet domain |
| `favicon` | Medium | Same favicon hash |
| `handle_exact` | Medium | Exact handle match |
| `handle_similar` | Low | Similar handle (fuzzy) |
| `stylometry` | Low | Similar writing style (ML) |
| `temporal_overlap` | Low | Overlapping activity windows |

Confidence bands: **A** (≥80) · **B** (60-79) · **C** (40-59) · **D** (20-39) · **E** (<20)

---

## `09` Security & Compliance

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

| Framework | Alignment |
|:----------|:----------|
| IT Act, 2000 (§66, §69, §79) | Legal authority for monitoring |
| IT Act §65B | Court-admissible digital evidence exports |
| CERT-In Directions (2022) | 6-hour incident reporting capability |
| NCIIPC Guidelines | Critical infrastructure protection |
| STIX/TAXII 2.1 | International threat intelligence sharing |
| MITRE ATT&CK | Adversary technique classification |
| Budapest Convention | Cross-border cyber evidence framework |

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
