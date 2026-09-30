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
flowchart TB
    subgraph SOURCES["🌐 INGESTION & DATA SOURCES"]
        direction LR
        S1["🧅 <b>Tor Network</b><br/><i>Relays, Bridges & .onion Hidden Services</i>"]
        S2["⚡ <b>Ransomware Trackers</b><br/><i>RansomWatch & RansomLook Leaks</i>"]
        S3["⛓️ <b>Blockchain Ledgers</b><br/><i>BTC Mempool & Multi-Chain Explorers</i>"]
        S4["🛡️ <b>Threat Feeds & IOCs</b><br/><i>Abuse.ch, AlienVault OTX & PhishTank</i>"]
        S5["📜 <b>Cert Transparency</b><br/><i>crt.sh & Real-time CertStream Logs</i>"]
    end

    subgraph INGESTION["⚙️ COLLECTION & ANALYTIC PIPELINE"]
        direction TB
        BEAT(["⏰ <b>Celery Beat</b><br/><i>Periodic Scheduler & Dispatcher</i>"])
        WORKER[["🔄 <b>Celery Async Workers</b><br/><i>22 Concurrent Live Crawler Adapters</i>"]]

        subgraph PIPELINE["Core Analytics Engine"]
            direction LR
            NER["🔤 <b>spaCy NER</b><br/><i>Entity Extraction</i>"]
            DEDUP["🔍 <b>Murmur3</b><br/><i>Hash Deduplication</i>"]
            SCORE["📊 <b>Severity Engine</b><br/><i>Threat Index (0–100)</i>"]
            LINK["🧬 <b>Bayesian LLR</b><br/><i>Persona Linker</i>"]
        end

        BEAT -.->|Dispatches Cron Jobs| WORKER
        WORKER --> NER --> DEDUP --> SCORE --> LINK
    end

    subgraph STORAGE["💾 POLYGLOT PERSISTENCE FABRIC"]
        direction LR
        PG[("🐘 <b>PostgreSQL 16</b><br/><i>Actors, Entities, Links<br/>§65B Immutable Audit Log</i>")]
        N4[("🕸️ <b>Neo4j 5</b><br/><i>Knowledge Graph Network<br/>Graph Data Science (GDS)</i>")]
        RD[("⚡ <b>Redis 7</b><br/><i>Celery Broker, Event Bus<br/>Sub-second Pub/Sub Feed</i>")]
    end

    subgraph APP["🚀 APPLICATION GATEWAY"]
        API[["⚡ <b>FastAPI Async Gateway</b><br/><i>REST Endpoints • WebSocket Feed • JWT & RBAC Security • SlowAPI Rate Limits</i>"]]
    end

    subgraph PRESENTATION["🖥️ INVESTIGATOR CONSOLE"]
        UI["💻 <b>Next.js 16 Dashboard</b><br/><i>React 19 • Cytoscape.js Graph Explorer • IT Act §65B Certified PDF Exports</i>"]
    end

    S1 & S2 & S3 & S4 & S5 -->|Raw Feeds & Onion Scrapes| WORKER
    LINK -->|Persist Intelligence & Audit| PG
    LINK -->|Sync Graph Topology & Edges| N4
    LINK -->|Broadcast Live Alert Events| RD
    PG & N4 & RD <-->|Query, Traverse & Subscribe| API
    API <-->|REST API + Secure WebSockets| UI

    classDef sourceStyle fill:#1e293b,stroke:#64748b,stroke-width:1.5px,color:#f8fafc;
    classDef workerStyle fill:#0f172a,stroke:#38bdf8,stroke-width:2px,color:#f8fafc;
    classDef pipeStyle fill:#18181b,stroke:#818cf8,stroke-width:1.5px,color:#f8fafc;
    classDef storeStyle fill:#09090b,stroke:#10b981,stroke-width:1.5px,color:#f8fafc;
    classDef apiStyle fill:#0f172a,stroke:#f59e0b,stroke-width:2px,color:#f8fafc;
    classDef uiStyle fill:#18181b,stroke:#f43f5e,stroke-width:2px,color:#f8fafc;

    class S1,S2,S3,S4,S5 sourceStyle;
    class BEAT,WORKER workerStyle;
    class NER,DEDUP,SCORE,LINK pipeStyle;
    class PG,N4,RD storeStyle;
    class API apiStyle;
    class UI uiStyle;
```

### Docker Service Topology

```mermaid
flowchart LR
    subgraph INGRESS["INGRESS & PRESENTATION"]
        direction TB
        FE["💻 <b>frontend</b><br/>Next.js 16 + React 19<br/><code>Host Port 3000:3000</code>"]
        API["⚡ <b>api / gateway</b><br/>FastAPI + Uvicorn Async<br/><code>Host Port 8000:8000</code>"]
    end

    subgraph WORKERS["ASYNC INTELLIGENCE WORKERS"]
        direction TB
        WK["🔄 <b>worker</b><br/>Celery Distributed Task Engine<br/><i>22 Live Zero-Cost Adapters</i>"]
        BT["⏰ <b>beat</b><br/>Celery Beat Scheduler<br/><i>Autonomous Crawl Intervals</i>"]
        TOR["🧅 <b>tor</b><br/>SOCKS5 Onion Routing Proxy<br/><code>Container Port 9050</code>"]
    end

    subgraph STORAGE["DATASTORES & EVENT FABRIC"]
        direction TB
        PG[("🐘 <b>postgres</b> (16-alpine)<br/>Relational & Audit Ledger<br/><code>Port 5433:5432</code>")]
        N4[("🕸️ <b>neo4j</b> (5-community)<br/>Knowledge Graph Engine<br/><code>Ports 7474, 7687</code>")]
        RD[("⚡ <b>redis</b> (7-alpine)<br/>Broker, Cache & Pub/Sub<br/><code>Port 6379:6379</code>")]
        MN[("🪣 <b>minio</b> (S3-compatible)<br/>Forensic Snapshot Storage<br/><code>Ports 9000, 9001</code>")]
    end

    FE <-->|HTTP REST & WebSockets| API
    API -->|Read & Write State| PG
    API -->|Cypher Ego-Graph Queries| N4
    API -->|Session Cache & Event Streams| RD
    API -->|Dossier Snapshot Artifacts| MN

    BT -.->|Schedule Collection Tasks| RD
    WK <-->|Consume Celery Tasks| RD
    WK -->|Route Scrapes Anonymously| TOR
    WK -->|Persist Normalised Entities| PG
    WK -->|Synchronize Graph Nodes & Edges| N4
    WK -->|Archive Raw Evidence Snapshots| MN

    classDef feStyle fill:#09090b,stroke:#f43f5e,stroke-width:1.5px,color:#f8fafc;
    classDef apiStyle fill:#0f172a,stroke:#f59e0b,stroke-width:1.5px,color:#f8fafc;
    classDef workerStyle fill:#18181b,stroke:#38bdf8,stroke-width:1.5px,color:#f8fafc;
    classDef storeStyle fill:#09090b,stroke:#10b981,stroke-width:1.5px,color:#f8fafc;

    class FE feStyle;
    class API apiStyle;
    class WK,BT,TOR workerStyle;
    class PG,N4,RD,MN storeStyle;
```

---

## `03` Data Flow Pipeline

```mermaid
flowchart TD
    subgraph P1["PHASE 1: MULTI-SOURCE INGESTION"]
        direction TB
        subgraph ADAPTERS["22 Live Zero-Cost Intelligence Crawlers"]
            direction LR
            C1["🧅 <b>Dark Web & Onion</b><br/>• Ahmia BFS Web Crawler<br/>• Onionoo Relay Monitor<br/>• Onion Probe (HTTP/TLS)"]
            C2["⚡ <b>Threat & Malware Feeds</b><br/>• RansomWatch & RansomLook<br/>• Abuse.ch (URLhaus/ThreatFox)<br/>• Feodo Botnet C2 Tracker"]
            C3["⛓️ <b>Blockchain & Wallets</b><br/>• Mempool.space BTC API<br/>• Blockchain.com Explorer<br/>• Multi-Chain Address Parser"]
            C4["📜 <b>OSINT & Infrastructure</b><br/>• crt.sh / CertStream CT Logs<br/>• AlienVault OTX Pulses<br/>• CISA KEV & Sigma Rules"]
        end
        SCHED["⏰ Celery Beat & Autonomous Scheduler"] --> C1 & C2 & C3 & C4
    end

    subgraph P2["PHASE 2: ANALYTIC ENRICHMENT PIPELINE"]
        direction TB
        E1["🔤 <b>Entity Extraction (NER)</b><br/>spaCy Transformer Model extracts Wallets, .onions, IPs, Emails, PGP & Handles"]
        E2["🔍 <b>Deduplication & Provenance Scoring</b><br/>MurmurHash3 (mmh3) deduplication + Source Reliability Bands (A–E)"]
        E3["📊 <b>Multi-Factor Severity Scoring</b><br/>Dynamic 0–100 threat assessment incorporating reach, exploitability & infrastructure"]
        E4["🧬 <b>Bayesian Persona Linker</b><br/>Pairwise Log-Likelihood Ratio (LLR) calculation across handles, crypto & infrastructure"]

        E1 --> E2 --> E3 --> E4
    end

    subgraph P3["PHASE 3: POLYGLOT PERSISTENCE & GRAPH"]
        direction LR
        S_PG[("🐘 <b>PostgreSQL 16</b><br/>• Threat Actors & Aliases<br/>• Normalized Entity Tables<br/>• §65B Immutable Audit Log")]
        S_NEO[("🕸️ <b>Neo4j 5 Graph</b><br/>• Actor Knowledge Graph<br/>• Crypto Wallet Transfers<br/>• Infrastructure Hosting Edges")]
        S_RD[("⚡ <b>Redis 7</b><br/>• Real-time WebSocket Feed<br/>• In-Memory Ring Buffer<br/>• Celery Task Queue Cache")]
    end

    subgraph P4["PHASE 4: CONSUMPTION & ACTIONABLE DISRUPTION"]
        direction LR
        OUT_WS["📡 <b>Real-time SOC Feed</b><br/>Sub-second WebSocket alert feed streaming directly to monitoring analysts"]
        OUT_ACT["👤 <b>Actor Dossiers</b><br/>360° Profile view with historical timeline, corroborated evidence & entity tags"]
        OUT_GRAPH["🕸️ <b>Interactive Graph</b><br/>Cytoscape.js interactive topological traversal with dynamic depth exploration"]
        OUT_EXP["⚖️ <b>Court-Ready Exports</b><br/>Evidence packages in PDF (IT Act §65B format), CSV, and structured JSON"]
    end

    C1 & C2 & C3 & C4 -->|Raw Unstructured Scrapes| E1
    E4 -->|Structured Relational State| S_PG
    E4 -->|Topological Sync & Cypher Edges| S_NEO
    E4 -->|Publish Alert Events| S_RD

    S_RD --> OUT_WS
    S_PG --> OUT_ACT
    S_NEO --> OUT_GRAPH
    S_PG & S_NEO --> OUT_EXP

    classDef p1Style fill:#1e293b,stroke:#64748b,stroke-width:1.5px,color:#f8fafc;
    classDef p2Style fill:#0f172a,stroke:#38bdf8,stroke-width:1.5px,color:#f8fafc;
    classDef p3Style fill:#09090b,stroke:#10b981,stroke-width:1.5px,color:#f8fafc;
    classDef p4Style fill:#18181b,stroke:#f59e0b,stroke-width:1.5px,color:#f8fafc;

    class C1,C2,C3,C4,SCHED p1Style;
    class E1,E2,E3,E4 p2Style;
    class S_PG,S_NEO,S_RD p3Style;
    class OUT_WS,OUT_ACT,OUT_GRAPH,OUT_EXP p4Style;
```

### Entity Types Extracted

```mermaid
flowchart LR
    ROOT(["Ψ <b>NETRA ENTITY RECONNAISSANCE</b>"])

    subgraph CRYPTO["Cryptocurrency Intelligence"]
        direction TB
        CAT1["💰 <b>Crypto Assets</b>"]
        CR1["BTC & ETH Addresses<br/><code>Base58Check / bech32 / Hex</code>"]
        CR2["Transaction Hashes<br/><code>UTXO & Internal Transfers</code>"]
        CR3["Wallet Clusters<br/><code>Common-input-ownership</code>"]
        CAT1 --> CR1 & CR2 & CR3
    end

    subgraph NETWORK["Network & Darknet Infrastructure"]
        direction TB
        CAT2["🌐 <b>Dark Infrastructure</b>"]
        NW1[".onion Hidden Services<br/><code>v3 Ed25519 addresses</code>"]
        NW2["IP Addresses & Ports<br/><code>IPv4 / IPv6 C2 nodes</code>"]
        NW3["Domains & Subdomains<br/><code>Clearweb mirrors & gates</code>"]
        NW4["BGP ASNs & Relays<br/><code>Guard / Exit flags & bandwidth</code>"]
        CAT2 --> NW1 & NW2 & NW3 & NW4
    end

    subgraph IDENTITY["Persona & Operator Identity"]
        direction TB
        CAT3["👤 <b>Actor Identities</b>"]
        ID1["Forum Handles & Aliases<br/><code>Cross-platform handles</code>"]
        ID2["Communication Channels<br/><code>Telegram, Tox, Jabber</code>"]
        ID3["PGP Fingerprints<br/><code>Public key IDs & subkeys</code>"]
        CAT3 --> ID1 & ID2 & ID3
    end

    subgraph FORENSICS["Digital Signatures & Artefacts"]
        direction TB
        CAT4["🛡️ <b>Forensic Signals</b>"]
        FO1["TLS / SSL Certificates<br/><code>SHA-256 cert fingerprints</code>"]
        FO2["Server Banners & Headers<br/><code>HTTP server response signatures</code>"]
        FO3["Favicon MMH3 Hashes<br/><code>Murmur3 icon hash correlations</code>"]
        FO4["SSH Host Keys<br/><code>RSA / Ed25519 fingerprints</code>"]
        CAT4 --> FO1 & FO2 & FO3 & FO4
    end

    ROOT --> CAT1 & CAT2 & CAT3 & CAT4

    classDef rootStyle fill:#000000,stroke:#f8fafc,stroke-width:2px,color:#f8fafc;
    classDef catStyle fill:#1e293b,stroke:#94a3b8,stroke-width:1.5px,color:#f8fafc;
    classDef cryptoStyle fill:#1a1505,stroke:#f59e0b,stroke-width:1.5px,color:#fef3c7;
    classDef netStyle fill:#031525,stroke:#0ea5e9,stroke-width:1.5px,color:#e0f2fe;
    classDef idStyle fill:#061a12,stroke:#10b981,stroke-width:1.5px,color:#d1fae5;
    classDef forStyle fill:#160b24,stroke:#a855f7,stroke-width:1.5px,color:#f3e8ff;

    class ROOT rootStyle;
    class CAT1,CAT2,CAT3,CAT4 catStyle;
    class CR1,CR2,CR3 cryptoStyle;
    class NW1,NW2,NW3,NW4 netStyle;
    class ID1,ID2,ID3 idStyle;
    class FO1,FO2,FO3,FO4 forStyle;
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
flowchart LR
    subgraph S1["01 · AUTH & ACCESS"]
        L1["<b>/login</b><br/>Analyst Authentication<br/><i>JWT Session & RBAC Enforcement</i>"]
    end

    subgraph S2["02 · SITUATIONAL AWARENESS"]
        L2["<b>/dashboard</b><br/>SOC Operations Center<br/><i>KPIs • Live Feeds • Node Health</i>"]
        L3["<b>/alerts</b><br/>Threat Alert Inbox<br/><i>Severity Triage & Escalation</i>"]
    end

    subgraph S3["03 · INVESTIGATION & RECON"]
        L4["<b>/search</b><br/>Entity Search<br/><i>Full-Text & Wildcard Match</i>"]
        L5["<b>/pipeline</b><br/>Reconnaissance Suite<br/><i>Blockchain • Onion Probe • Ahmia</i>"]
    end

    subgraph S4["04 · DOSSIER & GRAPH ANALYSIS"]
        L6["<b>/actors</b><br/>Threat Actor Registry<br/><i>Filters • Status • Scoring</i>"]
        L7["<b>/actors/[id]</b><br/>Full Actor Dossier<br/><i>Entities • Timeline • Links • Evidence</i>"]
        L8["<b>/graph</b><br/>Cytoscape Explorer<br/><i>Interactive Topology Traversals</i>"]
    end

    subgraph S5["05 · ACTION & EVIDENCE"]
        L9["<b>Court-Ready Export</b><br/>Evidence Package<br/><i>IT Act §65B Certified PDF/CSV/JSON</i>"]
    end

    L1 --> L2
    L2 --> L3
    L2 --> L4
    L2 --> L5
    L2 --> L6

    L3 -->|Triage Incident| L7
    L4 -->|Target Identified| L7
    L5 -->|Enrich Intelligence| L7
    L6 -->|Select Threat Actor| L7

    L7 <-->|Explore Ego Network| L8
    L7 -->|Export Legal Package| L9

    classDef s1 fill:#09090b,stroke:#64748b,stroke-width:1.5px,color:#f8fafc;
    classDef s2 fill:#0f172a,stroke:#38bdf8,stroke-width:1.5px,color:#f8fafc;
    classDef s3 fill:#18181b,stroke:#818cf8,stroke-width:1.5px,color:#f8fafc;
    classDef s4 fill:#09090b,stroke:#10b981,stroke-width:1.5px,color:#f8fafc;
    classDef s5 fill:#1a1505,stroke:#f59e0b,stroke-width:2px,color:#f8fafc;

    class L1 s1;
    class L2,L3 s2;
    class L4,L5 s3;
    class L6,L7,L8 s4;
    class L9 s5;
```

---

## `08` Database Schema

### PostgreSQL Schema

```mermaid
erDiagram
    USERS ||--o{ AUDIT_LOG : "triggers"
    USERS ||--o{ ACTORS : "supervises"
    ACTORS ||--o{ ACTOR_ENTITIES : "owns"
    ENTITIES ||--o{ ACTOR_ENTITIES : "linked_to"
    ACTORS ||--o{ PERSONA_LINKS : "primary_actor"
    ACTORS ||--o{ PERSONA_LINKS : "target_actor"
    PERSONA_LINKS ||--|{ LINK_EVIDENCE : "substantiated_by"

    USERS {
        string user_id PK "UUID"
        string username UK "Alphanumeric handle"
        string hashed_password "bcrypt hash"
        string role "admin | analyst | viewer"
        boolean is_active "Account status flag"
        datetime last_login "Last authentication timestamp"
    }

    ACTORS {
        string actor_id PK "UUID"
        string label "Display name / group"
        string category "ransomware | market | forum"
        string status "active | dormant | seized"
        float threat_score "Dynamic score (0–100)"
        datetime first_seen "First detection timestamp"
        datetime last_seen "Latest telemetry timestamp"
        datetime last_scan_at "Recent crawl timestamp"
    }

    ENTITIES {
        string entity_id PK "UUID"
        string kind "wallet | onion | ip | email | handle"
        string value "Normalized entity string"
        float confidence "Extraction certainty (0.0-1.0)"
        string source_provenance "Source reliability rating (A–E)"
        datetime first_seen "Discovery timestamp"
        datetime last_seen "Telemetry timestamp"
    }

    ACTOR_ENTITIES {
        string actor_id FK "References ACTORS"
        string entity_id FK "References ENTITIES"
        string association_type "operator | infra | financial"
        datetime linked_at "Creation timestamp"
    }

    PERSONA_LINKS {
        string link_id PK "UUID"
        string actor_a FK "References primary ACTORS"
        string actor_b FK "References target ACTORS"
        float score "Composite Bayesian score"
        string band "Confidence band (A to E)"
        string analyst_status "pending | confirmed | rejected"
        datetime computed_at "Calculation timestamp"
    }

    LINK_EVIDENCE {
        int id PK "Serial identifier"
        string link_id FK "References PERSONA_LINKS"
        string evidence_type "pgp | wallet | favicon | handle"
        float llr "Log-Likelihood Ratio value"
        string raw_value "Supporting proof snippet"
        string notes "Investigator notes"
    }

    AUDIT_LOG {
        int id PK "Serial identifier"
        string user_id FK "References USERS"
        string action "LOGIN | EXPORT | TRIAGE | EDIT"
        string target "Accessed resource identifier"
        datetime timestamp "IT Act Section 65B timestamp"
        json detail "Contextual payload metadata"
        string integrity_hash "SHA-256 chain verification hash"
    }
```

### Neo4j Graph Schema

```mermaid
flowchart LR
    A1["👤 <b>:Actor</b><br/>name: 'LockBit 3.0'<br/>status: 'active'<br/>score: 94.2"]
    A2["👤 <b>:Actor</b><br/>name: 'DarkBitz'<br/>status: 'dormant'<br/>score: 72.0"]

    P1["🪪 <b>:Persona</b><br/>handle: 'lockbit_supp'<br/>platform: 'Tox/XMPP'"]
    W1["💰 <b>:CryptoWallet</b><br/>addr: 'bc1q9...83j'<br/>chain: 'BTC'<br/>balance: 14.82 BTC"]
    W2["💰 <b>:CryptoWallet</b><br/>addr: '1P5Z...9z8'<br/>chain: 'BTC'<br/>cluster: 'Laundering'"]

    O1["🧅 <b>:DarkwebSite</b><br/>onion: 'lockbit7...onion'<br/>title: 'LockBit Blog'<br/>status: 'online'"]
    I1["🖥️ <b>:Infrastructure</b><br/>ip: '185.220.101.5'<br/>asn: 'AS208323'<br/>country: 'DE'"]
    C1["📜 <b>:TLSCertificate</b><br/>fingerprint: 'a7c9...1f'<br/>san: 'leak-service.org'"]

    A1 -->|OPERATES| P1
    A1 -->|CONTROLS| W1
    A1 -->|HOSTS| O1

    W1 -->|TRANSFERS_TO<br/><i>tx: 5.2 BTC</i>| W2
    O1 -->|HOSTED_ON| I1
    I1 -->|SERVES_CERT| C1

    A1 <==|REBRANDED_TO<br/><b>Bayesian Score: 87.4 (Band A)</b><br/><i>LLR: +4.8 (PGP & Wallet Match)</i>|==> A2

    classDef actorStyle fill:#09090b,stroke:#f43f5e,stroke-width:2px,color:#f8fafc;
    classDef personaStyle fill:#061a12,stroke:#10b981,stroke-width:1.5px,color:#d1fae5;
    classDef cryptoStyle fill:#1a1505,stroke:#f59e0b,stroke-width:1.5px,color:#fef3c7;
    classDef onionStyle fill:#160b24,stroke:#a855f7,stroke-width:1.5px,color:#f3e8ff;
    classDef infraStyle fill:#031525,stroke:#0ea5e9,stroke-width:1.5px,color:#e0f2fe;

    class A1,A2 actorStyle;
    class P1 personaStyle;
    class W1,W2 cryptoStyle;
    class O1 onionStyle;
    class I1,C1 infraStyle;
```

### Persona Link Scoring (Bayesian LLR)

```mermaid
flowchart TD
    subgraph EVIDENCE["CORRELATED EVIDENCE INPUTS"]
        direction LR
        subgraph T1["Tier 1: Cryptographic Determinism"]
            E1["🔑 <b>PGP Fingerprint Match</b><br/><code>LLR = +5.0</code>"]
            E2["🗝️ <b>SSH Host Key Match</b><br/><code>LLR = +4.5</code>"]
            E3["⛓️ <b>Multi-Sig Wallet Co-spend</b><br/><code>LLR = +4.0</code>"]
        end

        subgraph T2["Tier 2: Infrastructure & Financial"]
            E4["💰 <b>Direct Wallet Transfer</b><br/><code>LLR = +2.8</code>"]
            E5["🧅 <b>Colocated Onion / TLS SAN</b><br/><code>LLR = +2.5</code>"]
            E6["🖼️ <b>Murmur3 Favicon Hash</b><br/><code>LLR = +2.0</code>"]
        end

        subgraph T3["Tier 3: Behavioral & Heuristics"]
            E7["👤 <b>Exact Handle Match</b><br/><code>LLR = +1.5</code>"]
            E8["📝 <b>Stylometry Vocabulary Match</b><br/><code>LLR = +1.0</code>"]
            E9["⏰ <b>Temporal Activity Overlap</b><br/><code>LLR = +0.6</code>"]
        end
    end

    subgraph ENGINE["BAYESIAN EVIDENCE ACCUMULATION ENGINE"]
        CALC["<b>Log-Likelihood Ratio Accumulator</b><br/><code>LLR_total = ∑ LLR_i</code><br/><code>Posterior Probability = 1 / (1 + e^(-LLR_total))</code>"]
    end

    subgraph BANDS["CONFIDENCE BANDS & OPERATIONAL ACTION"]
        direction LR
        B_A["🟢 <b>BAND A (Score 80–100)</b><br/><b>Verified Attribution</b><br/>• Automated entity linkage<br/>• High-priority LE alert"]
        B_B["🔵 <b>BAND B (Score 60–79)</b><br/><b>High Probability Link</b><br/>• Flagged for Analyst Confirmation<br/>• Corroboration scheduled"]
        B_C["🟡 <b>BAND C (Score 40–59)</b><br/><b>Moderate Lead</b><br/>• Displayed in exploratory graph<br/>• Awaiting further data"]
        B_DE["⚪ <b>BAND D/E (Score < 40)</b><br/><b>Low / Speculative</b><br/>• Suppressed from public dossiers<br/>• Stored for historical indexing"]
    end

    E1 & E2 & E3 -->|Tier 1: High LLR| CALC
    E4 & E5 & E6 -->|Tier 2: Medium LLR| CALC
    E7 & E8 & E9 -->|Tier 3: Heuristic LLR| CALC
    CALC --> B_A
    CALC --> B_B
    CALC --> B_C
    CALC --> B_DE

    classDef t1Style fill:#09090b,stroke:#f43f5e,stroke-width:1.5px,color:#f8fafc;
    classDef t2Style fill:#1a1505,stroke:#f59e0b,stroke-width:1.5px,color:#fef3c7;
    classDef t3Style fill:#031525,stroke:#0ea5e9,stroke-width:1.5px,color:#e0f2fe;
    classDef calcStyle fill:#0f172a,stroke:#38bdf8,stroke-width:2px,color:#f8fafc;
    classDef bandA fill:#061a12,stroke:#10b981,stroke-width:2px,color:#d1fae5;
    classDef bandB fill:#031525,stroke:#3b82f6,stroke-width:1.5px,color:#dbeafe;
    classDef bandC fill:#1a1505,stroke:#f59e0b,stroke-width:1.5px,color:#fef3c7;
    classDef bandDE fill:#18181b,stroke:#71717a,stroke-width:1px,color:#a1a1aa;

    class E1,E2,E3 t1Style;
    class E4,E5,E6 t2Style;
    class E7,E8,E9 t3Style;
    class CALC calcStyle;
    class B_A bandA;
    class B_B bandB;
    class B_C bandC;
    class B_DE bandDE;
```

---

## `09` Security & Compliance

### Authentication & Authorization Flow

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as 👮 Investigator / Analyst
    box rgba(30, 41, 59, 0.5) Client Presentation Tier
        participant FE as 💻 Next.js Frontend
    end
    box rgba(15, 23, 42, 0.7) Security Gateway Tier
        participant API as ⚡ FastAPI Gateway
    end
    box rgba(9, 9, 11, 0.9) Storage & Message Tier
        participant DB as 🐘 PostgreSQL 16
        participant RD as ⚡ Redis 7
    end

    Note over Analyst,FE: Step 1: Authentication & Token Issuance
    Analyst->>FE: Enter Credentials (username, password)
    FE->>API: POST /api/v1/auth/login
    API->>API: Rate Limit Check (SlowAPI: 60 req/min)
    API->>DB: Query User Record (SELECT * FROM users WHERE username = ?)
    DB-->>API: User Record + Salted bcrypt Hash
    API->>API: Verify Password Hash (bcrypt.verify)
    API->>API: Generate Dual JWT Tokens (HS256 with 64-char key)
    API->>DB: INSERT into audit_log (action='LOGIN', status='SUCCESS')
    API-->>FE: HTTP 200 { access_token, refresh_token, role }
    FE->>FE: Store Token in Protected Session Storage

    Note over Analyst,FE: Step 2: Authenticated Intelligence Access
    Analyst->>FE: Navigate to Actor Dossier (/actors/149)
    FE->>API: GET /api/v1/actors/149 (Authorization: Bearer <JWT>)
    API->>API: Validate Token Signature & Expiry
    API->>API: Enforce Role-Based Access Control (RBAC: 'analyst')
    API->>RD: Check Query Cache (Key: actor:149)
    alt Cache Miss
        API->>DB: Fetch Actor Profile, Corroborated Entities & Evidence
        DB-->>API: Return Relational Entity Records
        API->>RD: Populate Cache (TTL 120s)
    else Cache Hit
        RD-->>API: Return Cached Intelligence
    end
    API->>DB: INSERT into audit_log (action='VIEW_DOSSIER', target='149')
    API-->>FE: HTTP 200 { actor_dossier_payload }
    FE-->>Analyst: Render Interactive Dossier & Graph View
```

### OWASP Top 10 Coverage

| OWASP ID | Threat | NETRA Mitigation |
|:---------|:-------|:-----------------|
| A01 | Broken Access Control | Strict RBAC with JWT token scopes, role-based API route guards |
| A02 | Cryptographic Failures | Salted bcrypt password hashing, JOSE/JWE encrypted token exchange |
| A03 | Injection | SQLAlchemy ORM parameterized queries, Pydantic strict payload validation |
| A04 | Insecure Design | Threat-modeled architecture, principle of least privilege across services |
| A05 | Security Misconfiguration | Docker `security_opt: [no-new-privileges:true]`, read-only filesystems |
| A07 | Auth Failures | Brute-force lockout (5 attempts / 30m), SlowAPI IP rate limiting |
| A09 | Logging & Monitoring | Immutable SHA-256 chained audit_log table, structured JSON logging |

### Legal & Regulatory Compliance

```mermaid
flowchart TD
    subgraph MANDATES["🏛️ INDIAN STATUTORY & REGULATORY MANDATES"]
        direction LR
        M1["📜 <b>IT Act, 2000</b><br/>• Section 66 (Cyber Offenses)<br/>• Section 69 (Lawful Interception)<br/>• Section 79 (Intermediary Due Diligence)"]
        M2["⚖️ <b>IT Act Section 65B</b><br/>• Admissibility of Electronic Records<br/>• Certified SHA-256 Hash Evidence<br/>• Tamper-Evident Audit Timestamps"]
        M3["🚨 <b>CERT-In Directions 2022</b><br/>• 6-Hour Mandatory Incident Reporting<br/>• Threat IOC Dissemination Formats<br/>• Strict Log Preservation Rules"]
        M4["🛡️ <b>NCIIPC & MHA I4C</b><br/>• Critical Information Infra Protection<br/>• Cyber Crime Coordination Centre<br/>• NCRP Threat Data Interchange"]
    end

    subgraph ENGINE["Ψ NETRA AUTOMATED COMPLIANCE & GOVERNANCE CORE"]
        direction TB
        CORE(["Ψ <b>NETRA COMPLIANCE & PROVENANCE ENGINE</b><br/><i>Continuous Automated Verification • SHA-256 Chain of Custody • Zero Active Intrusion</i>"])
        C_AUDIT["🔒 <b>Tamper-Evident Audit Logging</b><br/>SHA-256 chained transaction log recording every search, query, and export action"]
        C_PASSIVE["🛡️ <b>Strict Passive Reconnaissance</b><br/>Exclusively utilizes public OSINT, Tor relays & CT logs • Zero active intrusion"]
        C_EVIDENCE["📑 <b>Automated §65B Certificate Generation</b><br/>PDF exports embedded with cryptographic checksums, system time & officer credentials"]
        C_REDACT["🎭 <b>PII & Privacy Boundary Guard</b><br/>Automated masking of victim PII & non-target civilian personal data"]

        CORE --> C_AUDIT & C_PASSIVE & C_EVIDENCE & C_REDACT
    end

    subgraph STANDARDS["🌐 INTERNATIONAL CYBERSECURITY & THREAT STANDARDS"]
        direction LR
        S1["🛡️ <b>NIST CSF v2.0</b><br/>Identify • Protect • Detect<br/>Respond • Recover"]
        S2["🎯 <b>MITRE ATT&CK</b><br/>Adversary TTP Mapping<br/>Enterprise Cyber Matrix"]
        S3["📦 <b>STIX / TAXII 2.1</b><br/>Automated Threat Intel<br/>Structured CTI Exchange"]
        S4["🤝 <b>Budapest Convention</b><br/>Cross-Border Cybercrime<br/>Digital Evidence Standards"]
    end

    M1 & M2 & M3 & M4 ==>|Mandatory Legal Directives| CORE
    S1 & S2 & S3 & S4 ==>|Architectural Frameworks| CORE

    classDef mandateStyle fill:#09090b,stroke:#f43f5e,stroke-width:1.5px,color:#f8fafc;
    classDef coreStyle fill:#000000,stroke:#38bdf8,stroke-width:2px,color:#f8fafc;
    classDef engineStyle fill:#0f172a,stroke:#38bdf8,stroke-width:1.5px,color:#f8fafc;
    classDef standardStyle fill:#1a1505,stroke:#f59e0b,stroke-width:1.5px,color:#fef3c7;

    class M1,M2,M3,M4 mandateStyle;
    class CORE coreStyle;
    class C_AUDIT,C_PASSIVE,C_EVIDENCE,C_REDACT engineStyle;
    class S1,S2,S3,S4 standardStyle;
```

---

## `10` Quick Start

### Prerequisites

- Docker & Docker Compose
- Node.js 18+ (for frontend development)
- Python 3.12+ (for backend development)

### One-Command Launch

```bash
# Clone repository
git clone https://github.com/Swaggyop/netra.git
cd netra

# Configure environment variables
cp .env.example .env
# Edit .env with your environment-specific secrets

# Launch all 6 microservices
make up

# Run database migrations
make migrate

# Seed database with initial registry
make seed

# Generate synthetic intelligence data
make generate

# Start frontend development server
cd frontend && npm install && npm run dev
```

### Full Demo (single command)

```bash
make demo    # runs: up → migrate → seed → generate → replay
```

### Access Points

| Service | URL | Description |
|:--------|:----|:------------|
| **Dashboard** | http://localhost:3000 | Investigator Next.js UI |
| **API Docs** | http://localhost:8000/docs | Interactive Swagger UI |
| **Neo4j Browser** | http://localhost:7474 | Graph DBMS Console |
| **WebSocket Feed** | ws://localhost:8000/ws/feed | Real-time Alert Stream |

### Initial Access & Authentication Setup

> [!IMPORTANT]
> **Zero Default Passwords Policy (OWASP A07 / CERT-In Compliance)**:
> In accordance with Indian cybersecurity guidelines and secure development best practices, NETRA **does not ship with hardcoded credentials** in version control.
>
> 1. Initial administrator access is provisioned during the seed phase:
>    ```bash
>    make seed
>    ```
> 2. The seed script provisions an initial admin account and outputs development access credentials to the secure console.
> 3. For staging or production deployments, specify custom administrator credentials directly in your uncommitted `.env` file before initial boot.
> 4. **Mandatory Security Requirement**: Change default development passwords immediately upon first login via the user management profile.

---

## `11` Environment Variables

```bash
# ── Application ──────────────────────────────
APP_NAME=netra
APP_ENV=development          # development | staging | production
SECRET_KEY=<random-64-character-secret>
ALLOWED_HOSTS=localhost,127.0.0.1

# ── PostgreSQL ───────────────────────────────
POSTGRES_HOST=postgres
POSTGRES_PORT=5432           # Internal Docker network port (mapped to 5433 on host)
POSTGRES_DB=netra
POSTGRES_USER=netra
POSTGRES_PASSWORD=<strong-database-password>

# ── Neo4j ────────────────────────────────────
NEO4J_URI=bolt://neo4j:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=<strong-graph-password>

# ── Redis ────────────────────────────────────
REDIS_URL=redis://redis:6379/0
CELERY_BROKER_URL=redis://redis:6379/1
CELERY_RESULT_BACKEND=redis://redis:6379/2

# ── MinIO (Object Storage) ───────────────────
MINIO_ENDPOINT=minio:9000
MINIO_ACCESS_KEY=<minio-access-key>
MINIO_SECRET_KEY=<minio-secret-key>

# ── Tor (Optional SOCKS5) ────────────────────
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
