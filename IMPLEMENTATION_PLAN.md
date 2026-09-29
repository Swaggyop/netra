# NETRA — Implementation Plan (Agent-Ready)

**NETRA** = Networked Evidence & Threat-actor Relationship Analyzer (placeholder name, rename freely)
**Problem statement:** SIH26151 — Dark web threat actor de-anonymization (NTRO, Blockchain & Cybersecurity)
**Positioning:** An evidence-driven threat-actor *attribution assistance* platform. It correlates infrastructure, identifiers, financial artifacts, behaviour and writing style across time. Final attribution is always an analyst decision.

This file is the build spec for an AI coding agent. The companion file `SYSTEM_DESIGN.md` explains the reasoning. Read both. Where they conflict, this file wins for implementation.

---

## 0. Hard rules for the agent (non-negotiable)

1. **Do NOT write crawlers, scrapers, or adapters that target live illegal marketplaces, extremist forums, or any real illicit .onion service.** Do not add real illicit onion addresses anywhere in code, config, tests, or docs.
2. The `authorized` adapter type exists only as an **interface plus a disabled stub** that raises `NotAuthorizedError` unless a signed authorization reference is configured. Ship it disabled.
3. Every source must exist in the **source registry** with `authorization_status = approved` (or `authorized` with a reference) before any adapter may collect from it.
4. The **policy gate runs BEFORE collection and storage**. Prohibited content is never downloaded, never stored. No image, video, or archive collection in the MVP at all.
5. All Tor traffic goes through a dedicated Tor container. Never call the host network directly for `.onion` targets.
6. Redact PII (Aadhaar, PAN, phone, victim emails) at ingestion, before persistence.
7. No blocking work in the request path. Use the worker queue.
8. Everything that produces a score must also produce an **evidence chain** (see section 8).

---

## 1. MVP scope (frozen) — build in this order

| # | Module | Acceptance (short) |
|---|---|---|
| MVP-1 | Source adapters: synthetic + approved OSINT feed + replay dataset | Events flow through one pipeline in all 3 modes |
| MVP-2 | Entity extraction | handle, PGP, wallet, email, domain, onion, timestamp extracted with tests |
| MVP-3 | Actor graph (Neo4j) | Entity resolution merges identities across 3+ synthetic markets |
| MVP-4 | Infrastructure correlation | Self-hosted onion lab leaks are detected and matched to lab clearnet twins |
| MVP-5 | Persona correlation | Baseline stylometry vs SBERT evaluated; best model selected by metrics |
| MVP-6 | Evidence / confidence engine | Explainable score with evidence chain and Admiralty grading |
| MVP-7 | Investigator dashboard | Graph + timeline + evidence panel + CSV/JSON/PDF export |

**Stretch (only after MVP-7 is demo-ready, in this order):** blockchain anchoring, STIX 2.1 export, advanced wallet analysis, OpenSearch, behaviour prediction, local LLM copilot, more adapters.

---

## 2. Pinned stack

| Concern | Choice |
|---|---|
| Language | Python 3.12 (backend/analytics), TypeScript 5 (frontend) |
| API | FastAPI, Pydantic v2, Uvicorn |
| ORM/migrations | SQLAlchemy 2.x, Alembic |
| Relational DB | PostgreSQL 16 (also full-text search via `tsvector` in MVP) |
| Graph DB | Neo4j 5 Community, official Python driver |
| Event bus | Redpanda (Kafka API; durable log for events + replay) |
| Worker queue / cache | Redis 7 (Celery 5 broker + general cache) |
| Object storage | MinIO (S3-compatible) for text snapshots and reports |
| NLP | spaCy 3 (`en_core_web_sm`), regex extractors, `langdetect` |
| Stylometry | scikit-learn (TF-IDF, LogisticRegression), `sentence-transformers` + PyTorch |
| Tor | Docker `tor` container exposing SOCKS5 on 9050 (collectors use `httpx[socks]`) |
| Lab | Docker `tor` (onion service) + `nginx` containers |
| Reports | Jinja2 + WeasyPrint (PDF), stdlib csv/json |
| Frontend | React 18, Vite, Tailwind, Cytoscape.js, Recharts, TanStack Query |
| Tests | pytest, pytest-asyncio, Playwright (UI smoke), Ruff, mypy |
| Deploy | Docker Compose, one command: `make up` |

Scale-path (design only, do not build in MVP): OpenSearch in place of Postgres FTS, Airflow for complex scheduling.

Dev fallback: an `EventBus` protocol interface allows swapping Redpanda for Redis Streams on resource-constrained machines (`EVENT_BUS=redis` in `.env`). CI and production always use Redpanda.

---

## 3. Repository layout

```
netra/
├── docker-compose.yml
├── Makefile                      # up, down, seed, replay, test, demo
├── .env.example
├── docs/
│   ├── IMPLEMENTATION_PLAN.md
│   └── SYSTEM_DESIGN.md
├── backend/
│   ├── app/
│   │   ├── main.py               # FastAPI app
│   │   ├── config.py
│   │   ├── api/                  # routers: actors, graph, evidence, sources, search, exports, alerts
│   │   ├── core/
│   │   │   ├── events.py         # Event schema + EventBus protocol (Redpanda/Kafka default, Redis Streams fallback)
│   │   │   ├── registry.py       # source registry access
│   │   │   ├── policy.py         # policy gate
│   │   │   ├── safety.py         # content safety gate
│   │   │   ├── provenance.py     # hashing, evidence IDs, Merkle batches
│   │   │   └── redaction.py
│   │   ├── adapters/
│   │   │   ├── base.py           # SourceAdapter protocol
│   │   │   ├── synthetic.py
│   │   │   ├── replay.py
│   │   │   ├── osint_feeds.py    # approved feeds (abuse.ch, ransomware trackers, OTX, MISP feeds)
│   │   │   ├── clearnet_intel.py # crt.sh, optional Shodan/Censys, urlscan
│   │   │   ├── blockchain.py     # mempool.space / Blockstream / Etherscan readers
│   │   │   └── authorized_stub.py# DISABLED, raises NotAuthorizedError
│   │   ├── extraction/           # regex + spaCy extractors
│   │   ├── analytics/
│   │   │   ├── infra/            # fingerprints, matcher
│   │   │   ├── wallet/           # clustering heuristics
│   │   │   ├── stylometry/       # baseline.py, sbert.py, evaluate.py
│   │   │   ├── behaviour/        # circadian, cadence
│   │   │   ├── resolution/       # entity resolution
│   │   │   ├── confidence/       # LLR engine, admiralty
│   │   │   └── rebrand/          # migration detector
│   │   ├── graph/                # Neo4j schema, queries
│   │   ├── models/               # SQLAlchemy models
│   │   ├── exports/              # csv, json, pdf, (stix stretch)
│   │   └── workers/              # celery app + tasks
│   ├── migrations/
│   └── tests/
├── lab/
│   ├── onion_a_vulnerable/       # nginx: server-status, SAN cert, default banner, shared favicon
│   ├── onion_b_mixed/
│   ├── onion_c_hardened/
│   ├── clearnet_twin/            # nginx twins that share fingerprints with onion_a/b
│   └── mock_clearnet_index/      # small API imitating a Shodan/Censys-style index for lab hosts
├── datagen/
│   ├── generate.py               # synthetic actors, markets, posts, wallets, keys
│   ├── scenarios/                # rebrand_basic.yaml, rebrand_hard.yaml, decoys.yaml
│   └── personas/                 # style profiles used to generate text
├── datasets/                     # replay data (gitignored; README explains sourcing)
├── eval/                         # stylometry + linking evaluation notebooks/scripts
└── frontend/
    └── src/{pages,components,graph,api}/
```

---

## 4. Docker Compose services

`postgres`, `neo4j`, `redpanda`, `redis`, `minio`, `tor` (SOCKS5 proxy), `api` (FastAPI), `worker` (Celery), `beat` (Celery scheduler), `replay` (replay engine), `frontend`, plus lab services `onion_a`, `onion_b`, `onion_c`, `clearnet_twin`, `mock_clearnet_index`.

Networks: `core_net` (api, db, workers), `collect_net` (tor + collectors only), `lab_net` (isolated lab). Only `tor` and collectors may attach to `collect_net`.

---

## 5. Event contract (freeze before any pipeline code)

```json
{
  "event_id": "uuid4",
  "source_id": "src_synthetic_market_1",
  "adapter_type": "synthetic | replay | osint_feed | clearnet_intel | blockchain | authorized",
  "mode": "live | replay | authorized",
  "observed_at": "2026-01-14T09:21:00Z",
  "collected_at": "2026-01-14T09:21:04Z",
  "content_type": "text | json",
  "payload_ref": "s3://netra-snapshots/2026/01/14/<event_id>.txt",
  "content_hash": "sha256:...",
  "policy_decision_id": "uuid4",
  "language": "en",
  "raw_metadata": { "url": "...", "title": "...", "author_handle": "...", "thread_id": "..." },
  "redactions": ["aadhaar:1", "phone:2"]
}
```

Pipeline stage outputs append to the event (`entities`, `fingerprints`, `links`) in Postgres, not by mutating the stream message.

---

## 6. Data model

### 6.1 Postgres (DDL summary)

```sql
sources(source_id PK, name, source_type, collection_method, authorization_status,
        authorization_ref, permitted_use, retention_days, pii_policy,
        reliability_grade CHAR(1), enabled BOOL, last_scan_at, created_at);

policy_decisions(decision_id PK, source_id FK, event_id, rule_hits JSONB,
                 decision TEXT CHECK (decision IN ('allow','block','redact_allow')),
                 decided_at);

events(event_id PK, source_id FK, mode, observed_at, collected_at, content_hash,
       payload_ref, language, raw_metadata JSONB);

evidence(evidence_id PK, event_id FK, content_hash, merkle_batch_id, collected_at, source_id);
merkle_batches(batch_id PK, root_hash, leaf_count, created_at, anchor_ref NULL, anchor_type NULL);

entities(entity_id PK, kind TEXT, value TEXT, normalized TEXT, first_seen, last_seen,
         UNIQUE(kind, normalized));           -- kind: handle|pgp|wallet|email|domain|onion|contact_id|avatar_hash|ip|favicon_hash|cert_fp|ssh_key
observations(obs_id PK, event_id FK, entity_id FK, role TEXT, observed_at);

actors(actor_id PK, label, category, first_seen, last_seen, status, last_scan_at);
actor_entities(actor_id FK, entity_id FK, added_by TEXT, added_at, PRIMARY KEY(actor_id, entity_id));

persona_links(link_id PK, actor_a FK, actor_b FK, link_type TEXT, score NUMERIC,
              band TEXT, computed_at, model_version, analyst_status TEXT DEFAULT 'pending');
link_evidence(link_id FK, evidence_type TEXT, raw_value JSONB, llr NUMERIC,
              source_id FK, reliability CHAR(1), credibility SMALLINT, note TEXT);

infra_findings(finding_id PK, onion_entity FK, kind TEXT, raw JSONB, matched_clearnet JSONB,
               confidence NUMERIC, detected_at, source_id FK);

posts(post_id PK, event_id FK, actor_id FK NULL, handle TEXT, market TEXT, text TEXT,
      posted_at, tsv TSVECTOR);            -- GIN index on tsv
alerts(alert_id PK, alert_type, subject JSONB, score, created_at, status);
watchlist(item_id PK, entity_id FK, created_by, created_at);
audit_log(id PK, actor TEXT, action TEXT, target TEXT, at, detail JSONB);
```

### 6.2 Neo4j

Node labels (each has a uniqueness constraint on `id`):
`Actor`, `Handle`, `PGPKey`, `Wallet`, `WalletCluster`, `Email`, `ContactID`, `AvatarHash`, `Onion`, `Domain`, `IP`, `Cert`, `Favicon`, `SSHKey`, `Market`, `Listing`, `Post`.

Relationships (all carry `first_seen`, `last_seen`, `source_id`, `evidence_id`):
`(:Actor)-[:USES]->(:Handle|:PGPKey|:Wallet|:Email|:ContactID|:AvatarHash)`
`(:Handle)-[:ACTIVE_ON]->(:Market)`
`(:Wallet)-[:MEMBER_OF]->(:WalletCluster)`
`(:Wallet)-[:SENT_TO {amount, ts}]->(:Wallet)`
`(:Onion)-[:SHARES_FINGERPRINT {kind, value}]->(:Domain|:IP)`
`(:Onion)-[:OPERATED_BY_LIKELY {score}]->(:Actor)`
`(:Actor)-[:LINKED_TO {score, band, link_id}]->(:Actor)`
`(:Handle)-[:TRUSTS|VOUCHES_FOR]->(:Handle)`

---

## 7. Pipeline (module contracts)

```
SOURCE ADAPTER → POLICY GATE → CONTENT SAFETY GATE → MINIMAL COLLECTION
→ HASH/PROVENANCE → NORMALIZATION → ENTITY EXTRACTION → CORRELATION
→ GRAPH → ATTRIBUTION ASSESSMENT → ANALYST REVIEW
```

```python
class SourceAdapter(Protocol):
    source_id: str
    def discover(self) -> Iterable[CandidateRef]: ...        # metadata only, no content
    def fetch(self, ref: CandidateRef) -> RawItem: ...       # only called after policy allow

class PolicyGate:
    def decide(self, source: Source, ref: CandidateRef) -> PolicyDecision: ...
    # rules: source enabled + approved/authorized, domain allow/deny list,
    # content-type allowlist (text/html, application/json only), size cap,
    # retention policy attached, mode/legal-basis tag recorded

class SafetyGate:
    def pre_fetch(self, ref) -> Allow|Block      # metadata / content-type decision, no download
    def post_fetch(self, raw) -> Allow|Block     # text-only keyword+classifier check, then discard on block

class Extractor(Protocol):
    def extract(self, text: str, meta: dict) -> list[EntityHit]: ...
```

Rules of the flow:
- `discover()` → `PolicyGate.decide()` → `SafetyGate.pre_fetch()` → `fetch()` → `SafetyGate.post_fetch()` → redaction → hash → store → extract.
- A blocked item writes only a `policy_decisions` row. No payload is kept.
- Every allowed item gets `content_hash`, an `evidence` row, and joins the current Merkle batch (batch closes every N items or T minutes).

### Extractors (regex first, spaCy second, all unit-tested)
- **PGP fingerprint** (40 hex, spaced variants), armored key blocks (store fingerprint only)
- **Wallets**: BTC (legacy, P2SH, bech32), ETH (`0x` + 40 hex, checksum), TRON (`T` + base58), XMR (95-char)
- **Emails**, **domains**, **onion v3** (56 chars + `.onion`), **URLs**
- **Contact IDs**: Telegram `@name`, Jabber/XMPP JIDs, Session/Wickr-style IDs by pattern
- **Handles** from post metadata and signature patterns
- **Timestamps**, **language**, **avatar hash** (perceptual hash of synthetic avatars only in lab)

---

## 8. Confidence engine (explainable attribution)

### 8.1 Evidence types and likelihood ratios (starting values; recalibrate on synthetic validation)

| Evidence | LR | Family |
|---|---|---|
| PGP fingerprint identical | 1000 | key |
| SSH host key identical (onion ↔ clearnet) | 1000 | infra |
| Contact ID identical | 500 | contact |
| Cert SAN/CN names the clearnet domain | 300 | infra |
| Wallet in same cluster | 200 | financial |
| Direct wallet-to-wallet transfer | 50 | financial |
| Favicon hash match | 30 | infra |
| Handle exact match | 30 | handle |
| Avatar hash match | 20 | handle |
| Handle similar (Jaro-Winkler ≥ 0.90) | 5 | handle |
| Stylometry (calibrated) | from isotonic bins | linguistic |
| Banner/header match only | 3 | infra |
| Circadian/activity overlap | 2–3 | temporal |

### 8.2 Scoring

```
prior_odds      = 1 / 1000                       (configurable)
adj_llr(e)      = ln(LR_e) * reliability_factor(grade) * credibility_factor(level)
family_llr(f)   = max(adj_llr in f) + 0.5 * sum(other adj_llr in f)    # damps correlated evidence
posterior_odds  = prior_odds * exp( sum over families family_llr )
posterior       = posterior_odds / (1 + posterior_odds)
score (0-100)   = round(posterior * 100)
band            = VERY_HIGH ≥ 90 | HIGH ≥ 75 | MODERATE ≥ 50 | LOW ≥ 25 | WEAK < 25
```

Admiralty factors (configurable):
- Reliability A=1.0, B=0.85, C=0.70, D=0.50, E=0.30, F=0.0 (unreliable → ignored)
- Credibility 1=1.0, 2=0.90, 3=0.75, 4=0.55, 5=0.35, 6=0.15

### 8.3 Evidence chain output (per link)
Store one `link_evidence` row per evidence item and return:

```json
{
  "link_id": "...", "actor_a": "ShadowX", "actor_b": "DarkWolf",
  "score": 94, "band": "VERY_HIGH", "analyst_status": "pending",
  "evidence": [
    {"type": "pgp_fingerprint", "strength": "very_strong", "source": "src_x", "reliability": "A", "credibility": 1},
    {"type": "wallet_cluster", "strength": "strong", "reliability": "B", "credibility": 2},
    {"type": "stylometry", "strength": "moderate", "value": 0.83},
    {"type": "temporal_overlap", "strength": "weak"}
  ],
  "why": ["Same PGP fingerprint", "Same wallet cluster", "Similar writing profile", "Overlapping activity window"]
}
```

The UI must render this as horizontal strength bars plus the "Why was this link created?" list. Never show a bare percentage.

---

## 9. Stylometry (make it an experiment, not an assumption)

Models to implement and compare in `eval/`:

| ID | Model |
|---|---|
| S1 | Character n-grams (3–5) TF-IDF + cosine |
| S2 | Word n-grams (1–2) TF-IDF + cosine |
| S3 | Function-word frequency + punctuation + length features → logistic regression on pair features |
| S4 | Sentence-Transformer embeddings (`all-MiniLM-L6-v2`, multilingual variant for Hinglish test) cosine |
| S5 | S4 fine-tuned with contrastive/triplet loss on training persona pairs |

Data: synthetic personas (datagen) + a public authorship corpus (PAN authorship verification, Blog Authorship Corpus) for sanity checks. Minimum text length per persona pair: 300 words (configurable).
Metrics: ROC-AUC, EER, accuracy at chosen threshold, calibration curve. Pick the model by validation score, save `model_version`, and fit **isotonic regression** to map similarity → LR bins for the confidence engine.
Also include a **decoy set**: different personas with similar topics (to measure false links). Report false-link rate.

---

## 10. Infrastructure correlation (MVP-4)

Lab hosts (all synthetic, isolated): 
- `onion_a` (vulnerable): exposed `/server-status`, default server banner, TLS cert whose SAN names `twin-a.lab.test`, shared favicon, unique header order.
- `onion_b` (mixed): favicon match only.
- `onion_c` (hardened): nothing leaks (control; must produce NO link).
- `clearnet_twin`: hosts sharing fingerprints with A and B.
- `mock_clearnet_index`: HTTP API returning lab clearnet records by `favicon_hash`, `cert_fp`, `ssh_key`, `banner`, imitating Shodan/Censys responses. Real Shodan/Censys/crt.sh adapters share the same interface and are enabled only with keys.

Detectors (each returns `InfraFinding`): exposed server-status/server-info, cert SAN/CN clearnet leak, default banner/version, favicon mmh3/MD5 hash, header ordering fingerprint, error-page fingerprint, SSH host key, clock-skew estimate (stretch). Matcher queries the clearnet index by each fingerprint and emits `SHARES_FINGERPRINT` edges plus an infra confidence (through the same confidence engine, infra family).

Acceptance: A → twin-a (high), B → twin-b (moderate), C → none.

---

## 11. Wallet logic (MVP minimal, advanced = stretch)

MVP: common-input-ownership heuristic on synthetic/replayed transaction sets; cluster ID stored as `WalletCluster`. Flag exit points via an **exchange-label table** (synthetic labels in MVP; GraphSense/OFAC/Chainabuse labels as approved feeds). Stretch: peel-chain detection, cross-chain (ETH, TRON-USDT), mixer flags.

---

## 12. Behaviour and rebrand detector

Behaviour features per actor: hour-of-day histogram (24 bins, circadian estimate of timezone), weekday histogram, posting cadence, category mix, price band.

**Rebrand detector rule:**
1. Candidate `A` is dormant ≥ `DORMANCY_DAYS` (default 14) and last seen at `t0`.
2. Candidate `B` first seen within `[t0, t0 + WINDOW_DAYS]` (default 45) and not co-active with A.
3. Compute evidence pairwise (keys, wallets, contact IDs, handle similarity, stylometry, behaviour) → confidence engine.
4. If score ≥ `ALERT_THRESHOLD` (default 75): raise `PERSONA_MIGRATION` alert with the evidence chain; status `pending` for analyst review.

This is the **centerpiece demo scenario**.

---

## 13. Synthetic data generator (`datagen/`)

- Inputs: scenario YAML (n_actors, n_markets, rebrand_pairs, decoys, noise, time_span).
- Outputs: markets, forum posts, handles, PGP fingerprints (random), fake wallets with transaction sets, contact IDs, avatar hashes, activity timestamps with persona-specific circadian shape.
- Text generation: template + persona style profile (punctuation habits, vocabulary, typo rates, Hinglish mix option). If a local LLM (Ollama) is available, use it with persona prompts; otherwise templates. **No real person data. No real illegal listing content.** Market items are neutral placeholders (e.g. "Item-1042") — the system tests linking, not content.
- Must include: rebrand pairs (easy/hard), decoy look-alikes, shared-key-only cases, wallet-only cases, and one "hardened" actor who should NOT be linked.
- Determinism: `--seed` flag. Ground truth file `truth.json` used by `eval/`.

Replay engine: reads generated (or approved archived) data and publishes events with original timestamps, speed factor `--speed 1|10|100`.

---

## 14. API (FastAPI, `/api/v1`)

```
GET  /actors?q=&category=&from=&to=&min_score=
GET  /actors/{id}                      profile, identifiers, infra, links, last_scan, sources
GET  /actors/{id}/graph?depth=2&from=&to=
GET  /links/{id}/evidence              evidence chain + why
POST /links/{id}/review                {status: confirmed|rejected|needs_info, note}
GET  /search?q=                        handle/PGP/wallet/onion/text
GET  /timeline?from=&to=&entity=
GET  /infra/findings?onion=
GET  /sources                          registry, grades, last scan
POST /sources/{id}/toggle              (admin, audit-logged)
GET  /alerts    PATCH /alerts/{id}
GET  /watchlist POST /watchlist
POST /exports  {format: csv|json|pdf, filter: {...}}   → job → download URL
GET  /provenance/{evidence_id}         hash, batch root, anchor status
GET  /health
```

Auth: JWT with roles `analyst`, `admin`, `viewer` (MVP: simple local users). Every read of an actor and every export is written to `audit_log`.

---

## 15. Frontend pages

1. **Dashboard/Graph** (centerpiece): search bar (actor/handle/PGP/wallet), Cytoscape graph (node colours by kind, edge width by score), side panel with evidence, timeline slider filtering the graph.
2. **Actor profile**: identifiers table, personas, infra indicators, category, last scan date, sources with grade chips (e.g. `B2`).
3. **Link review**: evidence bars, "Why was this link created?", confirm/reject buttons.
4. **Infrastructure**: onion → clearnet findings with matched fingerprints.
5. **Alerts**: persona-migration alerts, watchlist hits.
6. **Sources**: registry table (status, grade, retention, last scan, health).
7. **Exports**: format picker, filters, generated files list.
8. **Provenance viewer**: paste an evidence ID → shows hash, batch, root, anchor state, verify button.

UI must always show: score band + bars (never a bare %), source grade, last scan date, and the "analyst verification required" label on links.

---

## 16. Exports

- **CSV**: one row per actor: actor_id, label, category, handles, pgp, wallets, infra_indicators, linked_actors, attribution_confidence, last_scan_date, sources.
- **JSON**: full nested profile with evidence chains.
- **PDF/HTML report**: summary, graph snapshot image, evidence table, source grades, methodology + limitations paragraph, SHA-256 of the report, provenance IDs.
- (Stretch) **STIX 2.1** bundle via `stix2`.

---

## 17. Provenance and (stretch) blockchain anchoring

MVP: hash every stored payload (SHA-256) → `evidence` → Merkle batch → `merkle_batches.root_hash` in Postgres, with a verify endpoint (recompute root from stored leaves).
Stretch: anchor `root_hash` via OpenTimestamps or a testnet transaction; store `anchor_ref`. **The chain only holds hashes. Evidence stays in controlled storage.** Pitch it as tamper-evident provenance, not "blockchain stores the evidence."

---

## 18. Source registry seed (approved sources for the prototype)

| source_id | type | mode | notes |
|---|---|---|---|
| src_synthetic | synthetic | replay/live-sim | generated by `datagen` |
| src_replay_archive | archived dataset | replay | only datasets whose licence permits research use; document licence in registry |
| src_ransomware_trackers | OSINT feed | live | ransomware tracker APIs, metadata only |
| src_abusech | OSINT feed | live | URLhaus, ThreatFox, Feodo, SSLBL |
| src_otx / src_misp_osint | OSINT feed | live | indicator enrichment |
| src_crtsh | clearnet intel | live | Certificate Transparency queries |
| src_shodan / src_censys | clearnet intel | live (keys) | optional; lab uses mock index |
| src_blockchain_btc / eth / tron | blockchain | live | mempool.space, Blockstream, Etherscan, TronGrid |
| src_tor_metrics / src_ahmia | discovery | live | **metadata/discovery only**, never a bulk crawl source |
| src_lab_onions | lab | live | your own isolated services |
| src_authorized_* | authorized | disabled | interface only |

Each row: `authorization_status`, `permitted_use`, `retention_days`, `pii_policy`, `reliability_grade`. Seed via Alembic data migration + `make seed`.

---

## 19. Milestones (agent task list with acceptance tests)

**M0 — Freeze contracts (do first).** Event schema, Postgres DDL, Neo4j constraints, source registry, API stubs. *Accept:* migrations run; OpenAPI renders; JSON schema tests pass.

**M1 — Skeleton.** Compose stack up, health endpoints, Redpanda topics + consumer groups, Celery beat, MinIO bucket, Tor container reachable. *Accept:* `make up` all healthy; a test event round-trips through the event bus.

**M2 — Data + replay.** `datagen` scenarios + truth file; replay engine at 1×/10×/100×. *Accept:* generated data reproducible by seed; events appear in stream with correct timestamps.

**M3 — Policy/safety/provenance + extraction.** Policy gate, safety gate, redaction, hashing, Merkle batching, all extractors. *Accept:* blocked items leave no payload; extractor unit tests ≥ 95% on labelled fixtures; verify endpoint recomputes roots.

**M4 — Graph + entity resolution.** Load entities, resolve identities by shared strong identifiers, write Neo4j. *Accept:* on the truth set, rebrand pairs share a connected component; hardened actor stays isolated.

**M5 — Infra lab + correlation.** Lab containers, detectors, mock index, matcher. *Accept:* A→high, B→moderate, C→none, reproducible via `make lab-test`.

**M6 — Stylometry experiment.** Implement S1–S5, run `eval/`, store metrics, select model, calibrate to LRs. *Accept:* report with AUC/EER table and decoy false-link rate committed to `eval/results/`.

**M7 — Confidence engine + rebrand detector.** Section 8 and 12 exactly. *Accept:* rebrand scenario raises `PERSONA_MIGRATION` with score ≥ 75 and a full evidence chain; decoys stay below threshold.

**M8 — Dashboard + exports.** All pages in section 15, CSV/JSON/PDF exports, provenance viewer. *Accept:* Playwright smoke test walks the demo script (section 20).

**M9 — Stretch (in order):** OpenTimestamps/testnet anchoring → STIX 2.1 → wallet peel chains/cross-chain → OpenSearch → local LLM copilot (NL→Cypher, read-only, local model).

**M10 — Polish.** Docs, README, seed data, demo video script, safety slide assets.

---

## 20. Demo script (must work offline with `make demo`)

1. Dashboard shows source registry with grades and last-scan dates; live approved feeds ticking.
2. Start replay at 100×: new observations stream in, graph updates live.
3. Search `ShadowX`: actor page, identifiers, first/last seen.
4. Timeline slider: `ShadowX` goes dormant; `DarkWolf` appears 30 days later.
5. Alert: **POSSIBLE PERSONA MIGRATION**. Open evidence: PGP (very strong), wallet cluster (strong), stylometry (moderate), timing (weak); reliability/credibility grades; "why" list.
6. Infrastructure page: `onion_a` → `twin-a` via cert SAN + favicon; `onion_c` shows no findings.
7. Analyst confirms the link (audit-logged). Export CSV/JSON/PDF.
8. Provenance viewer: verify the report's evidence hash chain.
9. Show the disabled `authorized` adapter and the policy-gate block log (compliance story).

---

## 21. Definition of done

- `make up && make demo` runs the full story with no internet except approved feeds (which fall back to cached fixtures).
- All acceptance tests above pass in CI (`make test`).
- No adapter targets illicit services; the authorized adapter is disabled and documented.
- Every score in the UI has an evidence chain, a band, and source grades.
- `docs/SYSTEM_DESIGN.md` matches what was built (update if the build diverges).
