# NETRA — System Design Document

**NETRA** = Networked Evidence & Threat-actor Relationship Analyzer (placeholder name)
**Problem statement:** SIH26151, Dark web threat actor de-anonymization — National Technical Research Organisation (NTRO), Blockchain & Cybersecurity
**Companion file:** `IMPLEMENTATION_PLAN.md` (build spec for the coding agent)

---

## 1. Executive summary

NETRA is an evidence-driven dark-web threat-actor attribution platform. It correlates **infrastructure, identifiers, financial artifacts, behavioural patterns and linguistic signatures across time**, then produces explainable, graded links between personas, infrastructure and real-world indicators.

It does **not** break Tor and does **not** identify people automatically. Tor's protections hold; attribution comes from **operational mistakes** that actors make: reused keys and handles, reused wallets, misconfigured servers, consistent activity times, and consistent writing style. NETRA provides *attribution assistance*. Final attribution is always an analyst decision.

**Three ideas make it different:**
1. **Explainable attribution.** Every link shows the evidence chain, source grades and a strength breakdown, not a black-box percentage.
2. **One pipeline, three data modes** (Live, Replay, Authorized), so the system is genuinely continuous and autonomous while the prototype stays lawful.
3. **Compliance-by-design.** A policy gate and a safety gate sit before collection and storage. Provenance hashing makes evidence tamper-evident.

---

## 2. Mapping to the problem statement

| PS requirement | NETRA answer |
|---|---|
| Continuously gather footprints from many sources | Adapter framework + scheduler + event stream; source registry with grades and last-scan dates |
| Find Tor hidden-service misconfigurations and match to clearnet | Infra detectors (server-status, cert SAN, banners, favicon, headers, SSH key) + clearnet index matcher; demonstrated on a controlled lab |
| Map actors across marketplaces in one relationship graph (handles, PGP, wallets, trust links) | Neo4j actor graph with entity resolution |
| AI-based stylometry and behavioural profiling for rebrands and migrations | Baseline vs Sentence-Transformer stylometry (selected by measured performance), circadian/cadence features, rebrand detector |
| Analytical front end with timeline query | React + Cytoscape dashboard with a timeline slider and filters |
| Autonomous mode using good-quality, reliable sources | Scheduler + Admiralty A–F / 1–6 source grading that feeds the score |
| Profiles, identifiers, infra indicators, persona links, confidence, category, last scan, source | Data model fields exactly as listed; shown on the actor profile |
| Export CSV, JSON, report | CSV / JSON / PDF report (STIX 2.1 as stretch) |

---

## 3. "Real-time" — the design answer

The PS wants continuous, autonomous operation. That is an architecture property: adapters, a scheduler, an event stream and always-on analytics. Archives don't contradict this; they serve different roles.

```
                 SAME PIPELINE
                      │
       ┌──────────────┼───────────────┐
       ↓              ↓               ↓
     LIVE           REPLAY        AUTHORIZED
  approved feeds   datasets/       production
  (real-time)      synthetic       adapters
       │              │               │
       └──────────────┼───────────────┘
                      ↓
                Event Stream
                      ↓
               Analysis Engine
```

| Mode | Data | Role | Status in submission |
|---|---|---|---|
| **Live** | Approved/permitted intelligence feeds (ransomware trackers, abuse.ch, OTX/MISP feeds, CT logs, blockchain APIs, Tor Metrics), plus your own lab onions | Proves real continuous collection | Enabled |
| **Replay** | Synthetic data and licence-permitted archives streamed with original timestamps at 1×/10×/100× | Training, evaluation, controlled demo scenarios | Enabled |
| **Authorized** | Adapters that agencies (e.g. NTRO) run under legal authority against operational sources | The real deployment path | Interface only, disabled by default |

A student team should not claim to crawl illegal marketplaces. The demo replays a controlled dataset and shows **new observation → extraction → correlation → graph update → alert** in seconds. The authorized adapter shows exactly where an agency plugs in real sources; nothing downstream changes.

**Wording note:** call live sources *approved / permitted live intelligence feeds*. Public accessibility does not automatically permit every storage, enrichment or redistribution use. The source registry records the permitted use per source.

---

## 4. Architecture

### 4.1 Layered view

```
┌───────────────────────────────────────────────────────────────┐
│ 1  SOURCE LAYER          registry · adapters · scheduler      │
├───────────────────────────────────────────────────────────────┤
│ 2  GOVERNANCE LAYER      policy gate · safety gate · redaction│
├───────────────────────────────────────────────────────────────┤
│ 3  EVIDENCE LAYER        hashing · evidence IDs · Merkle batch│
├───────────────────────────────────────────────────────────────┤
│ 4  PROCESSING LAYER      normalisation · entity extraction    │
├───────────────────────────────────────────────────────────────┤
│ 5  ANALYTICS LAYER       infra · wallet · stylometry ·        │
│                          behaviour · entity resolution        │
├───────────────────────────────────────────────────────────────┤
│ 6  ATTRIBUTION LAYER     confidence engine · Admiralty grading│
│                          · rebrand detector · alerts          │
├───────────────────────────────────────────────────────────────┤
│ 7  STORAGE               PostgreSQL · Neo4j · MinIO · Redpanda │
│                          · Redis (cache/worker broker)         │
├───────────────────────────────────────────────────────────────┤
│ 8  SERVICE LAYER         FastAPI · auth · audit · exports     │
├───────────────────────────────────────────────────────────────┤
│ 9  INVESTIGATOR UI       graph · timeline · evidence · reports│
└───────────────────────────────────────────────────────────────┘
```

### 4.2 Component diagram

```
 ┌──────────────┐   ┌───────────────┐   ┌───────────────────┐
 │ Approved     │   │ Replay engine │   │ Authorized adapters│
 │ live feeds   │   │ + datagen     │   │ (disabled stub)    │
 └──────┬───────┘   └──────┬────────┘   └─────────┬─────────┘
        └──────────────────┼──────────────────────┘
                           ▼
                  ┌─────────────────┐    reads    ┌────────────┐
                  │ Source Adapter  │◄────────────│ Source     │
                  │ (discover)      │             │ Registry   │
                  └────────┬────────┘             └────────────┘
                           ▼
                  ┌─────────────────┐
                  │ POLICY GATE     │  approved? allowlist? type? size? retention?
                  └────────┬────────┘
                           ▼
                  ┌─────────────────┐
                  │ SAFETY GATE     │  pre-fetch: metadata/content-type decision
                  │ (pre/post)      │  post-fetch: text-only check, discard on block
                  └────────┬────────┘
                           ▼
                  ┌─────────────────┐
                  │ MINIMAL         │  text/JSON only; PII redaction
                  │ COLLECTION      │
                  └────────┬────────┘
                           ▼
                  ┌─────────────────┐   ┌────────┐
                  │ HASH/PROVENANCE │──►│ MinIO  │ payload
                  │ SHA-256 · ID ·  │   └────────┘
                  │ Merkle batch    │──►┌────────────┐
                  └────────┬────────┘   │ PostgreSQL │ evidence, events
                           ▼            └────────────┘
                  ┌─────────────────┐
                  │ NORMALISE +     │  handle · PGP · wallet · email ·
                  │ EXTRACT         │  domain · onion · contact ID · time
                  └────────┬────────┘
                           ▼
   ┌───────────┬───────────┬───────────────┬──────────────┐
   │ Infra     │ Wallet    │ Stylometry    │ Behaviour    │
   │ matcher   │ clusterer │ (baseline +   │ (circadian,  │
   │           │           │ SBERT)        │ cadence)     │
   └─────┬─────┴─────┬─────┴───────┬───────┴──────┬───────┘
         └───────────┴─────┬───────┴──────────────┘
                           ▼
                  ┌─────────────────┐
                  │ Entity          │
                  │ resolution      │──► Neo4j graph
                  └────────┬────────┘
                           ▼
                  ┌─────────────────┐
                  │ Confidence      │  LLR fusion · Admiralty discount ·
                  │ engine          │  evidence chain
                  └────────┬────────┘
                           ▼
              Rebrand detector · Alerts · Analyst review
                           ▼
                  FastAPI ──► React dashboard ──► CSV/JSON/PDF
```

---

## 5. Data flow, step by step

1. **Schedule.** Celery beat triggers each enabled source per its interval. Replay publishes on the original timeline.
2. **Discover.** The adapter lists candidate items (metadata only: URL, type, size, timestamp).
3. **Policy gate.** Checks: source enabled and `approved`/`authorized`; domain allowlist/denylist; content-type allowlist (text/HTML/JSON only); size cap; retention and PII policy attached; mode tag recorded. Decision saved in `policy_decisions`.
4. **Safety gate (pre-fetch).** Decides from metadata and content-type. Prohibited categories are never downloaded. Images, video and archives are not collected at all in the MVP.
5. **Fetch.** Only permitted items are fetched. Tor traffic (for lab onions) goes through the Tor container only.
6. **Safety gate (post-fetch).** A text-only check runs; on a block the payload is discarded and only the decision row remains.
7. **Redaction.** Aadhaar, PAN, phone numbers and victim emails are masked before storage.
8. **Provenance.** SHA-256 of the payload → `evidence_id` → added to the open Merkle batch (root stored; optional anchor later).
9. **Store.** Payload in MinIO; event metadata in PostgreSQL; event published to the analysis stream.
10. **Extract.** Regex and spaCy pull handles, PGP fingerprints, wallets, emails, domains, onions, contact IDs, timestamps.
11. **Analyse.** Infra matcher, wallet clusterer, stylometry, behaviour features run as workers.
12. **Resolve.** Entity resolution merges identifiers into actors and writes nodes/edges into Neo4j with `first_seen`, `last_seen`, `source_id`, `evidence_id`.
13. **Score.** The confidence engine turns evidence into a graded link with an evidence chain.
14. **Detect.** The rebrand detector looks for dormant actors and newly appearing ones with strong shared evidence.
15. **Alert and review.** Alerts appear for the analyst, who confirms or rejects; every action is audit-logged.
16. **Query and export.** Timeline-filtered dashboard; CSV/JSON/PDF exports carry provenance IDs and a report hash.

---

## 6. Core logic

### 6.1 Entity resolution
- **Strong identifiers** (PGP fingerprint, contact ID, SSH key, wallet cluster) create merge candidates.
- **Weak identifiers** (handle similarity, avatar, style, timing) never merge alone; they contribute evidence only.
- Merges are represented as `LINKED_TO` edges with scores, not destructive rewrites, so an analyst can reject a link and the graph reverts cleanly.

### 6.2 Confidence engine (explainable)
Evidence is combined with likelihood ratios in log space:

```
adj_llr(e)     = ln(LR_e) × reliability_factor × credibility_factor
family_llr(f)  = max(adj_llr) + 0.5 × sum(others)      (damps correlated evidence)
posterior_odds = prior_odds × exp(Σ family_llr)
score          = round(100 × posterior_odds / (1 + posterior_odds))
```

Example starting LRs: PGP fingerprint match 1000, SSH host key 1000, contact ID 500, cert SAN leak 300, same wallet cluster 200, favicon match 30, exact handle 30, similar handle 5, banner only 3, timing overlap 2–3; stylometry LR comes from calibration bins. Values are configurable and recalibrated on validation data.

**Admiralty grading** discounts evidence by source and item quality:
- *Source reliability:* A completely reliable, B usually, C fairly, D not usually, E unreliable, F cannot be judged.
- *Information credibility:* 1 confirmed, 2 probably true, 3 possibly true, 4 doubtful, 5 improbable, 6 cannot be judged.

The system reports, for example: "Source X has reliability B; this item is assessed credibility 2."

**Bands:** VERY_HIGH ≥ 90, HIGH ≥ 75, MODERATE ≥ 50, LOW ≥ 25, WEAK below.

**UI display for every link:**

```
ACTOR LINK  ShadowX ⇄ DarkWolf        Correlation: 94/100  (VERY HIGH)
PGP fingerprint        ██████████████████  Very strong   A1
Wallet relationship    ██████████████      Strong        B2
Handle similarity      ██████████          Moderate      C3
Stylometric similarity ████████            Moderate      model v3
Temporal overlap       ████                Weak

Why was this link created?
1. Same PGP fingerprint
2. Same wallet cluster
3. Similar writing profile
4. Overlapping activity window
Analyst verification: REQUIRED
```

### 6.3 Infrastructure attribution
Hidden services hide the server IP by design, but operators leak through mistakes. Detectors look for:

| Signal | Why it matters |
|---|---|
| Exposed `/server-status` or `/server-info` | Reveals software, config, sometimes hostnames |
| TLS certificate with clearnet CN/SAN | Directly names a clearnet domain; searchable in CT logs |
| Default banners and versions | Distinguishes and matches server builds |
| Favicon hash | Same favicon on a clearnet server is a strong pivot |
| HTTP header order and error pages | Fingerprints the exact stack/config |
| SSH host key | Identical key on onion and clearnet server = same machine |
| Descriptor/uptime/clock-skew correlation (stretch) | Links availability patterns to clearnet hosts |

The matcher queries a clearnet index (Shodan/Censys/CT for real use; a mock index for the lab) by each fingerprint, records `SHARES_FINGERPRINT` edges, and scores them with the same confidence engine (infra family).

**Controlled lab (safe, repeatable proof of the PS's first capability):**

```
            YOUR LAB (isolated network)
                  │
        ┌─────────┼──────────┐
        ↓         ↓          ↓
     Onion A    Onion B    Onion C
    vulnerable   mixed     hardened
        │         │          │
     twin-a    twin-b       (none)
   (clearnet) (clearnet)
```

Expected result: A → twin-a (high), B → twin-b (moderate, favicon only), C → no link. This shows detection, correct scoring and no false positive.

### 6.4 Wallet analysis
- Extract BTC, ETH, TRON and XMR patterns. Monero is identified but not traced.
- **Common-input-ownership** heuristic clusters Bitcoin addresses spent together.
- Cluster labels from approved sources (OFAC, Chainabuse, GraphSense labels) flag known-bad clusters and **exchange exit points**, the most realistic route to real-world identification because regulated exchanges can receive legal requests.
- Stretch: peel-chain detection, cross-chain tracing, mixer flags.

### 6.5 Stylometry (measured, not assumed)
Five candidates are compared on a controlled rebrand dataset plus a public authorship corpus:

```
Character n-grams ───┐
Word n-grams  ───────┤
Function-word/       ├──► similarity ──► calibration ──► LR bins
punctuation features ┤
SBERT embeddings ────┤
SBERT fine-tuned ────┘
```

Metrics: ROC-AUC, EER, accuracy at threshold, calibration, and **false-link rate on decoy personas** (same topic, different author). The model is chosen by validation performance, and its similarity is mapped to likelihood ratios with isotonic regression. The presentation line: "We evaluated multiple approaches and selected the model based on validation performance."

### 6.6 Behavioural profiling
Hour-of-day and weekday histograms estimate an actor's circadian rhythm and likely timezone. Cadence features (posting gaps, bursts) and category/price mix support persona linking. Timing is weak evidence on its own; it corroborates.

### 6.7 Rebrand / persona-migration detector (demo centerpiece)

```
ACTOR A                                   ACTOR B
 Handle ShadowX                            Handle DarkWolf
 PGP    KEY-A     ── dormant ≥14d ──►      PGP    KEY-A
 Wallet W-A       ── B appears ≤45d ─►     Wallet W-A
 Writing style A                           Writing style ≈ A
```

Rule: A dormant, B first seen shortly after and not co-active, pairwise evidence scored ≥ threshold → alert:

```
🚨 POSSIBLE PERSONA MIGRATION
Previous identity: ShadowX     New identity: DarkWolf
✓ Same PGP  ✓ Same wallet cluster  ✓ Strong stylometric similarity  ✓ Similar activity
Correlation: HIGH     Analyst verification: REQUIRED
```

This one story demonstrates nearly every capability in the PS.

---

## 7. Data sources

### 7.1 Source registry (the control point)
Every source has a registry record before any collection:

```
Source
├── source_id
├── source_type            (synthetic | replay | osint_feed | clearnet_intel | blockchain | discovery | lab | authorized)
├── collection_method
├── authorization_status   (approved | authorized | disabled)
├── authorization_ref      (required for `authorized`)
├── permitted_use
├── retention_policy
├── PII_policy
└── reliability_grade      (A–F)
```

### 7.2 Approved sources for the prototype

| Category | Sources | Use |
|---|---|---|
| Synthetic | `datagen` actors, markets, posts, wallets, keys | Controlled scenarios with ground truth |
| Replay | Licence-permitted research datasets (e.g. Gwern DNM archives, DUTA-10K, CIRCL AIL sample data; PAN/Blog Authorship for stylometry) | Training and evaluation |
| Threat intel feeds | ransomware tracker APIs, abuse.ch (URLhaus, ThreatFox, Feodo, SSLBL), AlienVault OTX, MISP OSINT feeds | Live indicator and actor-infrastructure context |
| Clearnet infra | crt.sh/CertStream, Shodan, Censys, FOFA, ZoomEye, urlscan.io, VirusTotal, passive DNS, Wayback | Fingerprint matching (lab uses a mock index) |
| Blockchain | mempool.space, Blockstream Esplora, Etherscan, TronGrid/Tronscan, OFAC SDN, Chainabuse, GraphSense/WalletExplorer labels | Wallet data and labels |
| Identity | keys.openpgp.org | PGP web of trust |
| Discovery | Tor Metrics, Ahmia | **Metadata/discovery only.** Ahmia filters abusive content and is not a bulk dataset. |
| Lab | your isolated onion services | Infra detection demo |

### 7.3 Discovery is not collection
```
Discovery → Policy check → Allowlist → Metadata / permitted collection → Analysis
```
Never `Ahmia → everything → crawl everything`.

### 7.4 Research datasets with access agreements
Some real cybercrime datasets (for example those from the Cambridge Cybercrime Centre) are available to academics under a formal legal agreement. Pursue this through your institution if you want real forum data for research; it stays in the Replay mode.

### 7.5 Operational sources (production only)
Marketplaces, forums and other operational dark-web sources belong to **Authorized adapters** run by an agency with legal authority and oversight. They are out of scope for this build. The design supports them by adapter interface, with the same policy and safety gates, so the analytics need no change.

---

## 8. Stack and rationale

| Layer | Choice | Why this over alternatives |
|---|---|---|
| Backend | Python 3.12 + FastAPI | The ML/NLP ecosystem is Python; FastAPI is async and typed with free API docs. Node/Express would split the stack from the analytics. |
| Relational | PostgreSQL 16 | Reliable, JSONB for flexible evidence, built-in full-text search for the MVP. MongoDB lacks the relational integrity needed for audit and provenance. |
| Graph | Neo4j 5 | Cypher and graph algorithms suit multi-hop entity resolution; the same query in SQL becomes unwieldy. ArangoDB/JanusGraph add complexity for no MVP gain. |
| Event bus | Redpanda (Kafka API) | Durable log with offsets makes Replay mode first-class: rewind to any point, run multiple independent consumers, retain history on disk. One container, no Zookeeper. Kafka API is the industry-standard story for production. An `EventBus` interface allows a Redis Streams fallback for lightweight dev. |
| Worker queue / cache | Redis 7 + Celery 5 | Celery broker and general cache. Already in the stack, low overhead. |
| Object store | MinIO | S3-compatible and on-prem friendly, which matters for government deployment. |
| Search | Postgres FTS (MVP) → OpenSearch (stretch) | Avoids running a heavy service until needed. |
| Extraction | Regex + spaCy | Deterministic for identifiers, NER for names/orgs. |
| Stylometry | scikit-learn baselines + sentence-transformers/PyTorch | Baselines give an honest comparison; transformers add power for rebrands. |
| Confidence | Log-likelihood-ratio fusion | Every weight is inspectable and defensible; a neural scorer cannot show why. |
| Provenance | SHA-256 + Merkle batches; anchor via OpenTimestamps/testnet (stretch) | Tamper-evident provenance without putting evidence on-chain. |
| Tor access | Dockerised Tor SOCKS5 + `httpx[socks]` | Isolated, reproducible; requests never leave through the host network. |
| Frontend | React 18 + Vite + TypeScript + Tailwind | Fast iteration and strong ecosystem. |
| Graph UI | Cytoscape.js | Built for large network graphs with layouts and styling; D3 needs far more custom work. |
| Charts | Recharts | Simple React-native charts for timelines and bars. |
| Reports | Jinja2 + WeasyPrint | Templated, reproducible PDFs. |
| Deploy | Docker Compose | One-command demo; Kubernetes is unnecessary for the prototype. |
| Local LLM (stretch) | Ollama | Data never leaves the machine. |

---

## 9. Compliance, ethics and security

**Principles**
- Attribution assistance, not automated identification; humans decide.
- Collect the minimum: text/JSON only, no images/video/archives in the MVP.
- Policy gate and safety gate run **before** collection and storage. The architecture never downloads first and filters later.
- Blocked items keep only a decision record.

**Controls**
- Source registry with authorization status, permitted use, retention, PII policy.
- PII redaction at ingestion; victim data is never surfaced.
- All Tor traffic in an isolated network segment; use an isolated VM for lab work, not a daily-use machine.
- No interaction with vendors: no purchases, logins, messaging or posting.
- Role-based access (viewer, analyst, admin); audit log for every actor view, review decision, export and source toggle.
- Retention limits enforced per source; deletion jobs.
- Secrets in environment/secret store, never in code.
- Exports carry provenance IDs and a report hash.

**What to state in the deck**
1. The tool does not break Tor.
2. Prototype data is synthetic, replayed or approved feeds.
3. Operational collection is an authorized-adapter deployment inside an agency's legal framework.
4. Every score is explainable and requires analyst confirmation.

**Legal note:** Indian law (IT Act, UAPA and others) and the laws of other countries impose serious liability for accessing certain content. Confirm specifics with your institution or a legal advisor before touching any non-approved source.

---

## 10. Evaluation plan

| Area | Metric | Target for demo |
|---|---|---|
| Entity extraction | precision/recall per entity type on labelled fixtures | ≥ 95% on synthetic fixtures |
| Entity resolution | pairwise precision/recall vs `truth.json` | High precision first (avoid false merges) |
| Stylometry | AUC, EER, decoy false-link rate | Report all five models; pick by validation |
| Infra lab | A high, B moderate, C none | 3/3 correct |
| Rebrand detector | detection rate on rebrand pairs; false alerts on decoys | Detect all easy, most hard pairs; zero alerts on decoys |
| Latency | observation → graph update at 100× replay | seconds |
| Provenance | recomputed Merkle root matches stored root | 100% |

Report honest limitations: synthetic data flatters models; real-world performance would differ; independence assumptions in LLR fusion are approximate (mitigated by family damping); adversarial stylometry (paraphrasing, LLM rewriting) can defeat linguistic evidence.

---

## 11. Limitations and roadmap

**Limitations:** results on synthetic data are optimistic; wallet privacy coins are untraceable; infra leaks depend on operator mistakes; stylometry needs enough text; source quality varies.

**Roadmap:** blockchain anchoring → STIX 2.1/MISP export → peel chains and cross-chain tracing → OpenSearch → adversarial-stylometry detection → India-specific language support (Hindi/Hinglish) → local-LLM analyst copilot (NL→Cypher, read-only) → authorized adapters deployed by an agency under legal authority.

---

## 12. Suggested deck outline (12 slides)

1. Title and one-line positioning
2. The problem: attribution on Tor
3. What NETRA does (and does not do)
4. System overview (layered diagram)
5. One pipeline, three modes (Live / Replay / Authorized)
6. Pillar 1: infrastructure attribution and the lab
7. Pillar 2: actor graph and entity resolution
8. Pillar 3: persona correlation and the rebrand detector
9. Explainable confidence + Admiralty source grading
10. Compliance-by-design and provenance
11. Demo storyboard / results and evaluation
12. Real-world path, roadmap and impact

---

## 13. Glossary

- **Attribution:** linking observed activity to an actor or entity with graded confidence.
- **Entity resolution:** deciding which identifiers belong to the same actor.
- **LLR / likelihood ratio:** how much more likely the evidence is if two personas are the same versus different.
- **Admiralty code:** A–F source reliability and 1–6 information credibility grading used in intelligence work.
- **Merkle batch:** a set of evidence hashes combined into one root hash for tamper-evident provenance.
- **Common-input-ownership:** heuristic that addresses spent together in a Bitcoin transaction belong to one owner.
- **Peel chain:** a pattern of repeatedly splitting off small amounts to new addresses to obscure flows.
- **Persona migration / rebrand:** an actor abandons one identity and reappears under another.
