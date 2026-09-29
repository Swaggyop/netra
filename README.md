# NETRA - Dark Web Intelligence & Threat Disruption Platform

> Networked Entity Tracking & Reconnaissance Architecture

NETRA is an automated dark web threat intelligence platform that monitors ransomware groups, Tor network infrastructure, abuse databases, certificate transparency logs, and blockchain transactions -- delivering real-time actionable intelligence to law enforcement.

## Features

- **22 Automated Crawlers** - Ransomware trackers, Tor relays, abuse databases, OSINT feeds
- **Real-time Dashboard** - Live event feed, source health monitoring, severity-scored alerts
- **Actor Registry** - Track threat actors with profiles, aliases, and activity timelines
- **Graph Explorer** - Visual relationship mapping between actors, wallets, and infrastructure
- **Pipeline Control** - On-demand collection triggers with task monitoring
- **Intel Export** - One-click JSON/CSV/PDF exports for evidence and reporting
- **OWASP-Compliant** - JWT auth, bcrypt, rate limiting, CORS, CSRF protection

## Tech Stack

| Layer | Technologies |
|-------|-------------|
| Frontend | Next.js 16, React, TypeScript, D3.js, WebSocket |
| Backend | Python, FastAPI, Celery, SQLAlchemy |
| Data | PostgreSQL, Redis, Neo4j |
| Infra | Docker Compose, Tor SOCKS Proxy, MinIO |

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+
- Redis
- PostgreSQL

### Setup

```bash
# Clone and configure
git clone <repo-url> && cd DarkHub
copy .env.example .env    # Edit with your DB credentials

# Install dependencies
pip install -e .
cd frontend && npm install && cd ..

# Setup database
psql -U postgres -c "CREATE DATABASE netra;"
alembic upgrade head
```

### Run (3 terminals)

```bash
# Terminal 1: Backend API
uvicorn backend.app.main:app --port 8000

# Terminal 2: Celery Worker
celery -A backend.app.workers.celery_app.celery_app worker -l info -P solo

# Terminal 3: Frontend
cd frontend && npm run dev
```

### Access
- Dashboard: http://localhost:3000
- Login: `admin` / `admin_changeme`
- API Docs: http://localhost:8000/docs

## Data Sources

**9 sources work without API keys:** ransomwatch, ransomlook, feodo tracker, onionoo, CISA KEV, crt.sh, mempool, certstream, sigma rules

**9 sources need free API keys:** See `.env.example` for registration URLs

## Project Structure

```
DarkHub/
  backend/
    app/
      adapters/      # 22 data source adapters
      api/           # FastAPI route handlers
      core/          # Pipeline, events, storage
      models/        # SQLAlchemy ORM models
      workers/       # Celery task definitions
  frontend/
    src/
      app/           # Next.js pages (dashboard, actors, alerts, pipeline, etc.)
      components/    # Reusable UI components
      lib/           # API client, WebSocket, utilities
  docker-compose.yml # Full stack deployment
```

## License

Built for Smart India Hackathon (SIH) 2024.
