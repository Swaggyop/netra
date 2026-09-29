.PHONY: up down restart logs seed test lint migrate demo lab-up lab-down replay clean

# ── Lifecycle ────────────────────────────────────────────────

up:
	docker compose up -d --build
	@echo "NETRA stack is up. API: http://localhost:8000/docs"

down:
	docker compose down

restart:
	docker compose restart api worker beat

logs:
	docker compose logs -f api worker beat

# ── Database ─────────────────────────────────────────────────

migrate:
	docker compose exec api alembic upgrade head

seed:
	docker compose exec api python -m backend.app.core.seed

# ── Lab ──────────────────────────────────────────────────────

lab-up:
	docker compose --profile lab up -d --build

lab-down:
	docker compose --profile lab down

lab-test:
	docker compose exec api pytest backend/tests/lab/ -v

# ── Data generation & replay ─────────────────────────────────

generate:
	docker compose exec api python -m datagen.generate --seed 42

replay:
	docker compose exec api python -m backend.app.adapters.replay --speed 100

# ── Demo ─────────────────────────────────────────────────────

demo: up migrate seed generate replay
	@echo "Demo scenario running."

# ── Quality ──────────────────────────────────────────────────

test:
	docker compose exec api pytest --cov=backend/app -v

lint:
	ruff check backend/ datagen/ --fix
	mypy backend/app/

format:
	ruff format backend/ datagen/

# ── Security ─────────────────────────────────────────────────

security-scan:
	pip-audit --strict
	ruff check backend/ --select S

# ── Cleanup ──────────────────────────────────────────────────

clean:
	docker compose down -v --remove-orphans
	find . -type d -name __pycache__ -exec rm -rf {} +
