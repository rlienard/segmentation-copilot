# segmentation-copilot

An AI Security Analyst agent that turns Cisco SD-Access SG-ACL hit logs into a TrustSec contract matrix proposal — designed to help networks switch the matrix default rule to `deny-ip` without breaking legitimate flows.

## What it does

1. Asks for a syslog source (local file or SSH to a syslog collector), an analysis window, and an SGT/DGT id→name dictionary.
2. Pulls and parses `%RBM-6-SGACLHIT` syslog entries from the configured source.
3. Aggregates the raw events into unique flow tuples (`sgt`, `dgt`, `protocol`, `src_port`, `dst_port`).
4. Uses Claude to classify each flow as **business_relevant**, **default**, **business_irrelevant**, or **harmful**.
5. Groups classified flows into one **contract** per (Source SGT, Destination SGT) pair, with one or more ACEs each.
6. Renders the matrix as a markdown table and persists runs to SQLite.

The matrix-wide default rule remains `deny-ip` — the agent emits only the explicit permits (and selective denies for visibility into Business Irrelevant / Harmful flows).

## Install

```bash
pip install -e ".[dev]"
```

## Run the stack

Phase 2 splits the app in two: a FastAPI service holds the agent + DB,
and Streamlit / the CLI talk to it over HTTP.

```bash
# Start the API
export SCOPILOT_ANTHROPIC__API_KEY=sk-ant-...
export SCOPILOT_API__REQUIRE_AUTH=false           # dev only
uvicorn services.api.main:app --reload

# Streamlit UI (in another terminal)
streamlit run app.py
# or use the CLI
scopilot --help
scopilot health
scopilot sgt set 100 Employees
scopilot run start tests/fixtures/sample.log
```

When `SCOPILOT_API__REQUIRE_AUTH=true` (prod default), set
`SCOPILOT_API__API_KEYS=["<token>"]` and pass it via
`Authorization: Bearer <token>` (or `SCOPILOT_API_TOKEN=<token>` for the CLI).

## Run the tests

```bash
pytest
```

## Project layout

```
app.py                          # Streamlit entry point (legacy; refactored to API client in Phase 2)
alembic/                        # async SQLAlchemy migrations
src/segmentation_copilot/
    config.py                   # Pydantic Settings — SCOPILOT_* env vars
    parser.py                   # %RBM-6-SGACLHIT regex parser
    aggregator.py               # Group events into unique flow tuples
    sgt.py                      # SGT dict load + lookup with missing-name registry
    classify.py                 # Claude-based flow categorisation
    contracts.py                # Build contracts + render markdown matrix
    db.py                       # legacy sync SQLite; replaced by core/ in Phase 1
    agent.py                    # Security Analyst system prompt + tool registry
    tools.py                    # legacy AgentState pipeline; replaced by core/services in Phase 1
    core/
        db.py                   # async SQLAlchemy 2.0 engine + session factory
        models/                 # ORM (orm.py) + Pydantic domain models (domain.py)
        repositories/           # async repos: runs, events, classifications, contracts, sgt, proposals, matrix
        services/               # orchestration: ingestion, classification, matrix, baseline
    sources/
        base.py                 # LogSource abstract base
        local.py                # Local file backend
        ssh.py                  # Paramiko-based SSH backend
tests/                          # pytest suite + fixtures
data/                           # SQLite db + uploads (gitignored)
```

## Production-readiness roadmap

The plan in `/root/.claude/plans/i-would-like-to-sparkling-owl.md` decomposes the
project into six phases. **Phase 1 (this PR)** lands the foundation:

- Centralized Pydantic `Settings` (`config.py`) consuming `SCOPILOT_*` env vars.
- Async SQLAlchemy 2.0 + Alembic — supports SQLite (dev) and Postgres (prod).
- ORM and Pydantic domain models with `tenant_id` on every tenant-scoped table.
- Repository layer (`core/repositories/`) with idempotent upserts and the
  optimistic-lock proposal `decide()` SQL.
- Service layer (`core/services/`) wrapping the existing pure-function pipeline
  (`parser`, `aggregator`, `classify`, `contracts`) with persistence and a
  recent-flow classification cache.
- Schema includes `proposals`, `proposal_audit`, `matrix_versions`,
  `threat_lookups`, `audit_events` so Phases 3 and 5 can land additively.

**Phase 2 (this PR)** adds:

- `services/api/` — FastAPI service exposing the pipeline over REST
  (runs, ingest, classify, matrix, sgt, proposals, healthz/readyz).
  Bearer-token auth via `SCOPILOT_API__API_KEYS` (OIDC arrives in Phase 6).
- `services/cli/` — `scopilot` Typer CLI talking to the API.
- `app.py` — Streamlit rewritten as a pure HTTP client. A CI test
  (`tests/test_no_core_in_app.py`) fails if `app.py` ever re-imports
  agent internals.

Subsequent phases (separate PRs):

- **Phase 3** — Proposal state machine + WebEx bot + approval loop.
- **Phase 4** — Scheduler worker + Redis Streams + cron-driven analysis.
- **Phase 5** — Real-time threat daemon + pluggable threat-intel module.
- **Phase 6** — MCP server + K8s manifests + observability + CI/CD.

## Apply migrations

```bash
alembic upgrade head
```

Override the database URL via `SCOPILOT_DB__URL` (see `.env.example`).
