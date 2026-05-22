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

### Run the scheduler + worker (proactive autonomy)

```bash
# Required for production; for dev, set SCOPILOT_REDIS__URL=memory:// to
# run everything single-process against the in-memory bus.
export SCOPILOT_REDIS__URL=redis://localhost:6379/0

# One process drives the cron + Redis leader election.
python -m services.worker.main --role scheduler

# One or more processes consume events.flow.unknown.
python -m services.worker.main --role worker
```

When the scheduler detects a flow not covered by the latest approved
matrix it publishes `events.flow.unknown`; the worker picks it up,
classifies via Claude, and creates a rule proposal that lands in WebEx
(or any other notifier sink). Operators approve/reject via the existing
Phase-3 flow.

### Run the threat daemon (reactive autonomy, optional)

Tails the syslog stream in real time and on a malicious destination IP
publishes `events.flow.unknown` with `trigger="threat"` — the same
worker pipeline classifies the flow and posts a proposal. Requires at
least one threat-intel provider configured.

```bash
export SCOPILOT_THREAT__ABUSEIPDB_API_KEY=<key>
# optional: SCOPILOT_THREAT__OTX_API_KEY, SCOPILOT_THREAT__VIRUSTOTAL_API_KEY

python -m services.threat_daemon.main \
    --host syslog.example.com \
    --username collector \
    --key-filename /run/secrets/ssh_key \
    --log-path /var/log/network/syslog
```

### Run the WebEx bot (optional)

```bash
export SCOPILOT_WEBEX__BOT_ACCESS_TOKEN=<bot token>
export SCOPILOT_WEBEX__WEBHOOK_SECRET=<hmac secret>
export SCOPILOT_WEBEX__OPERATORS_ROOM_ID=<room id>
uvicorn services.webex_bot.main:app --port 8001
```

Point your WebEx bot's webhook at `https://<bot host>/webhooks/webex`.
With these env vars set, every proposal created via the API automatically
posts an adaptive card to the operators' room; clicking Approve / Reject
drives the proposal through the state machine and, on approval, updates
the live matrix.

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

**Phase 6 (this PR)** adds:

- `services/mcp_server/` — MCP server exposing 14 tools (runs, SGT,
  proposals, threat intel). Two transports on one shared registry:
  stdio (`python -m services.mcp_server.stdio`) for Claude Code /
  Desktop, and streamable HTTP for LibreChat / remote clients.
  `set_sgt_name` is gated by `--allow-dictionary-edit`.
- `deploy/Dockerfile` — multi-stage; one image serves every role
  (api / worker / scheduler / mcp / threat-daemon / webex-bot / ui).
  Non-root, read-only-rootfs friendly.
- `deploy/docker-compose.yml` — full stack (postgres + redis + every
  service) behind Compose profiles for the optional ones (webex,
  threat, ui).
- `deploy/k8s/base/` — kustomize base with Deployments + Services +
  HPAs + PodDisruptionBudget for the scheduler + Ingress + an example
  NetworkPolicy stack. Migration runs as a pre-install Job /
  argocd-sync-wave -10.
- `core/observability/` — JSON structured logs + Prometheus metrics
  (counters for flow_unknown / classifications / proposals /
  threat_lookups). API exposes `/metrics`.
- `.github/workflows/ci.yml` — ruff lint, Alembic migration on a real
  Postgres service container, `pytest` against the full matrix,
  Docker build + push to GHCR on `main`, Trivy scan.

**Phase 5** added:

- `core/threat/` — pluggable threat-intelligence layer with a
  `ThreatIntelClient` Protocol and four implementations:
  - **AbuseIPDB** (primary; free tier 1000/day)
  - **AlienVault OTX** (pulse-count scoring)
  - **VirusTotal** (engine-stats normalisation)
  - **Talos** (opt-in best-effort; documented as brittle, never the
    only signal)
- `ThreatAggregator` runs them in parallel with a per-call timeout and
  applies the decision policy (score ≥ threshold OR two-provider
  category consensus). Per-provider failures don't poison the decision.
- Redis caching (6h clean / 24h malicious / 1h 404) backed by a
  `threat_lookups` audit table.
- `core/sources/streaming.py` — `StreamingLogSource` Protocol +
  `InMemoryStreamingSource` for tests/dev.
- `core/sources/streaming_ssh.py` — production `asyncssh`-based tail
  with `tail -F`, exponential-backoff reconnect, heartbeat markers, and
  resilience against log rotation.
- `services/threat_daemon/` — ties everything together: tail → parse →
  IP lookup → on malicious verdict, publish `events.flow.unknown` with
  `trigger="threat"` and the full verdict trail attached. Reuses the
  Phase-4 worker pipeline downstream — same classification, same
  proposal flow, same WebEx approval.

**Phase 4** added:

- `core/events/` — `EventBus` Protocol with two implementations:
  Redis Streams for production (consumer groups, at-least-once, idempotency
  dedup via `SET NX`) and an in-memory bus that's contract-equivalent
  for tests / single-process dev. Picked automatically from
  `SCOPILOT_REDIS__URL`.
- `services/worker/` — proactive autonomy service:
  - **Scheduler** (`--role scheduler`) — Redis-leader-elected; only the
    elected replica fires the cron, so multiple instances are safe.
    At every tick, loads new `flow_events` since the last cursor,
    diffs against the latest approved `matrix_version`, and publishes
    `events.flow.unknown` for every uncovered tuple.
  - **Worker** (`--role worker`) — consumes `events.flow.unknown`,
    classifies via Claude (honouring the 7-day classification cache so
    re-seen flows don't pay LLM cost), and turns the verdict into a
    rule proposal (deny for harmful / business_irrelevant; permit
    otherwise). The existing storm-collapse logic keeps a misconfigured
    syslog source from drowning operators.
- Per-tenant scan cursor in Redis (28-day TTL); on Redis loss the worst
  outcome is re-classifying the last few days — absorbed by the cache.
- Bus idempotency keys make scan ticks safe to retry.

**Phase 3** added:

- `core/services/proposal.py` — full proposal state machine
  (`pending → notified → {approved | rejected | expired}`,
  `approved → applied | failed`) with **idempotency** (same shape returns
  the existing row) and **storm collapse** (multiple proposals for the
  same `(src_sgt, dst_sgt)` merge into one).
- On approval, the service creates an immutable `matrix_version` whose
  `parent_id` chains back to the previous baseline — rollback is a pointer
  flip.
- `core/services/notifier.py` — pluggable sink fan-out so future channels
  (Slack, Teams, email) drop in without touching call sites.
- `services/webex_bot/` — FastAPI service with HMAC-SHA1 webhook
  verification, an adaptive-card builder, and a WebEx HTTP client. Drives
  the approve/reject loop end-to-end and handles operator races gracefully.
- API `POST /v1/proposals` now fans out to the notifier via
  `BackgroundTasks`; `POST /v1/proposals/{id}/decision` goes through the
  state machine.

## Deploy

```bash
# Local: full stack on docker-compose
docker compose -f deploy/docker-compose.yml up -d
docker compose -f deploy/docker-compose.yml --profile ui --profile webex up -d

# Kubernetes
kubectl apply -k deploy/k8s/base
```

Both targets need at least `SCOPILOT_ANTHROPIC__API_KEY`; threat-intel
and WebEx-bot keys are optional. In production, source secrets via
External Secrets Operator rather than the example `Secret`.

## Apply migrations

```bash
alembic upgrade head
```

Override the database URL via `SCOPILOT_DB__URL` (see `.env.example`).
