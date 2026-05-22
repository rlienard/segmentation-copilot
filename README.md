# segmentation-copilot

An AI Security Analyst for **Cisco TrustSec** networks. It watches SG-ACL hit
logs, proposes the explicit `permit` / `deny` contracts that should exist for
legitimate traffic, and lets a real human review every change before it
touches the live matrix — a safe path to flipping the matrix default to
`deny-ip`.

The agent runs both **on demand** (operator asks for a one-off analysis) and
**autonomously** (a scheduler scans for unknown flows; a daemon reacts to
threat-flagged destinations in real time). Operators can drive it from the
Streamlit UI, a CLI, any MCP-aware chat client (Claude Code, Claude Desktop,
LibreChat, …), or a WebEx bot — all backed by the same FastAPI service.

---

## Features

- **Interactive analysis.** Upload syslog, pick a time window, get a proposed
  TrustSec contract matrix as markdown / CSV.
- **Proactive autonomy.** A cron-driven scheduler scans the syslog backlog
  on a configurable interval, finds flows not covered by the current
  baseline, and proposes the rules that would let them through.
- **Reactive autonomy.** A real-time syslog tail runs every destination IP
  through a pluggable threat-intel layer (AbuseIPDB / OTX / VirusTotal /
  Talos) and proposes a deny rule the moment a malicious flow is seen.
- **Human-gated approvals.** Every proposed rule lands as a WebEx adaptive
  card (or in the UI / CLI / MCP); nothing changes the live matrix until
  an operator clicks Approve. Approval creates an immutable
  `matrix_version`; rollback is a pointer flip.
- **Multi-client.** Streamlit UI, `scopilot` CLI, MCP server (stdio + HTTP),
  WebEx bot, REST API — all reach the same agent.
- **Production-ready.** Microservices, Docker / Kubernetes deployment,
  Postgres + Redis, JSON logs, Prometheus metrics, NetworkPolicies, CI/CD.

---

## Architecture

```
                  External clients
   ┌──────────┬─────────┬───────────┬──────────┬───────────┐
   │   CLI    │ Claude  │ LibreChat │ Streamlit│  WebEx    │
   │ scopilot │  UI     │           │   UI     │   Bot     │
   └─────┬────┴────┬────┴─────┬─────┴────┬─────┴─────┬─────┘
         │ REST    │ MCP      │ MCP/SSE  │ REST      │ webhooks
         ▼         ▼          ▼          ▼           ▼
    ┌──────────────────┐  ┌──────────────────┐  ┌────────────┐
    │   api/ FastAPI   │  │  mcp-server/     │  │ webex-bot/ │
    │  OIDC-ready auth │  │  stdio + HTTP    │  │ HMAC verify│
    └────────┬─────────┘  └────────┬─────────┘  └─────┬──────┘
             └─────────────┬───────┴──────────────────┘
                           ▼
              ┌────────────────────────┐
              │ core/ (shared library) │
              │  services · repos      │
              │  events · threat intel │
              │  sources (stream + win)│
              └────┬──────────┬────────┘
                   │          │
   ┌───────────────┘          └───────────────┐
   ▼                                          ▼
┌──────────────┐   Redis Streams       ┌────────────────┐
│ worker/      │◄──── events.* ───────►│ threat-daemon/ │
│ scheduler    │      consumer groups  │ asyncssh tail  │
│  + consumer  │                       │  + intel lookup│
└──────┬───────┘                       └────────┬───────┘
       │                                        │
       └────────────────┬───────────────────────┘
                        ▼
               ┌────────────────┐
               │  PostgreSQL    │  (Redis: cache + Streams)
               │  via Alembic   │
               └────────────────┘
```

Everything underneath the clients is a separate, horizontally scalable
microservice; everything in `core/` is the shared library each microservice
imports.

---

## Quick start

### Run everything with Docker Compose

```bash
export SCOPILOT_ANTHROPIC__API_KEY=sk-ant-...
docker compose -f deploy/docker-compose.yml up -d
# api on :8000, mcp-http on :8002, worker + scheduler in the background
```

Optional services live behind Compose profiles:

```bash
docker compose -f deploy/docker-compose.yml --profile ui --profile webex up -d
```

### Local dev without Docker

```bash
pip install -e ".[dev,api,worker,webex,mcp,cli,sources,ui]"
export SCOPILOT_ANTHROPIC__API_KEY=sk-ant-...
export SCOPILOT_REDIS__URL=memory://       # in-memory bus, no Redis needed
export SCOPILOT_API__REQUIRE_AUTH=false    # dev only

# Apply migrations (SQLite by default — set SCOPILOT_DB__URL for Postgres)
alembic upgrade head

# Then start the bits you need:
uvicorn services.api.main:app --reload          # REST + /metrics
python -m services.worker.main --role worker    # consumes events.flow.unknown
python -m services.worker.main --role scheduler # cron tick
streamlit run app.py                            # UI
scopilot --help                                 # CLI
```

---

## Services

Each service is a separate process / container. They all import from the same
`core/` library, so a bug fix in the agent's pipeline lands everywhere at once.

### `api/` — FastAPI REST + `/metrics`

The control plane. Exposes runs, ingest, classify, matrix, SGT dictionary,
proposals, healthz/readyz, and Prometheus `/metrics`. Bearer-token auth via
`SCOPILOT_API__API_KEYS`; the dependency surface is JWKS-ready for a future
OIDC verifier swap. Streamlit, the CLI, and the WebEx bot all talk through
this service.

```bash
uvicorn services.api.main:app --host 0.0.0.0 --port 8000
```

### `worker/` — Scheduler + flow-unknown consumer

Two roles in one binary:

- **`--role scheduler`** runs a cron loop. Redis-leader-elected so multiple
  replicas are safe. At every tick it loads new `flow_events` since the
  per-tenant cursor, diffs them against the latest approved
  `matrix_version`, and publishes `events.flow.unknown` for every
  uncovered tuple.
- **`--role worker`** consumes `events.flow.unknown` in a consumer group,
  classifies the flow via Claude (honouring a 7-day classification cache
  so re-seen flows don't pay LLM cost), and turns the verdict into a rule
  proposal — `deny` for harmful / business_irrelevant, `permit` otherwise.
  Storm-collapse keeps a misconfigured source from drowning operators.

```bash
python -m services.worker.main --role scheduler
python -m services.worker.main --role worker
```

### `threat_daemon/` — Real-time SSH tail + threat intel

Tails `/var/log/network/syslog` over SSH (`asyncssh` with `tail -F`,
exponential-backoff reconnect, heartbeat markers, log-rotation transparent).
For every destination IP it consults the pluggable threat-intel layer; on a
malicious verdict it publishes `events.flow.unknown` with `trigger="threat"`
and the full verdict trail. From there it joins the same worker pipeline as
the scheduler — same classification, same proposal flow, same approval loop.

Providers (mix and match — at least one required):

- **AbuseIPDB** (primary; free 1000/day)
- **AlienVault OTX**
- **VirusTotal** (slow free-tier rate-limit; lookups cached aggressively)
- **Cisco Talos** (opt-in, best-effort, documented as brittle)

```bash
export SCOPILOT_THREAT__ABUSEIPDB_API_KEY=<key>
python -m services.threat_daemon.main \
    --host syslog.example.com \
    --username collector \
    --key-filename /run/secrets/ssh_key \
    --log-path /var/log/network/syslog
```

### `webex_bot/` — Approval loop in Cisco WebEx

Webhook receiver with HMAC-SHA1 verification, adaptive-card builder, and a
thin WebEx HTTP client. Every proposal posts an Approve / Reject card to the
configured operators' room; button clicks drive the proposal state machine
back through `core` (which on approve creates a new `matrix_version`).
Inline `approve <id>` / `reject <id>` / `list pending` commands work too.

```bash
export SCOPILOT_WEBEX__BOT_ACCESS_TOKEN=<bot token>
export SCOPILOT_WEBEX__WEBHOOK_SECRET=<hmac secret>
export SCOPILOT_WEBEX__OPERATORS_ROOM_ID=<room id>
uvicorn services.webex_bot.main:app --port 8001
# Point your WebEx bot webhook at https://<host>/webhooks/webex
```

### `mcp_server/` — MCP server (stdio + HTTP)

Exposes 14 tools (run lifecycle, SGT dictionary, proposals, threat intel) so
any MCP-aware client — Claude Code, Claude Desktop, LibreChat, custom — can
drive the agent. Two transports on one shared registry:

```bash
# stdio: Claude Code / Claude Desktop
python -m services.mcp_server.stdio

# streamable HTTP: LibreChat or any remote MCP client
uvicorn services.mcp_server.http:app --port 8002
```

`set_sgt_name` is gated behind `--allow-dictionary-edit`; the rest of the
tool surface is read or proposal-write.

### `cli/` — `scopilot` Typer CLI

A thin client of the REST API. Useful for scripting and as the reference
for what the API actually exposes.

```bash
export SCOPILOT_API_BASE=http://localhost:8000
export SCOPILOT_API_TOKEN=<bearer>            # only if auth is on
scopilot health
scopilot sgt set 100 Employees
scopilot run start tests/fixtures/sample.log
scopilot proposal list
scopilot proposal approve <id>
```

### `app.py` — Streamlit UI

Pure HTTP client of the API. Configure `SCOPILOT_API_BASE` and optionally a
bearer token, then drive runs / approvals from the browser.

```bash
SCOPILOT_API_BASE=http://localhost:8000 streamlit run app.py
```

---

## Deploy

### Docker Compose (single host)

```bash
docker compose -f deploy/docker-compose.yml up -d
```

Brings up Postgres + Redis + migrate + api + worker + scheduler + mcp-http.
Optional services behind profiles: `ui`, `webex`, `threat`.

### Kubernetes (kustomize)

```bash
kubectl apply -k deploy/k8s/base
```

`deploy/k8s/base/` ships Deployments + Services + HPAs + a leader-friendly
`PodDisruptionBudget` for the scheduler + `cert-manager`-aware Ingress for
`api`, `mcp`, `ui`, and `webex` hosts. Postgres + Redis are single-replica
StatefulSets — for production, point `SCOPILOT_DB__URL` at a managed
instance and remove the StatefulSet. An example `NetworkPolicy` stack
(default-deny + per-service allows) lives in `networkpolicy.yaml`.

Pods run non-root (uid 10001), `readOnlyRootFilesystem`, all capabilities
dropped, `seccomp: RuntimeDefault`. Namespace enforces Pod Security
Admission `restricted`. Replace `secret-example.yaml` with an
`ExternalSecret` backed by Vault / cloud SM in production.

### Migrations

```bash
alembic upgrade head
```

Driven by `SCOPILOT_DB__URL` (async) and `SCOPILOT_DB__SYNC_URL` (sync;
auto-derived if unset). The K8s base runs migrations as a pre-install Job.

---

## Configuration

Every setting is `SCOPILOT_*` and nested settings use `__`:

| Group | Examples |
|-------|----------|
| Core | `SCOPILOT_ENVIRONMENT`, `SCOPILOT_LOG_LEVEL`, `SCOPILOT_LOG_FORMAT`, `SCOPILOT_DEFAULT_TENANT_ID` |
| Database | `SCOPILOT_DB__URL`, `SCOPILOT_DB__SYNC_URL`, `SCOPILOT_DB__ECHO` |
| Redis / event bus | `SCOPILOT_REDIS__URL` (set to `memory://` for single-process dev) |
| Anthropic | `SCOPILOT_ANTHROPIC__API_KEY`, `SCOPILOT_ANTHROPIC__MODEL` |
| API | `SCOPILOT_API__REQUIRE_AUTH`, `SCOPILOT_API__API_KEYS` (JSON list) |
| Scheduler | `SCOPILOT_SCHED__SCAN_INTERVAL_MINUTES`, `SCOPILOT_SCHED__CLASSIFICATION_CACHE_DAYS` |
| Threat intel | `SCOPILOT_THREAT__ABUSEIPDB_API_KEY`, `SCOPILOT_THREAT__OTX_API_KEY`, `SCOPILOT_THREAT__VIRUSTOTAL_API_KEY`, `SCOPILOT_THREAT__TALOS_ENABLED` |
| WebEx | `SCOPILOT_WEBEX__BOT_ACCESS_TOKEN`, `SCOPILOT_WEBEX__WEBHOOK_SECRET`, `SCOPILOT_WEBEX__OPERATORS_ROOM_ID` |

See `.env.example` for the full surface with defaults.

---

## Tests

```bash
pip install -e ".[dev,api,worker,webex,mcp,cli,sources]"
pytest
```

Hermetic — no live Anthropic / WebEx / threat-feed calls. CI also runs
Alembic migrations against a real Postgres service container.

---

## Project layout

```
app.py                              # Streamlit UI (pure HTTP client of api/)
alembic/                            # async SQLAlchemy migrations
deploy/
    Dockerfile                      # multi-stage, one image per role
    docker-compose.yml              # full stack with optional profiles
    k8s/base/                       # kustomize Deployments + Services + HPAs + Ingress
.github/workflows/ci.yml            # ruff + pytest + Postgres + Docker + Trivy
services/
    api/            FastAPI REST + /metrics
    cli/            scopilot Typer client
    worker/         scheduler + flow-unknown consumer (leader-elected)
    threat_daemon/  real-time syslog tail + threat-intel lookup
    webex_bot/      adaptive-card approval loop
    mcp_server/     stdio + HTTP MCP server
src/segmentation_copilot/
    config.py                       # Pydantic Settings (SCOPILOT_* env vars)
    parser.py                       # %RBM-6-SGACLHIT regex parser
    aggregator.py                   # group events into unique flow tuples
    sgt.py                          # SGT id→name dictionary + missing-id registry
    classify.py                     # Claude-driven flow classification
    contracts.py                    # build contracts + render markdown matrix
    sources/
        local.py / ssh.py           # fetch-by-window sources
        streaming.py                # StreamingLogSource Protocol
        streaming_ssh.py            # asyncssh tail with reconnect + heartbeat
    core/
        db.py                       # async SQLAlchemy 2.0 engine + session
        models/                     # ORM (orm.py) + Pydantic domain models
        repositories/               # async repos (runs, events, classifications,
                                    #              contracts, sgt, proposals, matrix)
        services/                   # ingestion / classification / matrix / baseline
                                    # proposal state machine / notifier fan-out
        events/                     # EventBus Protocol + Redis Streams + InMemory
        threat/                     # ThreatIntelClient Protocol + 4 providers + aggregator
        observability/              # JSON logs + Prometheus counters
tests/                              # pytest suite + fixtures (79 tests)
data/                               # SQLite db + uploads (gitignored)
```
