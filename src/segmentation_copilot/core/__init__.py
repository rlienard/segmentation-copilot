"""Shared core library — services, repositories, models, and agent loop.

Every microservice (`api`, `worker`, `mcp-server`, `threat-daemon`,
`webex-bot`, `streamlit-ui`) imports from `core`. The library is
async-first, persistence-backed, and stateless across calls — all state
lives in Postgres (or SQLite for dev), keyed by `run_id` and `tenant_id`.
"""
