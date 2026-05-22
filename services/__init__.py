"""Segmentation Copilot service entry points.

Each subpackage is a separate microservice that imports from the shared
`segmentation_copilot.core` library:

* `services.api`  — FastAPI REST + (Phase 4) SSE chat
* `services.cli`  — Typer CLI client of the API
* `services.webex_bot`  — Phase 3
* `services.worker`     — Phase 4
* `services.threat_daemon`  — Phase 5
* `services.mcp_server`     — Phase 6
"""
