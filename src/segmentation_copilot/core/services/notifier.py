"""Notifier — single fan-out point for proposal lifecycle events.

The API and the worker (Phase 4) both invoke `Notifier.proposal_created`
when they mint a proposal. Today the only sink is WebEx, but the
`Sink` protocol lets Phase 6 add Teams / Slack / email without changing
the call sites.

Sinks are loaded lazily so a service that doesn't have WebEx credentials
(e.g. a test process) doesn't have to install the WebEx client at all.
"""

from __future__ import annotations

from typing import Protocol

from ...config import Settings, get_settings
from ..models.domain import ProposalRecord


class ProposalSink(Protocol):
    name: str

    async def proposal_created(self, proposal: ProposalRecord) -> None: ...

    async def proposal_decided(self, proposal: ProposalRecord) -> None: ...


class Notifier:
    """Fan out lifecycle events to every configured sink.

    Failures in one sink do not block others; they are swallowed and
    logged (Phase 6 wires structured logging + tracing). The notifier
    must never propagate an exception — the proposal write has already
    happened, the notification is best-effort.
    """

    def __init__(self, sinks: list[ProposalSink] | None = None) -> None:
        self._sinks: list[ProposalSink] = sinks if sinks is not None else _build_default_sinks()

    async def proposal_created(self, proposal: ProposalRecord) -> None:
        for sink in self._sinks:
            try:
                await sink.proposal_created(proposal)
            except Exception:
                # Phase 6: structured log + metric increment.
                pass

    async def proposal_decided(self, proposal: ProposalRecord) -> None:
        for sink in self._sinks:
            try:
                await sink.proposal_decided(proposal)
            except Exception:
                pass


def _build_default_sinks(settings: Settings | None = None) -> list[ProposalSink]:
    settings = settings or get_settings()
    sinks: list[ProposalSink] = []
    if settings.webex.bot_access_token and settings.webex.operators_room_id:
        # Lazy import — services that don't ship the webex extra still work.
        from services.webex_bot.notifier import WebExSink  # noqa: PLC0415

        sinks.append(WebExSink.from_settings(settings))
    return sinks


_default_notifier: Notifier | None = None


def get_notifier() -> Notifier:
    """Process-wide notifier — built once from settings on first call."""
    global _default_notifier
    if _default_notifier is None:
        _default_notifier = Notifier()
    return _default_notifier


def reset_notifier() -> None:
    """For tests: drop the cached notifier so a fresh one is built."""
    global _default_notifier
    _default_notifier = None
