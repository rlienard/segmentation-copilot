"""WebEx implementation of `core.services.notifier.ProposalSink`.

Posts an adaptive card to the operators' room on proposal creation, and
a follow-up markdown line on every decision (approved / applied /
rejected / expired / failed). Imported lazily so a process with no WebEx
credentials never has to construct the client.
"""

from __future__ import annotations

from segmentation_copilot.config import Settings
from segmentation_copilot.core.models.domain import ProposalRecord

from .cards import decision_summary, proposal_card
from .client import WebExClient


class WebExSink:
    name = "webex"

    def __init__(self, *, client: WebExClient, room_id: str) -> None:
        self._client = client
        self._room_id = room_id

    @classmethod
    def from_settings(cls, settings: Settings) -> WebExSink:
        if not (settings.webex.bot_access_token and settings.webex.operators_room_id):
            raise RuntimeError("WebEx is not fully configured")
        return cls(
            client=WebExClient.from_settings(settings),
            room_id=settings.webex.operators_room_id,
        )

    async def proposal_created(self, proposal: ProposalRecord) -> None:
        card = proposal_card(proposal)
        await self._client.post_message(
            room_id=self._room_id,
            text=f"New rule proposal pending: `{proposal.id[:8]}`",
            attachments=[card],
        )

    async def proposal_decided(self, proposal: ProposalRecord) -> None:
        await self._client.post_message(
            room_id=self._room_id,
            text=decision_summary(proposal),
        )
