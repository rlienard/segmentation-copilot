"""Thin async WebEx HTTP client.

Only the endpoints the bot actually uses:

  POST   /messages                — post text or an attachment card
  GET    /attachment/actions/{id} — fetch the card-action payload after
                                    a webhook fires (the webhook itself
                                    only carries the action's id, not its
                                    inputs)
  GET    /people/{id}             — resolve the actor email for audit
"""

from __future__ import annotations

from typing import Any

import httpx

from segmentation_copilot.config import Settings

BASE_URL = "https://webexapis.com/v1"


class WebExClient:
    def __init__(self, access_token: str, base_url: str = BASE_URL,
                 client: httpx.AsyncClient | None = None) -> None:
        self.access_token = access_token
        self.base_url = base_url
        self._client = client
        self._owns_client = client is None

    @classmethod
    def from_settings(cls, settings: Settings) -> WebExClient:
        if not settings.webex.bot_access_token:
            raise RuntimeError("SCOPILOT_WEBEX__BOT_ACCESS_TOKEN is not set")
        return cls(access_token=settings.webex.bot_access_token)

    def _client_lazy(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers={"Authorization": f"Bearer {self.access_token}"},
                timeout=30.0,
            )
        return self._client

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def post_message(
        self,
        *,
        room_id: str,
        text: str | None = None,
        attachments: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"roomId": room_id}
        if text is not None:
            payload["markdown"] = text
        if attachments:
            payload["attachments"] = attachments
        resp = await self._client_lazy().post("/messages", json=payload)
        resp.raise_for_status()
        return resp.json()

    async def get_attachment_action(self, action_id: str) -> dict[str, Any]:
        resp = await self._client_lazy().get(f"/attachment/actions/{action_id}")
        resp.raise_for_status()
        return resp.json()

    async def get_message(self, message_id: str) -> dict[str, Any]:
        resp = await self._client_lazy().get(f"/messages/{message_id}")
        resp.raise_for_status()
        return resp.json()

    async def get_person(self, person_id: str) -> dict[str, Any]:
        resp = await self._client_lazy().get(f"/people/{person_id}")
        resp.raise_for_status()
        return resp.json()
