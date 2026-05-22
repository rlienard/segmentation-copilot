"""Adaptive Card builders for the WebEx bot.

The Approve/Reject buttons embed the proposal_id in their `data` payload
so the webhook handler can dispatch back to `ProposalService.decide()`
without a separate state store. The card also surfaces the rationale and
the proposed ACEs so an operator can decide from the message alone —
they shouldn't need to open the UI for routine approvals.
"""

from __future__ import annotations

from typing import Any

from segmentation_copilot.core.models.domain import ProposalRecord


def proposal_card(proposal: ProposalRecord) -> dict[str, Any]:
    """Build the adaptive card body for a new proposal."""
    ace_facts = [
        {
            "title": f"{ace.protocol}/{ace.dst_port}",
            "value": f"{ace.action} (src {ace.src_port})",
        }
        for ace in proposal.proposed_aces
    ]

    return {
        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.2",
            "body": [
                {
                    "type": "TextBlock",
                    "size": "Medium",
                    "weight": "Bolder",
                    "text": (
                        f"Rule proposal: SGT {proposal.src_sgt} → "
                        f"SGT {proposal.dst_sgt}"
                    ),
                    "wrap": True,
                },
                {
                    "type": "TextBlock",
                    "isSubtle": True,
                    "wrap": True,
                    "text": f"Trigger: **{proposal.trigger.value}** · "
                            f"Status: **{proposal.status.value}**",
                },
                {"type": "TextBlock", "text": proposal.rationale, "wrap": True},
                {"type": "FactSet", "facts": ace_facts},
            ],
            "actions": [
                {
                    "type": "Action.Submit",
                    "title": "Approve",
                    "data": {"action": "approve", "proposal_id": proposal.id},
                    "style": "positive",
                },
                {
                    "type": "Action.Submit",
                    "title": "Reject",
                    "data": {"action": "reject", "proposal_id": proposal.id},
                    "style": "destructive",
                },
            ],
        },
    }


def decision_summary(proposal: ProposalRecord) -> str:
    """Markdown one-liner posted back after a decision."""
    verb = {
        "approved": "approved",
        "applied": "approved & applied",
        "rejected": "rejected",
        "failed": "approval failed to apply",
        "expired": "expired",
    }.get(proposal.status.value, proposal.status.value)
    actor = proposal.decided_by or "an operator"
    return (
        f"Proposal `{proposal.id[:8]}` "
        f"(SGT {proposal.src_sgt}→{proposal.dst_sgt}) "
        f"{verb} by {actor}."
    )
