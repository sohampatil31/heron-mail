"""The pure parts of the Alerts page: filters, which buttons to offer, and display text.

The buttons offered for an alert come from the same lifecycle rules the API
enforces (analysis.alerts.can_transition), so the page can never offer a move
the server would refuse.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from heron.analysis.alerts import AlertStatus, can_transition
from heron.ui.safe import clean_text

STATUS_FILTERS: dict[str, str | None] = {
    "Open": "open",
    "Acknowledged": "acknowledged",
    "Resolved": "resolved",
    "False positive": "false_positive",
    "All": None,
}

_STATUS_LABELS = {
    "open": "Open",
    "acknowledged": "Acknowledged",
    "resolved": "Resolved",
    "false_positive": "False positive",
}


def status_label(status: str) -> str:
    return _STATUS_LABELS.get(status, clean_text(status, 30))


@dataclass(frozen=True, slots=True)
class Move:
    target: AlertStatus
    label: str
    help: str
    primary: bool = False


_ALL_MOVES = (
    Move(AlertStatus.ACKNOWLEDGED, "Acknowledge", "I've seen this and I'm looking into it."),
    Move(
        AlertStatus.RESOLVED,
        "Mark resolved",
        "This was a real threat and it's been dealt with.",
        primary=True,
    ),
    Move(
        AlertStatus.FALSE_POSITIVE,
        "Mark as false positive",
        "This message is fine; Heron got it wrong.",
    ),
    Move(AlertStatus.OPEN, "Reopen", "Put this back in the open list."),
)


def available_moves(status: str) -> tuple[Move, ...]:
    """The buttons to show for an alert in `status`, in display order."""
    try:
        current = AlertStatus(status)
    except ValueError:
        return ()
    return tuple(move for move in _ALL_MOVES if can_transition(current, move.target))


def option_label(alert: dict[str, Any]) -> str:
    return f"#{alert['id']} · {alert['severity'].upper()} · {clean_text(alert['title'], 90)}"


def timeline_lines(alert: dict[str, Any]) -> list[str]:
    lines = [f"Raised {alert['created_at']} UTC"]
    if alert.get("acknowledged_at"):
        lines.append(f"Acknowledged {alert['acknowledged_at']} UTC")
    if alert.get("closed_at"):
        verb = "Marked as a false positive" if alert["status"] == "false_positive" else "Resolved"
        lines.append(f"{verb} {alert['closed_at']} UTC")
    return lines


def evidence_lines(reason: dict[str, Any]) -> list[str]:
    """Evidence comes from the email itself, so it is cleaned and shown as plain text."""
    return [clean_text(item, 300) for item in reason.get("evidence", [])]


def reason_summary(reason: dict[str, Any]) -> str:
    points = reason.get("points", 0)
    return f"{reason['title']} (+{points})" if points else reason["title"]
