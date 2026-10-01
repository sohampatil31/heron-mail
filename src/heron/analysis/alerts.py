"""Alerts: what a flagged message turns into, what to do about it, and its lifecycle.

Pure logic, no database. build_alert() decides whether an Assessment deserves
an alert and drafts its title, severity and recommended actions. The status
rules decide how an alert may move once someone is working on it. Saving
alerts is a separate step, so all of this can be tested without a database.

Heron only reads mail, so every action here is advice for a person. Nothing
is deleted, moved or blocked on their behalf.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from heron.analysis.scoring import Assessment, Reason, Verdict
from heron.rules.base import Severity

_MAX_SUBJECT = 100
# Control characters and the invisible direction overrides: both can make an
# attacker-chosen subject misleading or break a log line.
_UNSAFE_CHARS = re.compile(r"[\x00-\x1f\x7f\u200e\u200f\u202a-\u202e\u2066-\u2069]")


# ---------------------------------------------------------------- lifecycle


class AlertStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"  # someone has seen it and is looking
    RESOLVED = "resolved"  # dealt with
    FALSE_POSITIVE = "false_positive"  # it was fine after all


_TRANSITIONS: dict[AlertStatus, frozenset[AlertStatus]] = {
    AlertStatus.OPEN: frozenset(
        {AlertStatus.ACKNOWLEDGED, AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE}
    ),
    AlertStatus.ACKNOWLEDGED: frozenset({AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE}),
    # Closing is reversible: a mistaken click shouldn't be permanent.
    AlertStatus.RESOLVED: frozenset({AlertStatus.OPEN}),
    AlertStatus.FALSE_POSITIVE: frozenset({AlertStatus.OPEN}),
}


class InvalidTransition(ValueError):
    """Raised when an alert is moved somewhere its current status doesn't allow."""


def can_transition(current: AlertStatus, target: AlertStatus) -> bool:
    return target in _TRANSITIONS[current]


def transition(current: AlertStatus, target: AlertStatus) -> AlertStatus:
    """Return `target` if the move is allowed, otherwise raise InvalidTransition."""
    if not can_transition(current, target):
        raise InvalidTransition(f"cannot move an alert from {current.value} to {target.value}")
    return target


# ------------------------------------------------------- recommended actions


@dataclass(frozen=True, slots=True)
class Action:
    id: str  # stable, for the UI and for dedupe
    priority: int  # lower is shown first
    title: str
    detail: str


_ACTIONS: dict[str, Action] = {
    action.id: action
    for action in (
        Action(
            "no_click_no_open",
            10,
            "Don't click links or open attachments",
            "Leave the message alone until you have confirmed it is genuine.",
        ),
        Action(
            "dont_reply",
            20,
            "Don't reply",
            "A reply would go to an address you can't trust, and tells the sender "
            "your mailbox is active.",
        ),
        Action(
            "verify_sender",
            30,
            "Confirm the sender another way",
            "If the message might be real, contact the sender using a phone number or "
            "website you already know, not anything given in the message.",
        ),
        Action(
            "check_real_address",
            35,
            "Check the real sender address",
            "The name shown as the sender can say anything. Look at the actual address "
            "it was sent from.",
        ),
        Action(
            "type_the_address",
            40,
            "Visit the site yourself",
            "If you need to log in or pay, type the website address yourself or use a "
            "bookmark instead of the link in the message.",
        ),
        Action(
            "if_credentials_entered",
            50,
            "If you entered a password",
            "Change it now, anywhere else you use it too, and turn on two-factor "
            "authentication for the account.",
        ),
        Action(
            "if_attachment_opened",
            60,
            "If you opened the attachment",
            "Disconnect the device from the network, run a full malware scan, and tell "
            "whoever looks after your computer or accounts.",
        ),
        Action(
            "report_and_delete",
            90,
            "Report it and delete it",
            "Use your mail provider's report phishing option, then delete the message.",
        ),
    )
}

_ACTIONS_BY_RULE_PREFIX: dict[str, tuple[str, ...]] = {
    "auth": ("verify_sender",),
    "reply_to": ("dont_reply", "verify_sender"),
    "display_name": ("check_real_address", "verify_sender"),
    "link": ("no_click_no_open", "type_the_address", "if_credentials_entered"),
    "attachment": ("no_click_no_open", "if_attachment_opened"),
}


def recommend_actions(assessment: Assessment) -> tuple[Action, ...]:
    """Actions for the findings that actually scored, most urgent first."""
    wanted: set[str] = {"report_and_delete"}
    if assessment.verdict is Verdict.PHISHING:
        wanted.update({"no_click_no_open", "dont_reply"})
    for reason in assessment.reasons:
        if reason.points > 0:
            prefix = reason.rule_id.split(".")[0]
            wanted.update(_ACTIONS_BY_RULE_PREFIX.get(prefix, ()))
    return tuple(sorted((_ACTIONS[action_id] for action_id in wanted), key=lambda a: a.priority))


# ---------------------------------------------------------------- the alert


@dataclass(frozen=True, slots=True)
class AlertDraft:
    """Everything needed to save an alert, before it has an id or a status."""

    title: str
    severity: Severity  # HIGH for phishing, MEDIUM for suspicious
    verdict: Verdict
    score: int
    summary: str  # the assessment headline
    reasons: tuple[Reason, ...]
    actions: tuple[Action, ...]
    rules_version: str
    complete: bool  # False if some rules crashed and findings may be missing

    def to_dict(self) -> dict[str, Any]:
        """A JSON-safe form for storing or returning from the API."""
        return {
            "title": self.title,
            "severity": self.severity.name.lower(),
            "verdict": self.verdict.value,
            "score": self.score,
            "summary": self.summary,
            "reasons": [
                {
                    "rule_id": r.rule_id,
                    "severity": r.severity.name.lower(),
                    "title": r.title,
                    "detail": r.detail,
                    "evidence": list(r.evidence),
                    "points": r.points,
                }
                for r in self.reasons
            ],
            "actions": [{"id": a.id, "title": a.title, "detail": a.detail} for a in self.actions],
            "rules_version": self.rules_version,
            "complete": self.complete,
        }


def should_alert(assessment: Assessment) -> bool:
    return assessment.verdict is not Verdict.CLEAN


def build_alert(assessment: Assessment, subject: str) -> AlertDraft | None:
    """Draft an alert for a flagged message, or None when it looks clean."""
    if not should_alert(assessment):
        return None
    phishing = assessment.verdict is Verdict.PHISHING
    label = "Likely phishing" if phishing else "Suspicious message"
    return AlertDraft(
        title=f"{label}: {_clean_subject(subject)}",
        severity=Severity.HIGH if phishing else Severity.MEDIUM,
        verdict=assessment.verdict,
        score=assessment.score,
        summary=assessment.headline,
        reasons=assessment.reasons,
        actions=recommend_actions(assessment),
        rules_version=assessment.rules_version,
        complete=assessment.complete,
    )


def _clean_subject(subject: str) -> str:
    cleaned = " ".join(_UNSAFE_CHARS.sub(" ", subject).split())
    if not cleaned:
        return "(no subject)"
    if len(cleaned) > _MAX_SUBJECT:
        return cleaned[: _MAX_SUBJECT - 1].rstrip() + "…"
    return cleaned
