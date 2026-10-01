"""The shapes every rule shares.

A rule is a pure function: RuleContext in, list of Findings out. It reports
what it saw and how serious that is; it does not score the message. Turning
findings into a verdict is the scoring engine's job, which keeps rules easy
to test one at a time and easy to re-weigh later without touching them.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import IntEnum

from heron.analysis.extractor import Iocs
from heron.analysis.parser import ParsedEmail


class Severity(IntEnum):
    INFO = 0  # worth showing, not worth worrying about
    LOW = 1
    MEDIUM = 2
    HIGH = 3


@dataclass(frozen=True, slots=True)
class RuleContext:
    email: ParsedEmail
    iocs: Iocs


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str  # stable, dotted: "auth.dmarc_fail"
    severity: Severity
    title: str  # a few words, for a list
    detail: str  # one plain-English sentence on why it matters
    evidence: tuple[str, ...] = ()  # the specific values that triggered it


@dataclass(frozen=True, slots=True)
class Rule:
    id: str  # prefix of every rule_id this rule emits: "auth"
    version: int  # bump when the rule's behaviour changes
    check: Callable[[RuleContext], Sequence[Finding]]
