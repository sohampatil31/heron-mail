"""The list of active rules, and the one place that runs them."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from heron.rules import authentication, reply_to
from heron.rules.base import Finding, Rule, RuleContext

RULES: tuple[Rule, ...] = (
    Rule(authentication.RULE_ID, 1, authentication.check),
    Rule(reply_to.RULE_ID, 1, reply_to.check),
)


@dataclass(frozen=True, slots=True)
class RuleResults:
    findings: tuple[Finding, ...]  # most severe first, then registry order
    errors: tuple[str, ...]  # "rule_id: ExceptionType" for any rule that crashed


def run_rules(ctx: RuleContext, rules: Sequence[Rule] | None = None) -> RuleResults:
    """Run every rule. One broken rule must not hide the others' findings."""
    findings: list[Finding] = []
    errors: list[str] = []
    for rule in RULES if rules is None else rules:
        try:
            findings.extend(rule.check(ctx))
        except Exception as exc:  # noqa: BLE001 - isolate rules; the failure is reported
            errors.append(f"{rule.id}: {type(exc).__name__}")
    findings.sort(key=lambda finding: -finding.severity)  # stable: ties keep order
    return RuleResults(tuple(findings), tuple(errors))
