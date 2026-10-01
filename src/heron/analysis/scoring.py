"""Turn rule findings into one score, a verdict, and readable reasons.

Rules only report what they saw (and how serious it is). This module is the
only place that decides what that adds up to, so weights and thresholds can
change without touching a single rule.

How the score works:
- Each finding is worth points by severity (INFO 0, LOW 5, MEDIUM 15, HIGH 35).
- Within one rule_id only the first finding scores. Five executable
  attachments are not five times as bad as one.
- The sum is capped at 100.
- Verdict: score >= 60 is PHISHING ("likely phishing"), >= 25 is SUSPICIOUS,
  otherwise CLEAN. One HIGH signal alone is therefore only SUSPICIOUS; it
  takes two independent strong signals (or one plus several smaller ones)
  to reach PHISHING.

Every assessment carries a rules_version fingerprint. A stored verdict is
only comparable with others of the same version; when it changes (a rule was
added or changed, or the weights moved), old messages can be re-scored.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from heron.rules.base import Finding, Rule, Severity
from heron.rules.registry import RULES, RuleResults

# Bump when the scoring logic itself changes in a way the config can't express.
SCORING_VERSION = 1

_HEADLINE_REASONS = 3


class Verdict(StrEnum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    PHISHING = "phishing"


@dataclass(frozen=True, slots=True)
class ScoringConfig:
    low: int = 5
    medium: int = 15
    high: int = 35
    suspicious_at: int = 25
    phishing_at: int = 60
    max_score: int = 100

    def points(self, severity: Severity) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: self.low,
            Severity.MEDIUM: self.medium,
            Severity.HIGH: self.high,
        }[severity]


DEFAULT_CONFIG = ScoringConfig()


@dataclass(frozen=True, slots=True)
class Reason:
    rule_id: str
    severity: Severity
    title: str
    detail: str
    evidence: tuple[str, ...]
    points: int  # 0 for INFO, and for repeats of a rule_id that already scored


@dataclass(frozen=True, slots=True)
class Assessment:
    score: int  # 0..max_score
    verdict: Verdict
    reasons: tuple[Reason, ...]  # biggest contribution first
    headline: str  # one readable sentence for a list or an alert title
    rules_version: str
    rule_errors: tuple[str, ...]  # rules that crashed; their findings are missing

    @property
    def complete(self) -> bool:
        return not self.rule_errors


def rules_version(rules: Sequence[Rule] = RULES, config: ScoringConfig = DEFAULT_CONFIG) -> str:
    """e.g. "s1-3f9a2c1b": scoring logic version plus a hash of rules and weights."""
    parts = [f"{rule.id}:{rule.version}" for rule in sorted(rules, key=lambda r: r.id)]
    fingerprint = hashlib.sha256(f"{'|'.join(parts)}|{config!r}".encode()).hexdigest()[:8]
    return f"s{SCORING_VERSION}-{fingerprint}"


def assess(
    results: RuleResults,
    rules: Sequence[Rule] = RULES,
    config: ScoringConfig = DEFAULT_CONFIG,
) -> Assessment:
    reasons = _score_findings(results.findings, config)
    score = min(sum(reason.points for reason in reasons), config.max_score)
    if score >= config.phishing_at:
        verdict = Verdict.PHISHING
    elif score >= config.suspicious_at:
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.CLEAN
    return Assessment(
        score=score,
        verdict=verdict,
        reasons=reasons,
        headline=_headline(verdict, score, reasons, len(results.errors)),
        rules_version=rules_version(rules, config),
        rule_errors=results.errors,
    )


def _score_findings(findings: Sequence[Finding], config: ScoringConfig) -> tuple[Reason, ...]:
    # Strongest first, so when a rule_id repeats it is the strongest one that scores.
    ranked = sorted(findings, key=lambda finding: -finding.severity)
    scored: set[str] = set()
    reasons: list[Reason] = []
    for finding in ranked:
        first_of_its_rule = finding.rule_id not in scored
        scored.add(finding.rule_id)
        reasons.append(
            Reason(
                rule_id=finding.rule_id,
                severity=finding.severity,
                title=finding.title,
                detail=finding.detail,
                evidence=finding.evidence,
                points=config.points(finding.severity) if first_of_its_rule else 0,
            )
        )
    return tuple(sorted(reasons, key=lambda reason: -reason.points))


def _headline(verdict: Verdict, score: int, reasons: Sequence[Reason], errors: int) -> str:
    titles = [reason.title for reason in reasons if reason.points > 0][:_HEADLINE_REASONS]
    top = "; ".join(titles)
    if verdict is Verdict.PHISHING:
        text = f"Likely phishing (score {score}): {top}"
    elif verdict is Verdict.SUSPICIOUS:
        text = f"Suspicious (score {score}): {top}"
    elif titles:
        text = f"No strong warning signs (score {score}): {top}"
    else:
        text = "No suspicious signals found."
    if errors:
        text += f" Analysis incomplete: {errors} rule(s) failed."
    return text
