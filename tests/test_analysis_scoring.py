import re

from heron.analysis.scoring import (
    DEFAULT_CONFIG,
    SCORING_VERSION,
    ScoringConfig,
    Verdict,
    assess,
    rules_version,
)
from heron.rules.base import Finding, Rule, Severity
from heron.rules.registry import RULES, RuleResults


def finding(rule_id: str, severity: Severity, title: str = "") -> Finding:
    return Finding(rule_id, severity, title or rule_id, f"detail of {rule_id}", (f"e:{rule_id}",))


def results(*findings: Finding, errors: tuple[str, ...] = ()) -> RuleResults:
    return RuleResults(tuple(findings), errors)


def test_no_findings_is_clean_with_a_plain_headline():
    assessment = assess(results())
    assert assessment.score == 0
    assert assessment.verdict is Verdict.CLEAN
    assert assessment.reasons == ()
    assert assessment.headline == "No suspicious signals found."
    assert assessment.complete


def test_points_by_severity():
    assert assess(results(finding("a.x", Severity.INFO))).score == 0
    assert assess(results(finding("a.x", Severity.LOW))).score == 5
    assert assess(results(finding("a.x", Severity.MEDIUM))).score == 15
    assert assess(results(finding("a.x", Severity.HIGH))).score == 35


def test_one_high_signal_alone_is_only_suspicious():
    assessment = assess(results(finding("auth.dmarc_fail", Severity.HIGH)))
    assert assessment.verdict is Verdict.SUSPICIOUS
    assert assessment.score == 35


def test_two_independent_high_signals_are_phishing():
    assessment = assess(
        results(finding("auth.dmarc_fail", Severity.HIGH), finding("link.text", Severity.HIGH))
    )
    assert assessment.verdict is Verdict.PHISHING
    assert assessment.score == 70


def test_score_is_capped_at_100():
    many = [finding(f"r{i}.x", Severity.HIGH) for i in range(6)]
    assert assess(results(*many)).score == 100


def test_thresholds_are_inclusive():
    # MEDIUM + LOW + LOW = 25 = suspicious_at; MEDIUM + LOW = 20 is below it.
    assert (
        assess(
            results(
                finding("a.x", Severity.MEDIUM),
                finding("b.x", Severity.LOW),
                finding("c.x", Severity.LOW),
            )
        ).verdict
        is Verdict.SUSPICIOUS
    )
    assert (
        assess(results(finding("a.x", Severity.MEDIUM), finding("b.x", Severity.LOW))).verdict
        is Verdict.CLEAN
    )
    # HIGH + MEDIUM + LOW + LOW = 60 = phishing_at.
    sixty = results(
        finding("a.x", Severity.HIGH),
        finding("b.x", Severity.MEDIUM),
        finding("c.x", Severity.LOW),
        finding("d.x", Severity.LOW),
    )
    assert assess(sixty).score == 60
    assert assess(sixty).verdict is Verdict.PHISHING


def test_repeats_of_one_rule_id_score_once_using_the_strongest():
    weak = finding("attachment.archive", Severity.LOW, "weak")
    strong = finding("attachment.archive", Severity.HIGH, "strong")
    assessment = assess(results(weak, strong))
    assert assessment.score == 35
    assert [(r.title, r.points) for r in assessment.reasons] == [("strong", 35), ("weak", 0)]


def test_reasons_are_ordered_by_contribution_and_keep_their_text():
    assessment = assess(
        results(
            finding("a.low", Severity.LOW, "low one"),
            finding("b.info", Severity.INFO, "info one"),
            finding("c.high", Severity.HIGH, "high one"),
            finding("d.med", Severity.MEDIUM, "medium one"),
        )
    )
    titles = [r.title for r in assessment.reasons]
    assert titles == ["high one", "medium one", "low one", "info one"]
    top = assessment.reasons[0]
    assert (top.rule_id, top.severity, top.detail, top.evidence) == (
        "c.high",
        Severity.HIGH,
        "detail of c.high",
        ("e:c.high",),
    )


def test_headline_names_the_top_reasons_and_skips_zero_point_ones():
    assessment = assess(
        results(
            finding("a.x", Severity.HIGH, "DMARC check failed"),
            finding("b.x", Severity.HIGH, "Link text doesn't match"),
            finding("c.x", Severity.MEDIUM, "Reply-To differs"),
            finding("d.x", Severity.LOW, "Archive attachment"),
            finding("e.x", Severity.INFO, "No authentication results"),
        )
    )
    assert assessment.headline == (
        "Likely phishing (score 90): DMARC check failed; Link text doesn't match; Reply-To differs"
    )


def test_clean_verdict_with_minor_signals_still_says_what_they_were():
    assessment = assess(results(finding("a.x", Severity.LOW, "Archive attachment")))
    assert assessment.verdict is Verdict.CLEAN
    assert assessment.headline == "No strong warning signs (score 5): Archive attachment"


def test_crashed_rules_make_the_assessment_incomplete_and_say_so():
    assessment = assess(results(errors=("link: ValueError",)))
    assert assessment.verdict is Verdict.CLEAN
    assert not assessment.complete
    assert assessment.rule_errors == ("link: ValueError",)
    assert assessment.headline == (
        "No suspicious signals found. Analysis incomplete: 1 rule(s) failed."
    )


def test_custom_config_changes_the_outcome_and_the_version():
    strict = ScoringConfig(high=70)
    one_high = results(finding("a.x", Severity.HIGH))
    assert assess(one_high, config=strict).verdict is Verdict.PHISHING
    assert assess(one_high).verdict is Verdict.SUSPICIOUS
    assert assess(one_high, config=strict).rules_version != assess(one_high).rules_version


def test_rules_version_format_and_stability():
    version = rules_version()
    assert re.fullmatch(rf"s{SCORING_VERSION}-[0-9a-f]{{8}}", version)
    assert rules_version() == version
    assert assess(results()).rules_version == version


def test_rules_version_changes_when_a_rule_changes_or_is_added():
    def check(_ctx):
        return []

    base = rules_version(RULES)
    bumped = (*RULES[1:], Rule(RULES[0].id, RULES[0].version + 1, RULES[0].check))
    assert rules_version(bumped) != base  # a rule's behaviour changed
    assert rules_version((*RULES, Rule("new", 1, check))) != base  # a rule was added
    assert rules_version(tuple(reversed(RULES))) == base  # order is irrelevant
    assert rules_version(RULES, DEFAULT_CONFIG) == base
