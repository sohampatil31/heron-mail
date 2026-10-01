from pathlib import Path

from heron.analysis.extractor import extract_iocs
from heron.analysis.parser import parse_email
from heron.rules.base import Finding, Rule, RuleContext, Severity
from heron.rules.registry import RULES, run_rules

FIXTURES = Path(__file__).parent / "fixtures" / "emails"


def context(name: str) -> RuleContext:
    email = parse_email((FIXTURES / name).read_bytes())
    return RuleContext(email, extract_iocs(email))


def test_rule_ids_are_unique():
    ids = [rule.id for rule in RULES]
    assert len(ids) == len(set(ids))


def test_findings_are_most_severe_first_and_use_their_rules_prefix():
    results = run_rules(context("phish_invoice.eml"))
    assert results.errors == ()
    assert [f.rule_id for f in results.findings] == [
        "auth.dmarc_fail",  # HIGH
        "auth.spf_fail",  # MEDIUM, registry order keeps auth before reply_to
        "reply_to.mismatch",  # MEDIUM
    ]
    prefixes = {rule.id for rule in RULES}
    assert all(f.rule_id.split(".")[0] in prefixes for f in results.findings)


def test_clean_message_has_no_findings():
    results = run_rules(context("newsletter_alternative.eml"))
    assert results.findings == ()
    assert results.errors == ()


def test_a_crashing_rule_is_reported_and_does_not_hide_the_others():
    def boom(_ctx: RuleContext) -> list[Finding]:
        raise RuntimeError("secret detail that must not be echoed")

    def always(_ctx: RuleContext) -> list[Finding]:
        return [Finding("ok.always", Severity.LOW, "t", "d")]

    results = run_rules(context("plain_simple.eml"), [Rule("boom", 1, boom), Rule("ok", 1, always)])
    assert results.errors == ("boom: RuntimeError",)  # type only, never the message
    assert [f.rule_id for f in results.findings] == ["ok.always"]
