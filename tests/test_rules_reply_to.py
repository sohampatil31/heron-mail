from email.message import EmailMessage
from pathlib import Path

from heron.analysis.extractor import extract_iocs
from heron.analysis.parser import parse_email
from heron.rules.base import RuleContext, Severity
from heron.rules.reply_to import check

FIXTURES = Path(__file__).parent / "fixtures" / "emails"


def run_raw(raw: bytes):
    email = parse_email(raw)
    return check(RuleContext(email, extract_iocs(email)))


def run(from_: str | None, reply_to: str | None):
    message = EmailMessage()
    if from_:
        message["From"] = from_
    if reply_to:
        message["Reply-To"] = reply_to
    message.set_content("body")
    return run_raw(message.as_bytes())


def test_phish_fixture_flags_reply_to_on_another_domain():
    (finding,) = run_raw((FIXTURES / "phish_invoice.eml").read_bytes())
    assert finding.rule_id == "reply_to.mismatch"
    assert finding.severity == Severity.MEDIUM  # freemail.example is not a webmail provider
    assert finding.evidence == (
        "From: noreply@mailer.invalid",
        "Reply-To: billing@freemail.example",
    )


def test_webmail_reply_to_on_a_business_sender_is_high():
    (finding,) = run("Acme Billing <billing@acme.example>", "acme.billing.dept@gmail.com")
    assert finding.severity == Severity.HIGH
    assert "free webmail" in finding.detail


def test_same_organisation_different_subdomain_is_fine():
    assert run("news@mail.example.com", "support@example.com") == []
    assert run("a@news.example.co.uk", "b@example.co.uk") == []


def test_domain_comparison_ignores_case():
    assert run("a@Example.COM", "b@example.com") == []


def test_unrelated_organisations_under_one_suffix_still_differ():
    (finding,) = run("a@example.co.uk", "b@evil.co.uk")
    assert finding.severity == Severity.MEDIUM


def test_webmail_to_webmail_of_the_same_provider_is_fine():
    assert run("a@gmail.com", "b@gmail.com") == []


def test_webmail_sender_with_other_domain_reply_to_is_only_medium():
    (finding,) = run("a@gmail.com", "b@evil.example")
    assert finding.severity == Severity.MEDIUM


def test_no_reply_to_or_no_sender_means_nothing_to_compare():
    assert run("a@example.com", None) == []
    assert run(None, "b@example.com") == []


def test_only_the_foreign_addresses_are_listed():
    (finding,) = run("a@example.com", "ok@example.com, bad@evil.example")
    assert finding.evidence == ("From: a@example.com", "Reply-To: bad@evil.example")
