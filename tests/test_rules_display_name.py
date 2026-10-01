from email.message import EmailMessage
from pathlib import Path

from heron.analysis.extractor import extract_iocs
from heron.analysis.parser import parse_email
from heron.rules.base import RuleContext, Severity
from heron.rules.display_name import check

FIXTURES = Path(__file__).parent / "fixtures" / "emails"


def run_raw(raw: bytes):
    email = parse_email(raw)
    return check(RuleContext(email, extract_iocs(email)))


def run(from_header: str | None):
    message = EmailMessage()
    if from_header:
        message["From"] = from_header
    message.set_content("body")
    return run_raw(message.as_bytes())


def ids(findings):
    return [f.rule_id for f in findings]


def test_phish_fixture_name_claims_another_address():
    (finding,) = run_raw((FIXTURES / "phish_invoice.eml").read_bytes())
    assert finding.rule_id == "display_name.address_mismatch"
    assert finding.severity == Severity.HIGH
    assert finding.evidence == (
        "display name: security@example-bank.test",
        "actual sender: noreply@mailer.invalid",
    )


def test_address_in_name_on_the_same_organisation_is_fine():
    assert run('"billing@example.com" <noreply@mail.example.com>') == []


def test_web_address_in_name_on_another_domain():
    (finding,) = run('"www.your-bank.test support" <help@mailer.invalid>')
    assert finding.rule_id == "display_name.address_mismatch"


def test_plain_names_have_no_findings():
    assert run("Alice Example <alice@example.com>") == []
    assert run("Dr.Smith <smith@clinic.example>") == []  # dotted names are not domains
    assert run("<bare@example.com>") == []  # no display name at all
    assert run(None) == []


def test_brand_name_from_a_foreign_domain():
    (finding,) = run("PayPal Support <service@secure-pay.invalid>")
    assert finding.rule_id == "display_name.brand"
    assert finding.severity == Severity.MEDIUM
    assert "Paypal" in finding.title


def test_brand_name_from_the_brands_own_domains_is_fine():
    assert run("PayPal <service@paypal.com>") == []
    assert run("Microsoft Account Team <no-reply@accountprotection.microsoft.com>") == []
    assert run("Amazon.in <order-update@amazon.in>") == []
    assert run("Amazon <no-reply@amazon.co.uk>") == []


def test_brand_match_is_whole_word_and_allows_a_version_number():
    assert run("Applesauce Weekly <news@example.org>") == []  # not the word "apple"
    assert ids(run("Microsoft365 Team <team@evil.invalid>")) == ["display_name.brand"]


def test_only_one_brand_finding_per_message():
    findings = run("Google and Microsoft Security <alert@evil.invalid>")
    assert ids(findings) == ["display_name.brand"]


def test_address_mismatch_and_brand_can_both_fire():
    findings = run('"PayPal service@paypal.com" <alert@evil.invalid>')
    assert set(ids(findings)) == {"display_name.address_mismatch", "display_name.brand"}
