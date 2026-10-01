from email.message import EmailMessage
from pathlib import Path

from heron.analysis.extractor import extract_iocs
from heron.analysis.parser import parse_email
from heron.rules.authentication import check, parse_authentication_results
from heron.rules.base import RuleContext, Severity

FIXTURES = Path(__file__).parent / "fixtures" / "emails"


def run(raw: bytes):
    email = parse_email(raw)
    return check(RuleContext(email, extract_iocs(email)))


def run_headers(*headers: tuple[str, str]):
    message = EmailMessage()
    message["From"] = "sender@example.org"
    for name, value in headers:
        message[name] = value  # repeated names are appended, in order
    message.set_content("body")
    return run(message.as_bytes())


def by_id(findings):
    return {f.rule_id: f for f in findings}


def test_parse_authentication_results():
    authserv, results = parse_authentication_results(
        "MX.Example.org 1; SPF=PASS smtp.mailfrom=a.example; "
        "dkim=pass (good signature) header.d=a.example; dkim=fail header.d=other.example; "
        "dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=a.example; compauth=pass reason=100"
    )
    assert authserv == "mx.example.org"
    assert results["spf"] == ("pass",)
    assert results["dkim"] == ("pass", "fail")
    assert results["dmarc"] == ("pass",)


def test_parse_handles_empty_and_none_forms():
    assert parse_authentication_results("mx.example.org; none") == ("mx.example.org", {})
    assert parse_authentication_results("") == (None, {})


def test_phish_fixture_reports_dmarc_and_spf_failures():
    findings = by_id(run((FIXTURES / "phish_invoice.eml").read_bytes()))
    assert set(findings) == {"auth.dmarc_fail", "auth.spf_fail"}  # dkim=none is not a failure
    assert findings["auth.dmarc_fail"].severity == Severity.HIGH
    assert findings["auth.spf_fail"].severity == Severity.MEDIUM
    assert findings["auth.spf_fail"].evidence == ("spf=fail", "reported by mx.example.org")


def test_newsletter_fixture_that_passes_everything_has_no_findings():
    assert run((FIXTURES / "newsletter_alternative.eml").read_bytes()) == []


def test_message_with_no_results_is_info_only():
    (finding,) = run((FIXTURES / "plain_simple.eml").read_bytes())
    assert finding.rule_id == "auth.no_results"
    assert finding.severity == Severity.INFO


def test_dkim_failure_alone():
    findings = by_id(
        run_headers(
            (
                "Authentication-Results",
                "mx.example.org; spf=pass smtp.mailfrom=a.example; "
                "dkim=fail header.d=a.example; dmarc=pass header.from=a.example",
            )
        )
    )
    assert set(findings) == {"auth.dkim_fail"}
    assert findings["auth.dkim_fail"].severity == Severity.MEDIUM


def test_one_passing_dkim_signature_is_enough():
    findings = run_headers(
        (
            "Authentication-Results",
            "mx.example.org; dkim=fail header.d=relay.example; dkim=pass header.d=a.example; "
            "spf=pass; dmarc=pass",
        )
    )
    assert findings == []


def test_spf_softfail_is_low():
    (finding,) = run_headers(
        ("Authentication-Results", "mx.example.org; spf=softfail; dkim=pass; dmarc=pass")
    )
    assert finding.rule_id == "auth.spf_fail"
    assert finding.severity == Severity.LOW


def test_nothing_passing_without_a_failure_is_low():
    (finding,) = run_headers(
        ("Authentication-Results", "mx.example.org; spf=none; dkim=none; dmarc=none")
    )
    assert finding.rule_id == "auth.unauthenticated"
    assert finding.severity == Severity.LOW
    assert finding.evidence == ("spf=none", "dkim=none", "dmarc=none", "reported by mx.example.org")


def test_a_failure_suppresses_the_generic_unauthenticated_finding():
    findings = by_id(
        run_headers(("Authentication-Results", "mx.example.org; spf=fail; dkim=none; dmarc=none"))
    )
    assert set(findings) == {"auth.spf_fail"}


def test_only_the_topmost_authentication_results_header_counts():
    # The first header is the receiving server's. The lower one is older and
    # could have been written by the sender, so its "fail" must not matter.
    findings = run_headers(
        ("Authentication-Results", "mx.example.org; spf=pass; dkim=pass; dmarc=pass"),
        ("Authentication-Results", "forged.example; spf=fail; dmarc=fail"),
    )
    assert findings == []

    findings = run_headers(
        ("Authentication-Results", "mx.example.org; spf=fail; dkim=pass; dmarc=pass"),
        ("Authentication-Results", "forged.example; spf=pass; dmarc=pass"),
    )
    assert set(by_id(findings)) == {"auth.spf_fail"}


def test_received_spf_is_a_fallback_when_there_is_no_authentication_results():
    findings = run_headers(
        ("Received-SPF", "fail (google.com: domain of a@sender.example does not designate 1.2.3.4)")
    )
    assert [f.rule_id for f in findings] == ["auth.spf_fail"]

    assert run_headers(("Received-SPF", "pass (google.com: designates 1.2.3.4)")) == []


def test_authentication_results_spf_beats_received_spf():
    findings = run_headers(
        ("Authentication-Results", "mx.example.org; spf=pass; dkim=pass; dmarc=pass"),
        ("Received-SPF", "fail (somebody else)"),
    )
    assert findings == []
