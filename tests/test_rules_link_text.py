from email.message import EmailMessage
from pathlib import Path

from heron.analysis.extractor import extract_iocs
from heron.analysis.parser import parse_email
from heron.rules.base import RuleContext, Severity
from heron.rules.link_text import MAX_EVIDENCE, check

FIXTURES = Path(__file__).parent / "fixtures" / "emails"


def run_raw(raw: bytes):
    email = parse_email(raw)
    return check(RuleContext(email, extract_iocs(email)))


def run(html: str):
    message = EmailMessage()
    message["From"] = "sender@example.org"
    message.set_content("body")
    message.add_alternative(html, subtype="html")
    return run_raw(message.as_bytes())


def link(href: str, text: str) -> str:
    return f'<a href="{href}">{text}</a>'


def test_phish_fixture_text_shows_a_domain_but_goes_to_an_ip():
    (finding,) = run_raw((FIXTURES / "phish_invoice.eml").read_bytes())
    assert finding.rule_id == "link.text_mismatch"
    assert finding.severity == Severity.HIGH  # the real target is a raw IP
    assert finding.evidence == (
        'shows "https://www.example-bank.test/login" but goes to hxxp[://]198[.]51[.]100[.]7/login',
    )


def test_evidence_is_defanged():
    (finding,) = run(link("http://evil.invalid/x", "https://your-bank.test/login"))
    assert "http://" not in finding.evidence[0]
    assert "evil[.]invalid" in finding.evidence[0]


def test_matching_link_text_is_fine():
    assert run(link("https://www.example.com/a", "https://example.com/b")) == []
    assert run(link("https://news.example.co.uk/a", "www.example.co.uk")) == []
    assert run(link("https://example.com/a", "example.com")) == []


def test_ordinary_link_text_is_ignored():
    assert run(link("https://evil.invalid/x", "Click here")) == []
    assert run(link("https://evil.invalid/x", "Read the report. It is long.")) == []
    assert run(link("https://evil.invalid/x", "")) == []


def test_different_organisation_is_medium_like_a_tracking_redirect():
    (finding,) = run(link("https://click.mailer.invalid/r?u=1", "https://brand.example/offer"))
    assert finding.severity == Severity.MEDIUM


def test_bare_domain_text_is_compared_too():
    (finding,) = run(link("https://click.mailer.invalid/r", "brand.example/offer"))
    assert finding.rule_id == "link.text_mismatch"


def test_dangerous_targets_raise_severity_to_high():
    userinfo = run(link("http://brand.example@evil.invalid/x", "https://brand.example/x"))
    assert userinfo[0].severity == Severity.HIGH
    punycode = run(link("http://xn--brnd-evil.invalid/x", "https://brand.example/x"))
    assert punycode[0].severity == Severity.HIGH


def test_link_text_equal_to_the_ip_target_is_fine():
    assert run(link("http://198.51.100.7/a", "http://198.51.100.7/a")) == []


def test_images_and_forms_have_no_link_text():
    html = '<img src="http://evil.invalid/p.gif"><form action="http://evil.invalid/s"></form>'
    assert run(html) == []


def test_evidence_is_capped_and_severity_is_the_worst_seen():
    links = "".join(
        link(f"http://t{i}.mailer.invalid/", f"https://brand{i}.example/") for i in range(8)
    )
    links += link("http://198.51.100.7/", "https://brand.example/")
    (finding,) = run(links)
    assert len(finding.evidence) == MAX_EVIDENCE
    assert finding.severity == Severity.HIGH  # the IP link came after the cap but still counts
