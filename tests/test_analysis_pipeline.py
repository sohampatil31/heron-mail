from pathlib import Path

from heron.analysis.pipeline import analyze
from heron.analysis.scoring import Verdict

FIXTURES = Path(__file__).parent / "fixtures" / "emails"


def run(name: str):
    return analyze((FIXTURES / name).read_bytes())


def test_obvious_phishing_scores_high_with_readable_reasons():
    analysis = run("phish_invoice.eml")
    assessment = analysis.assessment
    assert assessment.verdict is Verdict.PHISHING
    assert assessment.score == 100
    assert assessment.complete
    assert [r.rule_id for r in assessment.reasons] == [
        "auth.dmarc_fail",
        "display_name.address_mismatch",
        "link.text_mismatch",
        "attachment.double_extension",
        "auth.spf_fail",
        "reply_to.mismatch",
    ]
    assert assessment.headline.startswith("Likely phishing (score 100): DMARC check failed;")
    # Every reason is something a person can read and verify.
    assert all(r.title and r.detail and r.evidence for r in assessment.reasons)


def test_ordinary_newsletter_scores_zero():
    analysis = run("newsletter_alternative.eml")
    assert analysis.assessment.verdict is Verdict.CLEAN
    assert analysis.assessment.score == 0
    assert analysis.assessment.reasons == ()


def test_message_without_auth_results_is_clean_but_keeps_the_note():
    assessment = run("plain_simple.eml").assessment
    assert assessment.verdict is Verdict.CLEAN
    assert assessment.score == 0  # INFO scores nothing
    assert [r.rule_id for r in assessment.reasons] == ["auth.no_results"]
    assert assessment.headline == "No suspicious signals found."


def test_forwarded_and_encoded_mail_are_clean():
    for name in ("forwarded_rfc822.eml", "encoded_headers.eml"):
        assert run(name).assessment.verdict is Verdict.CLEAN, name


def test_malformed_input_never_raises():
    for name in ("malformed_headers.eml", "truncated_multipart.eml"):
        assessment = run(name).assessment
        assert assessment.complete, name
        assert assessment.verdict is Verdict.CLEAN, name
    assert analyze(b"").assessment.verdict is Verdict.CLEAN
    assert analyze(b"\x00\xff" * 50).assessment.complete


def test_analysis_carries_the_parsed_email_and_iocs():
    analysis = run("phish_invoice.eml")
    assert analysis.email.subject == "Action required: verify your account"
    assert "http://198.51.100.7/login" in {u.url for u in analysis.iocs.urls}
    assert analysis.assessment.rules_version.startswith("s1-")
