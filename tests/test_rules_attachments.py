from email.message import EmailMessage
from pathlib import Path

from heron.analysis.extractor import extract_iocs
from heron.analysis.parser import parse_email
from heron.rules.attachments import MAX_ATTACHMENTS_CHECKED, check
from heron.rules.base import RuleContext, Severity

FIXTURES = Path(__file__).parent / "fixtures" / "emails"


def run_raw(raw: bytes):
    email = parse_email(raw)
    return check(RuleContext(email, extract_iocs(email)))


def run(*files: tuple[str | None, str]):
    """Each file is (filename, "maintype/subtype")."""
    message = EmailMessage()
    message["From"] = "sender@example.org"
    message.set_content("body")
    for filename, content_type in files:
        maintype, _, subtype = content_type.partition("/")
        message.add_attachment(b"data", maintype=maintype, subtype=subtype, filename=filename)
    return run_raw(message.as_bytes())


def ids(findings):
    return [f.rule_id for f in findings]


def test_phish_fixture_program_disguised_as_a_document():
    (finding,) = run_raw((FIXTURES / "phish_invoice.eml").read_bytes())
    assert finding.rule_id == "attachment.double_extension"
    assert finding.severity == Severity.HIGH
    assert finding.evidence == ("file: invoice.pdf.exe", "type: application/octet-stream")
    assert ".pdf.exe" in finding.detail


def test_clean_fixtures_have_no_findings():
    for name in ("plain_simple.eml", "newsletter_alternative.eml", "forwarded_rfc822.eml"):
        assert run_raw((FIXTURES / name).read_bytes()) == [], name


def test_plain_executable_and_scripts_are_high():
    for name in ("setup.exe", "run.bat", "x.js", "x.vbs", "x.ps1", "a.scr", "tool.lnk", "a.jar"):
        (finding,) = run((name, "application/octet-stream"))
        assert finding.rule_id == "attachment.executable", name
        assert finding.severity == Severity.HIGH


def test_double_extension_needs_a_document_looking_first_extension():
    assert ids(run(("report.v2.exe", "application/octet-stream"))) == ["attachment.executable"]
    jpg_scr = run(("photo.JPG.scr", "application/octet-stream"))
    assert ids(jpg_scr) == ["attachment.double_extension"]
    assert run(("invoice.pdf.txt", "text/plain")) == []  # not a program


def test_macro_documents_disk_images_html_and_archives():
    cases = {
        "budget.xlsm": ("attachment.macro_document", Severity.MEDIUM),
        "setup.iso": ("attachment.disk_image", Severity.MEDIUM),
        "login.html": ("attachment.html_file", Severity.MEDIUM),
        "files.zip": ("attachment.archive", Severity.LOW),
    }
    for name, (rule_id, severity) in cases.items():
        (finding,) = run((name, "application/octet-stream"))
        assert (finding.rule_id, finding.severity) == (rule_id, severity), name


def test_ordinary_documents_and_images_are_fine():
    assert run(("report.pdf", "application/pdf"), ("photo.png", "image/png")) == []
    assert run(("notes.docx", "application/octet-stream")) == []


def test_declared_program_type_behind_a_harmless_name():
    (finding,) = run(("holiday.jpg", "application/x-msdownload"))
    assert finding.rule_id == "attachment.type_mismatch"
    assert finding.severity == Severity.MEDIUM


def test_hidden_direction_characters_are_flagged_and_written_out():
    # "invoice" + RIGHT-TO-LEFT OVERRIDE + "gpj.exe" displays as "invoiceexe.jpg"
    findings = run(("invoice\u202egpj.exe", "application/octet-stream"))
    assert set(ids(findings)) == {"attachment.bidi_filename", "attachment.executable"}
    bidi = next(f for f in findings if f.rule_id == "attachment.bidi_filename")
    assert bidi.severity == Severity.HIGH
    assert bidi.evidence[0] == "file: invoice\\u202egpj.exe"  # never the raw character


def test_each_attachment_is_reported_and_the_count_is_capped():
    findings = run(("a.exe", "application/octet-stream"), ("b.zip", "application/zip"))
    assert ids(findings) == ["attachment.executable", "attachment.archive"]

    many = run(*[(f"f{i}.exe", "application/octet-stream") for i in range(30)])
    assert len(many) == MAX_ATTACHMENTS_CHECKED
