"""Parser tests, run against the synthetic .eml files in tests/fixtures/emails.

Every fixture uses reserved domains (example.*, *.test, *.invalid) and
documentation IP ranges, so nothing here points at a real site or person.
"""

import hashlib
from email.message import EmailMessage
from pathlib import Path

import pytest

from heron.analysis import parser
from heron.analysis.parser import AttachmentInfo, parse_email

FIXTURES = Path(__file__).parent / "fixtures" / "emails"


def load(name: str):
    return parse_email((FIXTURES / name).read_bytes())


def test_plain_message_basic_fields():
    email = load("plain_simple.eml")
    assert email.subject == "Lunch on Friday?"
    assert email.message_id == "<plain-001@example.com>"
    assert email.date_header == "Tue, 29 Sep 2026 09:15:00 +0000"
    assert email.body_text == "Hi Bob,\nAre you free for lunch on Friday?\n\nAlice\n"
    assert email.body_html == ""
    assert email.attachments == ()
    assert email.defects == ()
    assert not email.body_truncated


def test_addresses_are_split_and_domain_is_lowercased():
    email = load("plain_simple.eml")
    sender = email.from_address
    assert sender is not None
    assert sender.display_name == "Alice Example"
    assert sender.address == "Alice@example.com"  # local part untouched
    assert sender.domain == "example.com"
    assert [a.address for a in email.to] == ["bob@example.org", "carol@example.org"]
    assert email.to[1].display_name == "Carol"
    assert [a.address for a in email.cc] == ["dave@example.net"]


def test_phish_sender_reply_to_and_return_path_are_reported_as_found():
    email = load("phish_invoice.eml")
    sender = email.from_address
    assert sender is not None
    # The display name claims one identity, the address is another.
    assert sender.display_name == "security@example-bank.test"
    assert sender.address == "noreply@mailer.invalid"
    assert email.reply_to[0].address == "billing@freemail.example"
    assert email.reply_to[0].display_name == "Billing Desk"
    assert email.return_path is not None
    assert email.return_path.address == "bounce@mailer.invalid"


def test_header_values_keep_order_and_ignore_case():
    email = load("phish_invoice.eml")
    received = email.header_values("received")
    assert len(received) == 3
    assert "203.0.113.9" in received[0]  # top of the list is the last hop
    assert "10.0.0.5" in received[2]
    auth = email.header_values("AUTHENTICATION-RESULTS")
    assert len(auth) == 1
    assert "spf=fail" in auth[0]
    assert "dmarc=fail" in auth[0]
    assert email.header_values("X-Does-Not-Exist") == ()


def test_phish_bodies_are_split_into_text_and_html():
    email = load("phish_invoice.eml")
    assert "198.51.100.7/login" in email.body_text
    assert '<a href="http://198.51.100.7/login">' in email.body_html
    assert "example-bank.test/login" in email.body_html


def test_phish_attachment_metadata_and_hash():
    email = load("phish_invoice.eml")
    assert len(email.attachments) == 1
    attachment = email.attachments[0]
    content = b"not a real executable, just bytes"
    assert attachment.filename == "invoice.pdf.exe"
    assert attachment.extensions == ("pdf", "exe")
    assert attachment.extension == "exe"
    assert attachment.content_type == "application/octet-stream"
    assert attachment.disposition == "attachment"
    assert attachment.size == len(content)
    assert attachment.sha256 == hashlib.sha256(content).hexdigest()


def test_newsletter_picks_both_bodies_and_treats_inline_image_as_attachment():
    email = load("newsletter_alternative.eml")
    assert "three stories" in email.body_text
    assert '<img src="cid:logo1">' in email.body_html
    assert len(email.attachments) == 1
    image = email.attachments[0]
    assert image.content_type == "image/png"
    assert image.disposition == "inline"
    assert image.content_id == "logo1"
    assert image.filename is None
    assert image.extensions == ()
    assert image.size > 0
    assert email.header_values("List-Unsubscribe") == (
        "<https://newsletter.example.com/unsub?id=42>",
    )


def test_rfc2047_headers_and_non_utf8_body_are_decoded():
    email = load("encoded_headers.eml")
    assert email.subject == "Réunion — café ☕"
    assert email.from_address is not None
    assert email.from_address.display_name == "José Müller"
    assert email.body_text == "Grüße aus Köln\n"


def test_forwarded_message_is_one_attachment_and_its_body_stays_out():
    email = load("forwarded_rfc822.eml")
    assert email.body_text == "Forwarding this, see attached.\n"
    assert "INNER SECRET BODY" not in email.body_text
    assert len(email.attachments) == 1
    forwarded = email.attachments[0]
    assert forwarded.content_type == "message/rfc822"
    assert forwarded.filename == "forwarded.eml"
    assert forwarded.size > 0


def test_missing_headers_and_unknown_charset_do_not_raise():
    email = load("malformed_headers.eml")
    assert email.subject == ""
    assert email.from_addresses == ()
    assert email.from_address is None
    assert email.return_path is None
    assert email.message_id is None
    assert "broken" in email.body_text  # decoded with replacement characters
    assert "\ufffd" in email.body_text


def test_truncated_multipart_keeps_what_it_can_and_reports_the_defect():
    email = load("truncated_multipart.eml")
    assert email.body_text == "visible text"
    assert [a.filename for a in email.attachments] == ["data.bin"]
    assert "CloseBoundaryNotFoundDefect" in email.defects


def test_empty_input_gives_an_empty_result():
    email = parse_email(b"")
    assert email.subject == ""
    assert email.headers == ()
    assert email.body_text == ""
    assert email.attachments == ()


def test_attachment_filename_is_stripped_of_paths_and_control_characters():
    message = EmailMessage()
    message["From"] = "a@example.org"
    message.set_content("body")
    message.add_attachment(
        b"x", maintype="application", subtype="octet-stream", filename="..\\..\\evil\x07.exe"
    )
    email = parse_email(message.as_bytes())
    assert email.attachments[0].filename == "evil.exe"


def test_extensions_ignore_a_leading_dot():
    hidden = AttachmentInfo(".bashrc", "text/plain", 0, "", None, None)
    assert hidden.extensions == ()
    assert hidden.extension == ""
    nameless = AttachmentInfo(None, "text/plain", 0, "", None, None)
    assert nameless.extensions == ()


def test_oversized_body_is_cut_and_flagged(monkeypatch):
    monkeypatch.setattr(parser, "MAX_BODY_CHARS", 10)
    email = load("plain_simple.eml")
    assert email.body_text == "Hi Bob,\nAre"[:10]
    assert email.body_truncated


def test_parsed_email_is_immutable():
    email = load("plain_simple.eml")
    with pytest.raises(AttributeError):
        email.subject = "changed"  # type: ignore[misc]
