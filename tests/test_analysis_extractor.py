"""Extractor tests: synthetic fixtures plus small in-test messages.

Hosts are reserved names (example.*, *.test, *.invalid) and documentation IP
ranges, except 8.8.8.8, used once to prove a public address reads as global.
"""

import hashlib
import ipaddress
from email.message import EmailMessage
from pathlib import Path

from heron.analysis import extractor
from heron.analysis.extractor import (
    defang_domain,
    defang_ip,
    defang_url,
    extract_iocs,
    refang,
)
from heron.analysis.parser import parse_email

FIXTURES = Path(__file__).parent / "fixtures" / "emails"


def make_email(text: str | None = None, html: str | None = None, **headers: str):
    message = EmailMessage()
    message["From"] = headers.pop("From", "sender@example.org")
    for name, value in headers.items():
        message[name.replace("_", "-")] = value
    message.set_content(text or "")
    if html is not None:
        message.add_alternative(html, subtype="html")
    return parse_email(message.as_bytes())


def urls_of(iocs):
    return {u.url: u for u in iocs.urls}


# ------------------------------------------------------------ the fixture


def test_phish_fixture_urls_keep_sources_and_link_text():
    iocs = extract_iocs(parse_email((FIXTURES / "phish_invoice.eml").read_bytes()))
    urls = urls_of(iocs)

    login = urls["http://198.51.100.7/login"]
    assert set(login.sources) == {"text", "href"}
    assert login.link_texts == ("https://www.example-bank.test/login",)
    assert login.ip == "198.51.100.7"
    assert login.host == "198.51.100.7"

    shown = urls["https://www.example-bank.test/login"]
    assert shown.sources == ("html-text",)  # visible text, never a link target
    assert shown.ip is None


def test_phish_fixture_ips_domains_and_hashes():
    iocs = extract_iocs(parse_email((FIXTURES / "phish_invoice.eml").read_bytes()))

    ips = {i.address: i for i in iocs.ips}
    assert set(ips) == {"198.51.100.7", "203.0.113.9", "203.0.113.8", "10.0.0.5"}
    assert "url" in ips["198.51.100.7"].sources
    assert ips["203.0.113.9"].sources == ("received",)
    assert not any(i.is_global for i in iocs.ips)  # documentation and private ranges

    domains = {d.domain: d.sources for d in iocs.domains}
    assert domains["www.example-bank.test"] == ("url",)
    assert domains["mailer.invalid"] == ("from", "return-path")
    assert domains["freemail.example"] == ("reply-to",)
    assert "example.org" not in domains  # the recipient's domain is not an IOC

    content = b"not a real executable, just bytes"
    (attachment_hash,) = iocs.hashes
    assert attachment_hash.algorithm == "sha256"
    assert attachment_hash.value == hashlib.sha256(content).hexdigest()
    assert attachment_hash.sources == ("attachment",)
    assert attachment_hash.filenames == ("invoice.pdf.exe",)


def test_plain_fixture_has_no_iocs():
    iocs = extract_iocs(parse_email((FIXTURES / "plain_simple.eml").read_bytes()))
    assert iocs.urls == iocs.ips == iocs.hashes == ()
    assert [d.domain for d in iocs.domains] == ["example.com"]  # the sender only
    assert not iocs.truncated


def test_empty_message_gives_empty_iocs():
    iocs = extract_iocs(parse_email(b""))
    assert (iocs.urls, iocs.ips, iocs.domains, iocs.hashes) == ((), (), (), ())


# ------------------------------------------------------------------- URLs


def test_trailing_punctuation_and_unbalanced_brackets_are_dropped():
    email = make_email(
        "See (http://example.org/a_(b)). Also http://a.example/x, and <https://b.example/y>."
    )
    assert set(urls_of(extract_iocs(email))) == {
        "http://example.org/a_(b)",
        "http://a.example/x",
        "https://b.example/y",
    }


def test_bare_www_gets_a_scheme_and_scheme_is_lowercased():
    email = make_email("Go to www.evil.invalid/pay or HTTPS://Shop.Example/Cart now")
    assert set(urls_of(extract_iocs(email))) == {
        "http://www.evil.invalid/pay",
        "https://Shop.Example/Cart",
    }
    assert urls_of(extract_iocs(email))["https://Shop.Example/Cart"].host == "shop.example"


def test_already_defanged_urls_in_the_body_are_found():
    email = make_email("Indicator: hxxps://evil[.]invalid/login and 203[.]0[.]113[.]5")
    iocs = extract_iocs(email)
    assert "https://evil.invalid/login" in urls_of(iocs)
    assert "203.0.113.5" in {i.address for i in iocs.ips}


def test_userinfo_trick_reports_the_real_host():
    email = make_email("http://secure.example.com@evil.invalid/x")
    (url,) = extract_iocs(email).urls
    assert url.host == "evil.invalid"
    assert url.has_userinfo


def test_obfuscated_ipv4_hosts_are_normalised():
    target = ipaddress.IPv4Address("192.168.2.1")
    decimal = str(int(target))
    email = make_email(
        f"http://{decimal}/a http://0xC0.0xA8.2.1/b http://0300.0250.2.1/c http://192.168.2.1/d"
    )
    iocs = extract_iocs(email)
    assert {u.ip for u in iocs.urls} == {"192.168.2.1"}
    assert {u.host for u in iocs.urls} == {decimal, "0xc0.0xa8.2.1", "0300.0250.2.1", "192.168.2.1"}
    assert [i.address for i in iocs.ips] == ["192.168.2.1"]  # one address, four spellings
    assert iocs.domains[0].domain == "example.org"  # no domain invented from an IP


def test_ipv6_url_host():
    (url,) = extract_iocs(make_email("http://[2001:db8::1]/x")).urls
    assert url.ip == "2001:db8::1"
    assert url.host == "2001:db8::1"


def test_idn_host_is_reported_in_punycode():
    (url,) = extract_iocs(make_email("http://münchen.example/")).urls
    assert url.host == "xn--mnchen-3ya.example"


def test_invalid_urls_do_not_raise():
    email = make_email("http:// and http://[::1 and http://a b and ftp://")
    iocs = extract_iocs(email)
    assert all(u.scheme in ("http", "https", "ftp") for u in iocs.urls)


def test_html_link_targets_text_and_non_web_links():
    html = (
        "<html><head><meta http-equiv='refresh' content='0; url=http://redirect.example/go'>"
        "<style>.x{background:url(http://style.example/a.png)}</style></head><body>"
        "<script>var u='http://script.example/s';</script>"
        "<a href='http://a.example/?x=1&amp;y=2'>  Click\n here  </a>"
        "<a href='mailto:someone@example.org'>mail</a>"
        "<a href='javascript:alert(1)'>js</a><a href='/relative'>rel</a>"
        "<a href='#top'>top</a><img src='cid:logo1'><img src='data:image/png;base64,AAAA'>"
        "<img src='http://img.example/pixel.gif'>"
        "<form action='https://form.example/submit'></form>"
        "</body></html>"
    )
    urls = urls_of(extract_iocs(make_email(html=html)))
    assert set(urls) == {
        "http://redirect.example/go",
        "http://a.example/?x=1&y=2",
        "http://img.example/pixel.gif",
        "https://form.example/submit",
    }
    assert urls["http://a.example/?x=1&y=2"].link_texts == ("Click here",)
    assert urls["http://redirect.example/go"].sources == ("meta-refresh",)
    assert urls["http://img.example/pixel.gif"].sources == ("src",)
    assert urls["https://form.example/submit"].sources == ("form",)


def test_same_url_in_text_and_html_merges_into_one_entry():
    email = make_email(
        "Visit http://same.example/p", html="<a href='http://same.example/p'>site</a>"
    )
    (url,) = extract_iocs(email).urls
    assert url.sources == ("text", "href")
    assert url.link_texts == ("site",)


def test_broken_html_does_not_raise():
    html = "<a href='http://x.example'>unclosed <b <<<>> <a href=http://y.example>y"
    urls = urls_of(extract_iocs(make_email(html=html)))
    assert "http://x.example" in urls


# ------------------------------------------------------- IPs, domains, hashes


def test_ip_detection_and_false_positives():
    text = (
        "good 8.8.8.8 and 10.0.0.5 and 2001:db8::1 | "
        "bad 999.1.1.1 version 1.2.3.4.5 time 12:30:45 mac aa:bb:cc:dd:ee:ff leading 01.02.03.04"
    )
    ips = {i.address: i for i in extract_iocs(make_email(text)).ips}
    assert set(ips) == {"8.8.8.8", "10.0.0.5", "2001:db8::1"}
    assert ips["8.8.8.8"].is_global
    assert not ips["10.0.0.5"].is_global


def test_received_header_ipv6_and_x_originating_ip():
    email = make_email(
        "hi",
        Received="from a.example (a.example [IPv6:2001:db8::7]) by mx.example.org",
        X_Originating_IP="[203.0.113.77]",
    )
    ips = {i.address: i.sources for i in extract_iocs(email).ips}
    assert ips == {"2001:db8::7": ("received",), "203.0.113.77": ("received",)}


def test_domains_from_body_addresses_but_not_recipients():
    email = make_email(
        "Write to support@helpdesk.invalid or see http://user@host.invalid/x",
        To="victim@victim-corp.example",
        Cc="boss@victim-corp.example",
    )
    domains = {d.domain: d.sources for d in extract_iocs(email).domains}
    assert domains["helpdesk.invalid"] == ("text-email",)
    assert domains["host.invalid"] == ("url",)  # userinfo is not mistaken for an address
    assert "victim-corp.example" not in domains


def test_hashes_in_body_are_classified_and_lowercased():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    sha256 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    text = (
        f"md5 {md5} sha1 {sha1} sha256 {sha256}\n"
        f"digits only {'1' * 32}\n"
        f"too long {'a' * 65}\n"
        f"inside {'f' * 31}g{'f' * 31}\n"
    )
    found = {(h.algorithm, h.value): h.sources for h in extract_iocs(make_email(text)).hashes}
    assert found == {
        ("md5", md5): ("text",),
        ("sha1", sha1): ("text",),
        ("sha256", sha256.lower()): ("text",),
    }


def test_empty_attachments_are_not_hashed():
    message = EmailMessage()
    message["From"] = "a@example.org"
    message.set_content("x")
    message.add_attachment(b"", maintype="application", subtype="octet-stream", filename="e.bin")
    assert extract_iocs(parse_email(message.as_bytes())).hashes == ()


def test_cap_truncates_and_flags(monkeypatch):
    monkeypatch.setattr(extractor, "MAX_PER_KIND", 3)
    text = " ".join(f"http://host{i}.example/" for i in range(10))
    iocs = extract_iocs(make_email(text))
    assert len(iocs.urls) == 3
    assert iocs.truncated


# ---------------------------------------------------------------- defanging


def test_defang_url():
    assert defang_url("https://evil.invalid/login.php") == "hxxps[://]evil[.]invalid/login.php"
    assert defang_url("ftp://files.example/a.zip") == "fxp[://]files[.]example/a.zip"
    assert (
        defang_url("http://user@evil.invalid:8080/p?u=http://other.example/x")
        == "hxxp[://]user[@]evil[.]invalid:8080/p?u=hxxp[://]other.example/x"
    )


def test_defanged_output_cannot_be_clicked():
    for url in (
        "https://evil.invalid/login",
        "http://198.51.100.7/a?r=https://x.example/y",
        "http://[2001:db8::1]/",
    ):
        out = defang_url(url)
        assert "://" not in out.replace("[://]", "")  # only the bracketed form is left
        assert "http" not in out.lower()


def test_defang_ip_and_domain():
    assert defang_ip("203.0.113.9") == "203[.]0[.]113[.]9"
    assert defang_domain("mail.example.com") == "mail[.]example[.]com"


def test_refang_round_trips_a_defanged_url():
    url = "https://evil.invalid/login"
    assert refang(defang_url(url)) == url
    assert refang("hxxp://a(.)example{.}org/x [at] y") == "http://a.example.org/x @ y"


def test_ioc_objects_expose_defanged_forms():
    iocs = extract_iocs(make_email("http://evil.invalid/x and 203.0.113.9"))
    assert iocs.urls[0].defanged == "hxxp[://]evil[.]invalid/x"
    assert iocs.ips[0].defanged == "203[.]0[.]113[.]9"
    assert [d.defanged for d in iocs.domains if d.domain == "evil.invalid"] == ["evil[.]invalid"]
