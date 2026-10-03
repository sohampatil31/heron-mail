from heron.ui.providers import (
    OTHER,
    PROVIDERS,
    clean_app_password,
    fingerprint,
    suggest_provider,
    validate_mailbox,
)


def test_presets_are_complete_and_use_tls_port_993():
    assert len({p.key for p in PROVIDERS}) == len(PROVIDERS)
    for provider in PROVIDERS:
        assert provider.host and "." in provider.host
        assert provider.port == 993
        assert provider.help
        assert provider.domains
    assert (OTHER.host, OTHER.port) == ("", 993)


def test_domains_are_not_shared_between_presets():
    domains = [d for p in PROVIDERS for d in p.domains]
    assert len(domains) == len(set(domains))


def test_suggest_provider_by_address_domain():
    assert suggest_provider("me@gmail.com").key == "gmail"
    assert suggest_provider("  Me@GMAIL.com ").key == "gmail"
    assert suggest_provider("a@hotmail.com").key == "outlook"
    assert suggest_provider("a@yahoo.co.in").key == "yahoo"
    assert suggest_provider("a@me.com").key == "icloud"
    assert suggest_provider("a@zoho.in").key == "zoho"
    assert suggest_provider("a@fastmail.com").key == "fastmail"


def test_suggest_provider_returns_none_when_unknown_or_incomplete():
    assert suggest_provider("a@example.org") is None
    assert suggest_provider("a@mail.gmail.com.evil.invalid") is None  # must match exactly
    assert suggest_provider("") is None
    assert suggest_provider("gmail.com") is not None  # no "@": treated as the domain
    assert suggest_provider("not an address") is None


def test_gmail_app_password_spaces_are_removed():
    assert clean_app_password("gmail", "abcd efgh ijkl mnop") == "abcdefghijklmnop"
    assert clean_app_password("gmail", "  abcdefghijklmnop ") == "abcdefghijklmnop"


def test_other_passwords_are_left_exactly_as_typed():
    assert clean_app_password("gmail", "my pass word") == "my pass word"
    assert clean_app_password("gmail", "ABCD EFGH IJKL MNOP") == "ABCD EFGH IJKL MNOP"
    assert clean_app_password("yahoo", "abcd efgh ijkl mnop") == "abcd efgh ijkl mnop"
    assert clean_app_password("other", " padded ") == " padded "


def test_valid_input_has_no_errors_or_warnings():
    result = validate_mailbox("me@example.org", "imap.example.org", 993, "secret")
    assert result.ok
    assert result.errors == result.warnings == ()


def test_each_problem_is_reported():
    result = validate_mailbox("nope", "", 0, "")
    assert not result.ok
    assert len(result.errors) == 4


def test_email_validation():
    for bad in ("", "name", "name@", "@example.org", "a b@example.org", "a@b@c"):
        assert not validate_mailbox(bad, "imap.example.org", 993, "x").ok, bad
    assert validate_mailbox(" me@example.org ", "imap.example.org", 993, "x").ok


def test_host_validation():
    for bad in (
        "imap.example.org:993",
        "https://imap.example.org",
        "imap example.org",
        "imap.example.org/",
        "-bad.example.org",
        "bad-.example.org",
        "a..b",
        "x" * 300,
    ):
        assert not validate_mailbox("me@example.org", bad, 993, "x").ok, bad
    for good in ("imap.example.org", "localhost", "10.0.0.5", "mail-1.example.co.uk"):
        assert validate_mailbox("me@example.org", good, 993, "x").ok, good


def test_port_range_and_non_tls_warning():
    assert not validate_mailbox("me@example.org", "h.example.org", 65536, "x").ok
    unusual = validate_mailbox("me@example.org", "h.example.org", 143, "x")
    assert unusual.ok
    assert len(unusual.warnings) == 1
    assert "993" in unusual.warnings[0]


def test_password_whitespace_is_not_trimmed_by_validation():
    assert validate_mailbox("me@example.org", "h.example.org", 993, "  ").ok


def test_fingerprint_changes_with_any_setting_and_hides_the_password():
    base = ("me@example.org", "imap.example.org", 993, "secret")
    original = fingerprint(*base)
    assert fingerprint(*base) == original
    assert fingerprint("other@example.org", *base[1:]) != original
    assert fingerprint(base[0], "imap.other.org", 993, "secret") != original
    assert fingerprint(base[0], base[1], 143, "secret") != original
    assert fingerprint(*base[:3], "Secret") != original
    assert "secret" not in original
    # Case and padding in the address and host don't count as a change.
    assert fingerprint(" ME@example.org ", " IMAP.example.org", 993, "secret") == original
