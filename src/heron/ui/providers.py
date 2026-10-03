"""Mail provider presets and the checks behind the add-mailbox form.

Pure logic with no Streamlit in it, so it can be tested on its own.

Heron reads mail over IMAP with TLS (normally port 993), read-only. Most
big providers no longer accept your normal password for that: you create an
"app password" and use it here instead. The help text says so per provider.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Provider:
    key: str
    name: str
    host: str
    port: int
    domains: tuple[str, ...]  # email domains that identify this provider
    help: str


PROVIDERS: tuple[Provider, ...] = (
    Provider(
        "gmail", "Gmail", "imap.gmail.com", 993, ("gmail.com", "googlemail.com"),
        "Turn on 2-Step Verification in your Google account, then create an App password "
        "and paste it below. Your normal Google password will not work.",
    ),
    Provider(
        "outlook", "Outlook / Hotmail / Microsoft 365", "outlook.office365.com", 993,
        ("outlook.com", "hotmail.com", "live.com", "msn.com"),
        "Microsoft is moving IMAP away from passwords. If sign-in fails, your account may "
        "require OAuth, which Heron doesn't support yet. Use an app password if your "
        "account offers one.",
    ),
    Provider(
        "yahoo", "Yahoo Mail", "imap.mail.yahoo.com", 993,
        ("yahoo.com", "ymail.com", "yahoo.co.in", "yahoo.co.uk"),
        "Create an app password in Yahoo Account Security and use it instead of your "
        "normal password.",
    ),
    Provider(
        "icloud", "iCloud Mail", "imap.mail.me.com", 993, ("icloud.com", "me.com", "mac.com"),
        "Create an app-specific password in your Apple Account settings (two-factor "
        "authentication must be on) and use your full iCloud address as the email.",
    ),
    Provider(
        "zoho", "Zoho Mail", "imap.zoho.com", 993, ("zoho.com", "zoho.in"),
        "Create an application-specific password in Zoho's security settings. Accounts in "
        "India or the EU use a regional server: change the server to imap.zoho.in or "
        "imap.zoho.eu if sign-in fails.",
    ),
    Provider(
        "fastmail", "Fastmail", "imap.fastmail.com", 993, ("fastmail.com", "fastmail.fm"),
        "Create an app password in Fastmail's Privacy & Security settings with IMAP access.",
    ),
)  # fmt: skip

OTHER = Provider(
    "other", "Other (enter manually)", "", 993, (),
    "Use your provider's IMAP server name and its TLS port (usually 993). Heron connects "
    "read-only and never changes, moves or deletes mail.",
)  # fmt: skip

_BY_DOMAIN = {domain: provider for provider in PROVIDERS for domain in provider.domains}
_GMAIL_APP_PASSWORD = re.compile(r"[a-z]{4}( ?[a-z]{4}){3}")
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+")
_HOST = re.compile(
    r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*"
)


def suggest_provider(email_address: str) -> Provider | None:
    """The preset matching an address's domain, if there is one."""
    _, _, domain = email_address.strip().lower().rpartition("@")
    return _BY_DOMAIN.get(domain)


def clean_app_password(provider_key: str, password: str) -> str:
    """Gmail shows app passwords as 'abcd efgh ijkl mnop'; remove those spaces.

    Only that exact shape is touched, and only for Gmail: a password's
    whitespace can be significant everywhere else.
    """
    candidate = password.strip()
    if provider_key == "gmail" and _GMAIL_APP_PASSWORD.fullmatch(candidate):
        return candidate.replace(" ", "")
    return password


@dataclass(frozen=True, slots=True)
class Validation:
    errors: tuple[str, ...]
    warnings: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.errors


def validate_mailbox(email_address: str, host: str, port: int, password: str) -> Validation:
    errors: list[str] = []
    warnings: list[str] = []
    if not _EMAIL.fullmatch(email_address.strip()):
        errors.append("Enter the full email address, like name@example.com.")
    host = host.strip()
    if not host:
        errors.append("Enter the IMAP server name.")
    elif ":" in host or "/" in host or " " in host:
        errors.append("Enter just the server name, like imap.example.com. The port goes below.")
    elif not _HOST.fullmatch(host):
        errors.append("That doesn't look like a valid server name.")
    if not 1 <= port <= 65535:
        errors.append("The port must be between 1 and 65535.")
    elif port != 993:
        warnings.append(
            "Heron connects with TLS from the first byte, which is port 993 almost "
            "everywhere. Other ports often fail."
        )
    if not password:
        errors.append("Enter the password or app password.")
    return Validation(tuple(errors), tuple(warnings))


def fingerprint(email_address: str, host: str, port: int, password: str) -> str:
    """A one-way digest of the settings, to tell whether they changed since the test.

    Lets the form insist that exactly what was tested is what gets saved,
    without keeping the password around a second time.
    """
    parts = (email_address.strip().lower(), host.strip().lower(), str(port), password)
    material = "\x00".join(parts)
    return hashlib.sha256(material.encode()).hexdigest()
