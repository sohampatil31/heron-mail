"""Link text that shows one website but points at another.

    <a href="http://198.51.100.7/login">https://www.your-bank.com/login</a>

The reader sees and trusts the text; the click goes to the href. This is
MEDIUM by default because bulk mailers legitimately wrap links in tracking
redirects. It is HIGH when the real target is a raw IP address, hides behind
a user@host trick, or uses a punycode (lookalike-character) domain, none of
which a tracking redirect needs.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from heron.analysis.domains import registered_domain
from heron.analysis.extractor import ExtractedUrl
from heron.rules.base import Finding, RuleContext, Severity

RULE_ID = "link"

MAX_EVIDENCE = 5
_MAX_TEXT = 80

_SHOWN_URL_RE = re.compile(r"(?i)(?:https?://|www\.)[^\s<>\"]+")
_BARE_DOMAIN_RE = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,}(?:[/?#]\S*)?")


def _shown_host(text: str) -> str | None:
    """The website address a link's visible text claims, if it shows one."""
    text = text.strip()
    match = _SHOWN_URL_RE.search(text)
    if match:
        raw = match.group(0)
        try:
            return urlsplit(raw if "://" in raw else f"http://{raw}").hostname
        except ValueError:
            return None
    if _BARE_DOMAIN_RE.fullmatch(text.lower()):  # the whole text is just "bank.com/login"
        return text.lower().split("/")[0].split("?")[0].split("#")[0]
    return None


def _mismatch(shown_host: str, url: ExtractedUrl) -> bool:
    target = url.ip or url.host
    if not target:
        return False
    if url.ip:  # target is an address: only the same address matches
        return shown_host.strip(".") != url.ip
    return registered_domain(shown_host) != registered_domain(target)


def _is_dangerous_target(url: ExtractedUrl) -> bool:
    return bool(url.ip or url.has_userinfo or url.host.startswith("xn--") or ".xn--" in url.host)


def check(ctx: RuleContext) -> list[Finding]:
    evidence: list[str] = []
    severity = Severity.MEDIUM
    for url in ctx.iocs.urls:
        for text in url.link_texts:
            shown = _shown_host(text)
            if shown is None or not _mismatch(shown, url):
                continue
            if _is_dangerous_target(url):
                severity = Severity.HIGH
            if len(evidence) < MAX_EVIDENCE:
                evidence.append(f'shows "{text[:_MAX_TEXT]}" but goes to {url.defanged}')
    if not evidence:
        return []
    return [
        Finding(
            f"{RULE_ID}.text_mismatch",
            severity,
            "Link text doesn't match its destination",
            "A link displays one website address but actually leads to a different site.",
            tuple(evidence),
        )
    ]
