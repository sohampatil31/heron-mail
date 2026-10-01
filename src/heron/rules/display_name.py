"""Display-name spoofing: a From name that claims an identity the address doesn't have.

Mail clients show the display name prominently and the address barely at all,
so attackers put the identity they want you to trust in the name.

Two findings:
- address_mismatch (HIGH): the name itself contains an email address or web
  address on a different organisation's domain than the real sender,
  e.g. "security@your-bank.com" <noreply@mailer.example>.
- brand (MEDIUM): the name uses a well-known brand but the sender's domain
  isn't one that brand owns. The brand list below is a short starter set:
  extend BRAND_DOMAINS for the services your mailbox actually sees. A
  legitimate sender whose name merely contains a brand word (an "Apple
  Valley Dental") can trigger it, which is why it is not HIGH.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from heron.analysis.domains import registered_domain
from heron.rules.base import Finding, RuleContext, Severity

RULE_ID = "display_name"

# brand word -> registered domains that brand genuinely sends mail from.
BRAND_DOMAINS: dict[str, frozenset[str]] = {
    "microsoft": frozenset(
        {"microsoft.com", "microsoftonline.com", "office.com", "office365.com", "live.com",
         "outlook.com", "windows.com", "azure.com", "xbox.com", "skype.com"}
    ),
    "google": frozenset({"google.com", "gmail.com", "googlemail.com", "youtube.com"}),
    "apple": frozenset({"apple.com", "icloud.com", "me.com"}),
    "amazon": frozenset(
        {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.fr",
         "amazon.es", "amazon.it", "amazon.co.jp"}
    ),
    "paypal": frozenset({"paypal.com"}),
    "netflix": frozenset({"netflix.com"}),
    "dhl": frozenset({"dhl.com", "dhl.de"}),
    "fedex": frozenset({"fedex.com"}),
    "docusign": frozenset({"docusign.com", "docusign.net"}),
    "linkedin": frozenset({"linkedin.com"}),
    "facebook": frozenset({"facebook.com", "facebookmail.com", "meta.com"}),
    "instagram": frozenset({"instagram.com"}),
    "dropbox": frozenset({"dropbox.com", "dropboxmail.com"}),
    "adobe": frozenset({"adobe.com", "adobesign.com", "echosign.com"}),
    "zoom": frozenset({"zoom.us", "zoom.com"}),
    "github": frozenset({"github.com"}),
    "slack": frozenset({"slack.com"}),
    "whatsapp": frozenset({"whatsapp.com"}),
}  # fmt: skip

_ADDRESS_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})")
_WEB_ADDRESS_RE = re.compile(r"(?i)(?:https?://|www\.)[^\s<>\"]+")


def _claimed_domains(display_name: str) -> list[str]:
    domains = [match.group(1).lower() for match in _ADDRESS_RE.finditer(display_name)]
    for match in _WEB_ADDRESS_RE.finditer(display_name):
        raw = match.group(0)
        host = urlsplit(raw if "://" in raw else f"http://{raw}").hostname
        if host:
            domains.append(host)
    return domains


def check(ctx: RuleContext) -> list[Finding]:
    sender = ctx.email.from_address
    if sender is None or not sender.domain or not sender.display_name:
        return []
    sender_org = registered_domain(sender.domain)
    name = sender.display_name
    findings: list[Finding] = []

    foreign = sorted({d for d in _claimed_domains(name) if registered_domain(d) != sender_org})
    if foreign:
        findings.append(
            Finding(
                f"{RULE_ID}.address_mismatch",
                Severity.HIGH,
                "Sender name shows a different address",
                "The name displayed as the sender contains an address on another domain "
                "than the one this message was actually sent from.",
                (f"display name: {name}", f"actual sender: {sender.address}"),
            )
        )

    words = re.findall(r"[a-z0-9]+", name.lower())
    for brand, owned in BRAND_DOMAINS.items():
        mentioned = any(word == brand or re.fullmatch(rf"{brand}\d+", word) for word in words)
        if mentioned and sender_org not in owned:
            findings.append(
                Finding(
                    f"{RULE_ID}.brand",
                    Severity.MEDIUM,
                    f"Sender name uses the {brand.title()} brand",
                    f"The sender's name mentions {brand.title()}, but the message was sent "
                    "from a domain that brand does not use.",
                    (f"display name: {name}", f"actual sender: {sender.address}"),
                )
            )
            break  # one brand finding per message is enough
    return findings
