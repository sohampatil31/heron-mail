"""Reply-To pointing at a different organisation than From.

Replies to a message that claims to be from one company but asks you to
answer someone else are a staple of phishing and business email compromise.
Legitimate mail does this too (mailing platforms, support desks), so the
rule is MEDIUM, and HIGH only when the reply address is free webmail while
the sender is not.
"""

from __future__ import annotations

from heron.analysis.domains import is_freemail, registered_domain
from heron.rules.base import Finding, RuleContext, Severity

RULE_ID = "reply_to"


def check(ctx: RuleContext) -> list[Finding]:
    sender = ctx.email.from_address
    if sender is None or not sender.domain:
        return []
    sender_org = registered_domain(sender.domain)

    foreign = [
        address
        for address in ctx.email.reply_to
        if address.domain and registered_domain(address.domain) != sender_org
    ]
    if not foreign:
        return []

    webmail = any(is_freemail(a.domain) for a in foreign) and not is_freemail(sender.domain)
    detail = "Replies would go to a different domain than the one this message claims to come from."
    if webmail:
        detail += " The reply address is on a free webmail service."
    return [
        Finding(
            f"{RULE_ID}.mismatch",
            Severity.HIGH if webmail else Severity.MEDIUM,
            "Reply-To differs from sender",
            detail,
            (f"From: {sender.address}", *(f"Reply-To: {a.address}" for a in foreign)),
        )
    ]
