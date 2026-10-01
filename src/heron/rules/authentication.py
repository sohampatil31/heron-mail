"""SPF, DKIM and DMARC results recorded by the receiving mail server.

Heron doesn't re-run these checks. It reads what the mailbox provider
already recorded in Authentication-Results (RFC 8601).

Trust: only the TOPMOST Authentication-Results header counts. A receiving
server prepends its own result above everything else, so anything lower
could have been written by the sender, including a forged "spf=pass".
Received-SPF is used only as a fallback for the SPF result.
"""

from __future__ import annotations

import re

from heron.rules.base import Finding, RuleContext, Severity

RULE_ID = "auth"

_COMMENT_RE = re.compile(r"\([^()]*\)")
_RESULT_RE = re.compile(r"^\s*([A-Za-z][\w-]*)\s*=\s*([A-Za-z]+)")
_RECEIVED_SPF_RE = re.compile(
    r"^\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.IGNORECASE
)


def parse_authentication_results(value: str) -> tuple[str | None, dict[str, tuple[str, ...]]]:
    """Return (authserv-id, {method: (results...)}) with everything lowercased."""
    cleaned = value
    for _ in range(3):  # comments can nest a little
        cleaned = _COMMENT_RE.sub("", cleaned)
    first, *segments = cleaned.split(";")
    tokens = first.split()
    authserv = tokens[0].lower() if tokens else None
    results: dict[str, tuple[str, ...]] = {}
    for segment in segments:
        match = _RESULT_RE.match(segment)
        if match:
            method, result = match.group(1).lower(), match.group(2).lower()
            results[method] = (*results.get(method, ()), result)
    return authserv, results


def _best(results: tuple[str, ...] | None) -> str | None:
    """One result per method. Several DKIM signatures: any pass counts."""
    if not results:
        return None
    return "pass" if "pass" in results else results[0]


def check(ctx: RuleContext) -> list[Finding]:
    email = ctx.email
    headers = email.header_values("Authentication-Results")
    authserv, results = parse_authentication_results(headers[0]) if headers else (None, {})

    spf = _best(results.get("spf"))
    if spf is None:
        for value in email.header_values("Received-SPF")[:1]:
            match = _RECEIVED_SPF_RE.match(value)
            spf = match.group(1).lower() if match else None
    dkim = _best(results.get("dkim"))
    dmarc = _best(results.get("dmarc"))

    if not headers and spf is None:
        return [
            Finding(
                f"{RULE_ID}.no_results",
                Severity.INFO,
                "No authentication results",
                "The receiving server recorded no SPF, DKIM or DMARC results, "
                "so the sender could not be verified.",
            )
        ]

    reporter = (f"reported by {authserv}",) if authserv else ()
    findings: list[Finding] = []

    if dmarc == "fail":
        findings.append(
            Finding(
                f"{RULE_ID}.dmarc_fail",
                Severity.HIGH,
                "DMARC check failed",
                "The sending domain's own policy says this message was not authorised "
                "to use its From address.",
                ("dmarc=fail", *reporter),
            )
        )
    if spf == "fail":
        findings.append(
            Finding(
                f"{RULE_ID}.spf_fail",
                Severity.MEDIUM,
                "SPF check failed",
                "The server that sent this message is not on the domain's list of "
                "permitted senders.",
                ("spf=fail", *reporter),
            )
        )
    elif spf == "softfail":
        findings.append(
            Finding(
                f"{RULE_ID}.spf_fail",
                Severity.LOW,
                "SPF soft fail",
                "The sending server is probably not permitted to send for this domain.",
                ("spf=softfail", *reporter),
            )
        )
    if dkim == "fail":
        findings.append(
            Finding(
                f"{RULE_ID}.dkim_fail",
                Severity.MEDIUM,
                "DKIM signature invalid",
                "The message's cryptographic signature did not verify; "
                "it may have been altered or forged.",
                ("dkim=fail", *reporter),
            )
        )

    nothing_passed = "pass" not in (spf, dkim, dmarc)
    if not findings and nothing_passed:
        pairs = (("spf", spf), ("dkim", dkim), ("dmarc", dmarc))
        seen = tuple(f"{name}={value}" for name, value in pairs if value)
        findings.append(
            Finding(
                f"{RULE_ID}.unauthenticated",
                Severity.LOW,
                "No passing sender authentication",
                "Neither SPF, DKIM nor DMARC passed, so nothing confirms who sent this message.",
                (*seen, *reporter),
            )
        )
    return findings
