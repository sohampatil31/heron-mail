"""Raw message in, finished Analysis out: parse, extract, run rules, score.

This is the one function the worker (and later the alert code) calls. It is
pure and does no I/O, so a stored .eml can be re-analysed at any time, for
example after the rules change.
"""

from __future__ import annotations

from dataclasses import dataclass

from heron.analysis.extractor import Iocs, extract_iocs
from heron.analysis.parser import ParsedEmail, parse_email
from heron.analysis.scoring import Assessment, assess
from heron.rules.base import RuleContext
from heron.rules.registry import run_rules


@dataclass(frozen=True, slots=True)
class Analysis:
    email: ParsedEmail
    iocs: Iocs
    assessment: Assessment


def analyze(raw: bytes) -> Analysis:
    email = parse_email(raw)
    iocs = extract_iocs(email)
    results = run_rules(RuleContext(email, iocs))
    return Analysis(email=email, iocs=iocs, assessment=assess(results))
