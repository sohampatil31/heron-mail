"""Making untrusted text safe to show.

Subjects, senders, evidence and error messages all come from outside. Streamlit
renders markdown, so an attacker-chosen subject like "![x](http://tracker/p.gif)"
would load a remote image the moment an analyst looks at it, and
"[Click](http://evil)" would become a link. Show email-derived text with
st.text() or st.dataframe(), or pass it through md_safe() before it goes
anywhere that renders markdown.
"""

from __future__ import annotations

import re

# Control characters plus invisible direction overrides, which can make text
# read differently from what it is.
_UNSAFE_CHARS = re.compile(r"[\x00-\x1f\x7f\u200e\u200f\u202a-\u202e\u2066-\u2069]")
# Everything Markdown, Streamlit's :color[text] / :emoji: syntax, or LaTeX ($)
# could treat as formatting.
_MARKDOWN_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|~<>&:$])")


def clean_text(text: str, max_len: int = 200) -> str:
    """One line, no control or direction characters, cut to max_len."""
    cleaned = " ".join(_UNSAFE_CHARS.sub(" ", text).split())
    if len(cleaned) > max_len:
        return cleaned[: max_len - 1].rstrip() + "…"
    return cleaned


def escape_markdown(text: str) -> str:
    """Backslash-escape every character that markdown could act on."""
    return _MARKDOWN_SPECIAL.sub(r"\\\1", text)


def md_safe(text: str, max_len: int = 200) -> str:
    """clean_text() then escape_markdown(): safe inside st.markdown()."""
    return escape_markdown(clean_text(text, max_len))
