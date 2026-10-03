import re

from heron.ui.safe import clean_text, escape_markdown, md_safe


def unescape(text: str) -> str:
    return re.sub(r"\\(.)", r"\1", text)


def test_clean_text_collapses_whitespace_and_removes_control_characters():
    assert clean_text("Pay\r\nnow\x00  please\t") == "Pay now please"
    assert clean_text("a\u202eb\u202cc") == "a b c"  # direction overrides can't hide text
    assert clean_text("   ") == ""


def test_clean_text_truncates_with_an_ellipsis():
    assert clean_text("x" * 50, max_len=10) == "x" * 9 + "…"
    assert clean_text("short", max_len=10) == "short"


def test_every_markdown_special_character_is_escaped():
    specials = "\\`*_{}[]()#+-.!|~<>&:$"
    escaped = escape_markdown(specials)
    assert unescape(escaped) == specials
    assert escaped == "".join("\\" + char for char in specials)


def test_image_link_and_directive_syntax_is_defused():
    for attack in (
        "![x](http://tracker.invalid/p.gif)",
        "[Click here](http://evil.invalid)",
        ":red[alert] :warning:",
        "$$ \\frac{1}{2} $$",
        "<img src=x onerror=alert(1)>",
    ):
        out = escape_markdown(attack)
        assert unescape(out) == attack
        for index, char in enumerate(out):
            if char in "[]()!<>$:" and (index == 0 or out[index - 1] != "\\"):
                raise AssertionError(f"unescaped {char!r} in {out!r}")


def test_plain_text_is_unchanged_apart_from_punctuation():
    assert escape_markdown("hello world 123") == "hello world 123"


def test_md_safe_cleans_then_escapes():
    assert md_safe("Pay *now*\r\n[x](y)") == "Pay \\*now\\* \\[x\\]\\(y\\)"
    assert md_safe("a" * 300, max_len=5) == "aaaa…"
