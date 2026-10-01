"""Risky attachments, judged from metadata only.

Nothing is opened or scanned: the decision uses the file name, its extensions
and the declared content type that the parser already recorded. A file name is
sender-controlled, so an innocent-looking name proves nothing; but a risky
one is a strong signal.

Per attachment, at most one of double_extension / executable fires (the
double-extension finding is the more specific), alongside any of the others.
"""

from __future__ import annotations

from heron.analysis.parser import AttachmentInfo
from heron.rules.base import Finding, RuleContext, Severity

RULE_ID = "attachment"

MAX_ATTACHMENTS_CHECKED = 20

EXECUTABLE_EXTENSIONS = frozenset(
    {"exe", "scr", "com", "pif", "bat", "cmd", "msi", "msp", "js", "jse", "vbs", "vbe", "wsf",
     "wsh", "ps1", "psm1", "jar", "hta", "lnk", "cpl", "reg", "dll", "sys", "inf", "scf", "chm",
     "gadget", "url"}
)  # fmt: skip
DOCUMENT_LOOKING_EXTENSIONS = frozenset(
    {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "jpg", "jpeg",
     "png", "gif"}
)  # fmt: skip
MACRO_EXTENSIONS = frozenset({"docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "xlsb"})
DISK_IMAGE_EXTENSIONS = frozenset({"iso", "img", "vhd", "vhdx"})
HTML_EXTENSIONS = frozenset({"html", "htm", "shtml", "xhtml"})
ARCHIVE_EXTENSIONS = frozenset({"zip", "rar", "7z", "gz", "tgz", "tar", "cab", "z", "bz2", "xz"})
EXECUTABLE_CONTENT_TYPES = frozenset(
    {"application/x-msdownload", "application/x-dosexec", "application/x-msdos-program",
     "application/vnd.microsoft.portable-executable", "application/x-executable"}
)  # fmt: skip

# Characters that reorder how a file name is displayed: "invoice\u202Egpj.exe"
# shows as "invoiceexe.jpg".
_BIDI_CONTROLS = frozenset("\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


def _safe_name(name: str | None) -> str:
    """The file name with invisible characters written out, safe to display."""
    if name is None:
        return "(no file name)"
    return "".join(
        f"\\u{ord(char):04x}" if char in _BIDI_CONTROLS or not char.isprintable() else char
        for char in name
    )


def _finding(kind: str, severity: Severity, title: str, detail: str, a: AttachmentInfo) -> Finding:
    return Finding(
        f"{RULE_ID}.{kind}",
        severity,
        title,
        detail,
        (f"file: {_safe_name(a.filename)}", f"type: {a.content_type}"),
    )


def _check_one(a: AttachmentInfo) -> list[Finding]:
    findings: list[Finding] = []
    extensions = a.extensions
    last = a.extension
    declared_executable = a.content_type in EXECUTABLE_CONTENT_TYPES
    is_executable = last in EXECUTABLE_EXTENSIONS or (a.filename is None and declared_executable)

    if a.filename and any(char in _BIDI_CONTROLS for char in a.filename):
        findings.append(
            _finding(
                "bidi_filename",
                Severity.HIGH,
                "Attachment name uses hidden text-direction characters",
                "The file name contains invisible characters that disguise its real extension.",
                a,
            )
        )

    if is_executable:
        if len(extensions) >= 2 and extensions[-2] in DOCUMENT_LOOKING_EXTENSIONS:
            findings.append(
                _finding(
                    "double_extension",
                    Severity.HIGH,
                    "Program disguised as a document",
                    f"The file name ends in two extensions (.{extensions[-2]}.{last}) so a "
                    "program looks like a document.",
                    a,
                )
            )
        else:
            findings.append(
                _finding(
                    "executable",
                    Severity.HIGH,
                    "Executable attachment",
                    "This attachment is a program or script that runs code when opened.",
                    a,
                )
            )
    elif declared_executable:
        findings.append(
            _finding(
                "type_mismatch",
                Severity.MEDIUM,
                "Attachment type doesn't match its name",
                "The file name looks harmless but the message declares it to be a Windows program.",
                a,
            )
        )

    if last in MACRO_EXTENSIONS:
        findings.append(
            _finding(
                "macro_document",
                Severity.MEDIUM,
                "Macro-enabled Office file",
                "This Office file can contain macros, a common way to deliver malware.",
                a,
            )
        )
    elif last in DISK_IMAGE_EXTENSIONS:
        findings.append(
            _finding(
                "disk_image",
                Severity.MEDIUM,
                "Disk image attachment",
                "Disk images are used to slip files past download protections.",
                a,
            )
        )
    elif last in HTML_EXTENSIONS:
        findings.append(
            _finding(
                "html_file",
                Severity.MEDIUM,
                "HTML attachment",
                "An HTML attachment can show a fake login page that runs from your own computer.",
                a,
            )
        )
    elif last in ARCHIVE_EXTENSIONS:
        findings.append(
            _finding(
                "archive",
                Severity.LOW,
                "Archive attachment",
                "Archives can hide other files from scanners; check what is inside before opening.",
                a,
            )
        )
    return findings


def check(ctx: RuleContext) -> list[Finding]:
    findings: list[Finding] = []
    for attachment in ctx.email.attachments[:MAX_ATTACHMENTS_CHECKED]:
        findings.extend(_check_one(attachment))
    return findings
