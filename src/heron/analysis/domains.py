"""Small domain helpers shared by the rules.

registered_domain() answers "which organisation owns this hostname?", so
mail.example.com and example.com compare as the same sender while
example.co.uk and evil.co.uk do not.

It uses a short built-in list of multi-part suffixes instead of the full
Public Suffix List, so it is offline and dependency-free but approximate.
A rare suffix missing from the list makes two unrelated sites look like one
organisation (or the reverse). If that ever matters, swap the body of
registered_domain() for a real PSL library; its callers won't change.
"""

from __future__ import annotations

# Public suffixes with more than one label. The registrable name is one label
# above these: news.example.co.uk -> example.co.uk.
_MULTI_LABEL_SUFFIXES = frozenset(
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "org.nz", "net.nz", "govt.nz",
        "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
        "co.kr", "or.kr", "go.kr", "co.in", "net.in", "org.in", "ac.in", "gov.in",
        "co.za", "org.za", "co.il", "org.il",
        "com.br", "net.br", "org.br", "gov.br",
        "com.cn", "net.cn", "org.cn", "gov.cn", "com.hk", "com.tw", "com.sg", "com.my",
        "com.mx", "com.ar", "com.co", "com.pe", "com.tr", "com.ua", "com.pl", "com.ng",
        "com.eg", "com.sa", "com.pk", "com.ph", "com.vn", "co.id", "co.th",
    }
)  # fmt: skip

# Hosting platforms where every customer gets a subdomain. Treating them as
# public suffixes keeps evil.pages.dev and benign.pages.dev apart.
_HOSTING_SUFFIXES = frozenset(
    {
        "github.io", "gitlab.io", "pages.dev", "workers.dev", "netlify.app", "vercel.app",
        "web.app", "firebaseapp.com", "herokuapp.com", "blogspot.com", "wordpress.com",
        "azurewebsites.net", "cloudfront.net", "appspot.com", "onrender.com", "glitch.me",
        "weebly.com", "wixsite.com", "sites.google.com", "s3.amazonaws.com",
    }
)  # fmt: skip

_SUFFIXES = _MULTI_LABEL_SUFFIXES | _HOSTING_SUFFIXES

# Free webmail: anyone can register an address, so it says nothing about an
# organisation. A business sender with a webmail Reply-To is a classic scam.
FREEMAIL_DOMAINS = frozenset(
    {
        "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "yahoo.co.in", "ymail.com",
        "outlook.com", "hotmail.com", "hotmail.co.uk", "live.com", "msn.com", "aol.com",
        "icloud.com", "me.com", "mac.com", "proton.me", "protonmail.com", "pm.me",
        "gmx.com", "gmx.net", "gmx.de", "mail.com", "zoho.com", "yandex.com", "yandex.ru",
        "mail.ru", "qq.com", "163.com", "126.com", "tutanota.com", "tuta.com",
    }
)  # fmt: skip


def registered_domain(domain: str) -> str:
    """The organisation-level name for a hostname, lowercased."""
    labels = domain.lower().strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    for size in (3, 2):  # longest suffix first: s3.amazonaws.com before amazonaws.com
        if size < len(labels) and ".".join(labels[-size:]) in _SUFFIXES:
            return ".".join(labels[-(size + 1) :])
    return ".".join(labels[-2:])


def is_freemail(domain: str) -> bool:
    return domain.lower().strip(".") in FREEMAIL_DOMAINS
