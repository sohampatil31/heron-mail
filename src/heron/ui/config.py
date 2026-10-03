"""UI settings, read from the environment."""

from __future__ import annotations

import os

from heron.ui.api_client import normalise_base_url

DEFAULT_API_URL = "http://127.0.0.1:8000"


def api_url() -> str:
    """HERON_API_URL, validated. Raises ValueError if it isn't a usable http(s) address."""
    return normalise_base_url(os.environ.get("HERON_API_URL", DEFAULT_API_URL))
