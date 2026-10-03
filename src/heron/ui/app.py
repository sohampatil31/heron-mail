"""The Heron dashboard shell: sign in, then navigate between pages.

Run from the repository root:

    streamlit run src/heron/ui/app.py

The API token lives only in Streamlit's server-side session, never in the
browser's URL or storage. Anything that came from an email is shown with
st.text() or st.dataframe(), never through markdown (see heron.ui.safe).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import streamlit as st

from heron.ui import mailbox_wizard
from heron.ui.api_client import ApiError, ApiUnreachable, HeronClient, Unauthorized
from heron.ui.auth import login
from heron.ui.config import api_url
from heron.ui.safe import clean_text

_CLIENT_KEY = "client"
_NOTICE_KEY = "notice"


def main() -> None:
    st.set_page_config(page_title="Heron", layout="wide")
    try:
        base_url = api_url()
    except ValueError as exc:  # HERON_API_URL is malformed
        st.error(str(exc))
        st.stop()

    client = st.session_state.get(_CLIENT_KEY)
    if client is None:
        _login_page(base_url)
    else:
        _shell(client)


# ----------------------------------------------------------------- sign in


def _login_page(base_url: str) -> None:
    st.title("Heron")
    st.caption("Self-hosted phishing detection for your inbox.")
    notice = st.session_state.pop(_NOTICE_KEY, None)
    if notice:
        st.warning(notice)

    with st.form("login"):
        token = st.text_input("API token", type="password")
        submitted = st.form_submit_button("Sign in")
    if submitted:
        result = login(base_url, token)
        if result.client is not None:
            st.session_state[_CLIENT_KEY] = result.client
            st.rerun()
        st.error(result.error)

    st.text(f"Server: {base_url}")
    st.caption("Your token is in data/api_token on the machine running Heron.")


def _sign_out() -> None:
    st.session_state.pop(_CLIENT_KEY, None)
    st.rerun()


# ------------------------------------------------------------------- shell


def _shell(client: HeronClient) -> None:
    pages: dict[str, Callable[[HeronClient], None]] = {
        "Overview": _overview,
        "Mailboxes": _mailboxes,
        "Add mailbox": lambda client: mailbox_wizard.render(client, _call),
    }
    with st.sidebar:
        st.header("Heron")
        page = st.radio("Go to", list(pages), label_visibility="collapsed")
        st.divider()
        _connection_status(client)
        if st.button("Sign out"):
            _sign_out()
    pages[page](client)


def _connection_status(client: HeronClient) -> None:
    try:
        client.health()
    except ApiUnreachable:
        st.error("API unreachable")
    except ApiError:
        st.warning("API error")
    else:
        st.success("API online")


def _call(fn: Callable[[], Any]) -> Any:
    """Run an API call; turn failures into a sign-out or a clear message."""
    try:
        return fn()
    except Unauthorized:
        st.session_state.pop(_CLIENT_KEY, None)
        st.session_state[_NOTICE_KEY] = "The API token was rejected. Please sign in again."
        st.rerun()
    except ApiUnreachable as exc:
        st.error(str(exc))
        st.stop()
    except ApiError as exc:
        st.error(clean_text(exc.message))
        st.stop()


# ------------------------------------------------------------------- pages


def _overview(client: HeronClient) -> None:
    st.title("Overview")
    mailboxes = _call(client.list_mailboxes)
    stats = _call(client.get_stats)
    counts = _call(client.alert_counts)

    columns = st.columns(4)
    columns[0].metric("Mailboxes", len(mailboxes))
    columns[1].metric("Emails stored", stats.get("total_emails", 0))
    columns[2].metric("Last 24 hours", stats.get("emails_last_24h", 0))
    columns[3].metric("Open alerts", counts.get("open", 0))


def _mailboxes(client: HeronClient) -> None:
    st.title("Mailboxes")
    mailboxes = _call(client.list_mailboxes)
    if not mailboxes:
        st.info("No mailboxes have been added yet.")
        return
    st.dataframe(
        [
            {
                "Address": box["email_address"],
                "IMAP host": box["imap_host"],
                "Port": box["imap_port"],
                "Added (UTC)": box["created_at"],
            }
            for box in mailboxes
        ],
        hide_index=True,
    )


if __name__ == "__main__":
    main()
