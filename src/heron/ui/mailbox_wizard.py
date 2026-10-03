"""The "Add a mailbox" page: pick a provider, test the login, then save.

Saving is only possible after a successful test of exactly the settings in
the form. Change anything and the test must be repeated.

The password lives only in this Streamlit session's widget state. After a
successful save the widgets are re-keyed, which discards it.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import streamlit as st

from heron.ui.api_client import HeronClient
from heron.ui.providers import (
    OTHER,
    PROVIDERS,
    clean_app_password,
    fingerprint,
    suggest_provider,
    validate_mailbox,
)
from heron.ui.safe import clean_text, md_safe

_COUNTER = "mailbox_form_counter"  # bumping it gives fresh, empty widgets
_TESTED = "mailbox_form_tested"  # fingerprint of the settings that passed a test
_ADDED = "mailbox_form_added"  # address to confirm after a save


def render(client: HeronClient, call: Callable[[Callable[[], Any]], Any]) -> None:
    """`call` runs an API call and handles sign-out and error display (see app._call)."""
    st.title("Add a mailbox")
    st.caption("Heron connects read-only. It never changes, moves or deletes your mail.")

    added = st.session_state.pop(_ADDED, None)
    if added:
        st.success(f"Added {md_safe(added)}. It will appear under Mailboxes.")

    n = st.session_state.get(_COUNTER, 0)
    email = st.text_input("Email address", key=f"mb_email_{n}").strip()

    suggestion = suggest_provider(email)
    options = (*PROVIDERS, OTHER)
    provider = st.selectbox(
        "Provider",
        options,
        index=options.index(suggestion or OTHER),
        format_func=lambda p: p.name,
        key=f"mb_provider_{n}_{suggestion.key if suggestion else 'none'}",
    )
    st.info(provider.help)

    host = st.text_input("IMAP server", value=provider.host, key=f"mb_host_{n}_{provider.key}")
    port = int(
        st.number_input(
            "Port",
            min_value=1,
            max_value=65535,
            value=provider.port,
            step=1,
            key=f"mb_port_{n}_{provider.key}",
        )
    )
    password = clean_app_password(
        provider.key,
        st.text_input("Password or app password", type="password", key=f"mb_pw_{n}"),
    )

    check = validate_mailbox(email, host, port, password)
    for message in check.errors if email or host != provider.host or password else ():
        st.caption(f"• {message}")
    for message in check.warnings:
        st.warning(message)

    current = fingerprint(email, host, port, password)
    tested = st.session_state.get(_TESTED) == current

    test_col, save_col = st.columns(2)
    if test_col.button("Test connection", disabled=not check.ok):
        result = call(lambda: client.test_mailbox_settings(email, host.strip(), port, password))
        if isinstance(result, dict) and result.get("ok"):
            st.session_state[_TESTED] = current
            tested = True
        else:
            st.session_state.pop(_TESTED, None)
            tested = False
            reason = result.get("error") if isinstance(result, dict) else None
            st.error(f"Could not sign in: {clean_text(reason or 'unknown error')}")
    if tested:
        st.success("The login works. You can save this mailbox.")

    if save_col.button("Save mailbox", type="primary", disabled=not (check.ok and tested)):
        box = call(lambda: client.create_mailbox(email, host.strip(), port, password))
        st.session_state[_COUNTER] = n + 1
        st.session_state.pop(_TESTED, None)
        st.session_state[_ADDED] = box.get("email_address", email)
        st.rerun()
