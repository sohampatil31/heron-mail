"""The Alerts page: browse alerts, read why Heron flagged one, and act on it.

Everything that came from an email (titles, evidence, rule details that quote a
file name) is shown with st.text() or escaped with md_safe(), never as live
markdown. The recommended-actions playbook is Heron's own text.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import streamlit as st

from heron.ui.alert_logic import (
    STATUS_FILTERS,
    available_moves,
    evidence_lines,
    option_label,
    reason_summary,
    status_label,
    timeline_lines,
)
from heron.ui.api_client import HeronClient
from heron.ui.safe import clean_text, md_safe

_FLASH = "alerts_flash"
_PAGE_SIZE = 50


def render(client: HeronClient, call: Callable[[Callable[[], Any]], Any]) -> None:
    st.title("Alerts")
    flash = st.session_state.pop(_FLASH, None)
    if flash:
        st.success(flash)

    mailboxes = call(client.list_mailboxes)
    filter_col, mailbox_col = st.columns([2, 1])
    shown = filter_col.radio("Show", list(STATUS_FILTERS), horizontal=True)
    names = ["All mailboxes", *(box["email_address"] for box in mailboxes)]
    choice = mailbox_col.selectbox("Mailbox", range(len(names)), format_func=lambda i: names[i])
    mailbox_id = None if choice == 0 else mailboxes[choice - 1]["id"]

    counts = call(lambda: client.alert_counts(mailbox_id))
    st.caption(
        " · ".join(f"{label} {counts.get(key, 0)}" for label, key in STATUS_FILTERS.items() if key)
    )
    alerts = call(
        lambda: client.list_alerts(
            mailbox_id=mailbox_id, status=STATUS_FILTERS[shown], limit=_PAGE_SIZE
        )
    )
    if not alerts:
        st.info("No alerts in this view.")
        return

    index = st.selectbox("Alert", range(len(alerts)), format_func=lambda i: option_label(alerts[i]))
    detail = call(lambda: client.get_alert(alerts[index]["id"]))
    _detail(client, call, detail)


def _detail(
    client: HeronClient, call: Callable[[Callable[[], Any]], Any], alert: dict[str, Any]
) -> None:
    st.divider()
    st.subheader(md_safe(alert["title"], 160))

    columns = st.columns(4)
    columns[0].metric("Verdict", alert["verdict"].title())
    columns[1].metric("Score", f"{alert['score']}/100")
    columns[2].metric("Severity", alert["severity"].title())
    columns[3].metric("Status", status_label(alert["status"]))
    if not alert.get("complete", True):
        st.warning("Some checks could not run, so this result may be incomplete.")

    st.text(f"From: {clean_text(alert.get('from_address') or '(unknown)', 200)}")
    st.text(f"Received: {alert.get('internal_date') or '(unknown)'} UTC")
    for line in timeline_lines(alert):
        st.text(line)

    st.markdown("#### Why Heron flagged it")
    for reason in alert["reasons"]:
        st.markdown(f"**{md_safe(reason_summary(reason), 160)}**")
        st.text(clean_text(reason["detail"], 400))
        for line in evidence_lines(reason):
            st.text(f"    {line}")

    st.markdown("#### What to do")
    for action in alert["actions"]:
        st.checkbox(
            md_safe(action["title"], 120),
            key=f"action_{alert['id']}_{action['id']}",
            help=clean_text(action["detail"], 400),
        )
    st.caption("These ticks are just for you while you work; they aren't saved.")

    moves = available_moves(alert["status"])
    if moves:
        st.markdown("#### Decide")
        for column, move in zip(st.columns(len(moves)), moves, strict=True):
            clicked = column.button(
                move.label,
                key=f"move_{alert['id']}_{move.target.value}",
                help=move.help,
                type="primary" if move.primary else "secondary",
            )
            if clicked:
                call(lambda m=move: client.set_alert_status(alert["id"], m.target.value))
                st.session_state[_FLASH] = (
                    f"Alert #{alert['id']} is now {status_label(move.target.value).lower()}."
                )
                st.rerun()
