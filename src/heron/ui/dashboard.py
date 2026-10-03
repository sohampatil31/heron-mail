"""The dashboard: KPIs, a timeline, and the newest open alerts. Defaults to today."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import streamlit as st

from heron.ui.api_client import HeronClient
from heron.ui.safe import clean_text

PERIODS = {"Today": 1, "Last 7 days": 7, "Last 30 days": 30}
_SERIES = ("Not flagged", "Suspicious", "Phishing")
_COLOURS = ("#9aa5b1", "#f2a900", "#d64545")
_RECENT_ALERTS = 5


def timeline_rows(buckets: list[dict[str, Any]], granularity: str) -> list[dict[str, Any]]:
    """Chart rows: every email counted once, as not flagged, suspicious or phishing."""
    rows = []
    for bucket in buckets:
        flagged = bucket["suspicious"] + bucket["phishing"]
        label = bucket["label"][11:] if granularity == "hour" else bucket["label"]
        rows.append(
            {
                "When": label,
                _SERIES[0]: max(bucket["emails"] - flagged, 0),
                _SERIES[1]: bucket["suspicious"],
                _SERIES[2]: bucket["phishing"],
            }
        )
    return rows


def alert_rows(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Table rows for st.dataframe, which shows text as text (never as markdown)."""
    return [
        {
            "Alert": alert["title"],
            "Severity": alert["severity"],
            "Score": alert["score"],
            "From": alert.get("from_address") or "",
            "Received (UTC)": alert.get("internal_date") or "",
        }
        for alert in alerts
    ]


def render(client: HeronClient, call: Callable[[Callable[[], Any]], Any]) -> None:
    st.title("Dashboard")
    mailboxes = call(client.list_mailboxes)

    period_col, mailbox_col = st.columns([2, 1])
    period = period_col.radio("Period", list(PERIODS), horizontal=True)
    names = ["All mailboxes", *(box["email_address"] for box in mailboxes)]
    choice = mailbox_col.selectbox("Mailbox", range(len(names)), format_func=lambda i: names[i])
    mailbox_id = None if choice == 0 else mailboxes[choice - 1]["id"]

    activity = call(lambda: client.get_activity(mailbox_id=mailbox_id, days=PERIODS[period]))
    counts = call(lambda: client.alert_counts(mailbox_id))

    where = f"{activity['start_date']}" + (
        "" if activity["start_date"] == activity["end_date"] else f" to {activity['end_date']}"
    )
    st.caption(f"{where} ({clean_text(activity['timezone'])})")

    flagged = activity["suspicious"] + activity["phishing"]
    columns = st.columns(5)
    columns[0].metric("Emails", activity["emails"])
    columns[1].metric("Flagged", flagged)
    columns[2].metric("Phishing", activity["phishing"])
    columns[3].metric("Not yet checked", activity["emails"] - activity["analysed"])
    columns[4].metric("Open alerts", counts.get("open", 0))

    if activity["emails"] == 0:
        st.info("No mail in this period yet. It appears here once a mailbox has been ingested.")
    else:
        st.subheader("Mail over time")
        st.bar_chart(
            timeline_rows(activity["buckets"], activity["granularity"]),
            x="When",
            y=list(_SERIES),
            color=list(_COLOURS),
        )

    st.subheader("Newest open alerts")
    alerts = call(
        lambda: client.list_alerts(mailbox_id=mailbox_id, status="open", limit=_RECENT_ALERTS)
    )
    if alerts:
        st.dataframe(alert_rows(alerts), hide_index=True)
    else:
        st.success("No open alerts.")
