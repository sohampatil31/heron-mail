"""A thin, read-only wrapper around imapclient.IMAPClient.

Every folder is opened with EXAMINE (never SELECT) and every fetch uses
BODY.PEEK[], so Heron never marks a message as read, or changes anything
else on the server - see ARCHITECTURE.md's "read-only mailbox access"
decision. This module only knows how to talk to one mailbox at a time; the
collector (Day 7+) is what will loop over accounts and decide what to fetch.
"""

from __future__ import annotations

import contextlib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from imapclient import IMAPClient
from imapclient.exceptions import IMAPClientError


class ImapConnectionError(Exception):
    """Raised when connecting, logging in, or talking to the server fails.

    Covers unreachable hosts, wrong host/port, and rejected credentials
    (imapclient does not expose a distinct exception type for the last one -
    a rejected login and a protocol error both surface as an
    IMAPClientError, so both are normalized to this one exception here).
    """


@dataclass(frozen=True, slots=True)
class FolderInfo:
    """What EXAMINE reports about a folder."""

    uidvalidity: int
    exists: int


@dataclass(frozen=True, slots=True)
class FetchedMessage:
    """One fetched message: its raw bytes and the server's INTERNALDATE for it.

    internal_date is timezone-aware (imapclient parses the IMAP INTERNALDATE
    into an aware datetime), so it is safe to pass directly into
    core.timeutil / core.storage without further conversion.
    """

    raw_bytes: bytes
    internal_date: datetime


class ImapClient:
    """Read-only IMAP access to one mailbox.

    Usage:
        with ImapClient(host, email_address, password) as client:
            info = client.select_folder_readonly("INBOX")
            uids = client.search_uids(["ALL"])
            messages = client.fetch_messages(uids)
    """

    def __init__(
        self,
        host: str,
        email_address: str,
        password: str,
        *,
        port: int = 993,
        use_ssl: bool = True,
        timeout: int = 30,
    ) -> None:
        self._host = host
        self._email_address = email_address
        self._password = password
        self._port = port
        self._use_ssl = use_ssl
        self._timeout = timeout
        self._conn: IMAPClient | None = None

    def __enter__(self) -> ImapClient:
        self.connect()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def connect(self) -> None:
        """Open the connection and log in. Safe to call again if already connected."""
        if self._conn is not None:
            return
        try:
            conn = IMAPClient(self._host, port=self._port, ssl=self._use_ssl, timeout=self._timeout)
        except OSError as exc:
            raise ImapConnectionError(f"could not reach {self._host}:{self._port}: {exc}") from exc

        try:
            conn.login(self._email_address, self._password)
        except IMAPClientError as exc:
            with contextlib.suppress(Exception):
                conn.shutdown()
            raise ImapConnectionError(
                "login failed - check the email address and app password"
            ) from exc

        self._conn = conn

    def close(self) -> None:
        """Log out and drop the connection. Safe to call even if never connected."""
        if self._conn is None:
            return
        with contextlib.suppress(Exception):
            self._conn.logout()
        self._conn = None

    def list_folders(self) -> list[str]:
        """Return the mailbox's folder names."""
        conn = self._require_connection()
        try:
            return [name for _flags, _delimiter, name in conn.list_folders()]
        except (OSError, IMAPClientError) as exc:
            raise ImapConnectionError(f"could not list folders: {exc}") from exc

    def select_folder_readonly(self, folder: str) -> FolderInfo:
        """EXAMINE a folder (never SELECT), so nothing about it can be modified.

        UIDVALIDITY is part of Heron's deduplication key (see
        core/models.py): if the server ever resets it for a folder, existing
        UIDs are no longer guaranteed to mean the same message, so a changed
        UIDVALIDITY should be treated as "re-fetch this folder", not merged
        with prior data under the old value.
        """
        conn = self._require_connection()
        try:
            info = conn.select_folder(folder, readonly=True)
        except (OSError, IMAPClientError) as exc:
            raise ImapConnectionError(f"could not open folder {folder!r}: {exc}") from exc
        return FolderInfo(uidvalidity=info[b"UIDVALIDITY"], exists=info[b"EXISTS"])

    def search_uids(self, criteria: Sequence[str]) -> list[int]:
        """Return UIDs matching an IMAP search, e.g. ["SINCE", date, "BEFORE", date]."""
        conn = self._require_connection()
        try:
            return conn.search(criteria)
        except (OSError, IMAPClientError) as exc:
            raise ImapConnectionError(f"search failed: {exc}") from exc

    def fetch_messages(self, uids: Sequence[int]) -> dict[int, FetchedMessage]:
        """Fetch raw message bytes and INTERNALDATE for the given UIDs.

        Uses BODY.PEEK[] rather than BODY[]: the latter implicitly sets the
        \\Seen flag on the server, which BODY.PEEK[] does not. An empty
        `uids` returns {} without making a request, since IMAP FETCH with no
        message set is at best a no-op and at worst a protocol error
        depending on the server.
        """
        if not uids:
            return {}
        conn = self._require_connection()
        try:
            raw = conn.fetch(uids, ["BODY.PEEK[]", "INTERNALDATE"])
        except (OSError, IMAPClientError) as exc:
            raise ImapConnectionError(f"fetch failed: {exc}") from exc
        return {
            uid: FetchedMessage(raw_bytes=data[b"BODY[]"], internal_date=data[b"INTERNALDATE"])
            for uid, data in raw.items()
        }

    def _require_connection(self) -> IMAPClient:
        if self._conn is None:
            raise ImapConnectionError("not connected - call connect() first")
        return self._conn
