"""Request and response shapes for the API.

MailboxOut deliberately has no password field of any kind, not even the
encrypted one. Responses are built from it (never from a raw database row),
so a stored secret cannot leak by accident when a column is added later.
"""

from datetime import date
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, SecretStr, StringConstraints, field_validator

_TrimmedText = Annotated[str, StringConstraints(strip_whitespace=True)]


class MailboxCreate(BaseModel):
    email_address: Annotated[_TrimmedText, Field(min_length=3, max_length=254)]
    imap_host: Annotated[_TrimmedText, Field(min_length=1, max_length=253)]
    imap_port: int = Field(default=993, ge=1, le=65535)
    # SecretStr keeps the value out of reprs and logs. It is not stripped:
    # a password's whitespace can be significant.
    password: SecretStr

    @field_validator("email_address")
    @classmethod
    def _looks_like_an_email_address(cls, value: str) -> str:
        local_part, _, domain = value.partition("@")
        if not local_part or not domain:
            raise ValueError("must look like name@example.com")
        return value

    @field_validator("password")
    @classmethod
    def _password_not_empty(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value():
            raise ValueError("must not be empty")
        return value


class MailboxOut(BaseModel):
    id: int
    email_address: str
    imap_host: str
    imap_port: int
    created_at: str  # UTC, "YYYY-MM-DD HH:MM:SS"


class ConnectionTestResult(BaseModel):
    ok: bool
    error: str | None = None


class JobOut(BaseModel):
    """A job row as the API shows it. Extra columns in the row are ignored."""

    model_config = ConfigDict(extra="ignore")

    id: int
    account_id: int
    folder: str
    status: str
    range_start: str | None = None
    range_end: str | None = None
    error: str | None = None
    created_at: str | None = None


class EmailOut(BaseModel):
    """Message metadata only: never the raw .eml path or body."""

    model_config = ConfigDict(extra="ignore")

    id: int
    account_id: int
    folder: str
    uid: int
    subject: str | None = None
    sender: str | None = None
    internal_date: str
    header_date: str | None = None


class StatsOut(BaseModel):
    total_emails: int
    emails_last_24h: int
    oldest_internal_date: str | None = None
    newest_internal_date: str | None = None


class IngestRequest(BaseModel):
    mailbox_id: int
    folder: Annotated[_TrimmedText, Field(min_length=1, max_length=255)] = "INBOX"
    start_date: date
    end_date: date


class IngestResponse(BaseModel):
    gaps_found: int
    jobs: list[JobOut]
