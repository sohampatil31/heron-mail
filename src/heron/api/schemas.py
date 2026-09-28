"""Request and response shapes for the API.

MailboxOut deliberately has no password field of any kind, not even the
encrypted one. Responses are built from it (never from a raw database row),
so a stored secret cannot leak by accident when a column is added later.
"""

from typing import Annotated

from pydantic import BaseModel, Field, SecretStr, StringConstraints, field_validator

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
