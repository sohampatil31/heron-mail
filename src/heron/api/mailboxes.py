"""Mailbox management: add, list, inspect, test, and delete.

Passwords go in through POST /mailboxes and are encrypted before they are
stored. Nothing here ever sends one back out.
"""

from fastapi import APIRouter, HTTPException, status
from sqlalchemy.exc import IntegrityError

from heron.api.deps import EngineDep, SecretBoxDep
from heron.api.schemas import ConnectionTestResult, MailboxCreate, MailboxOut
from heron.core.crypto import SecretBoxError
from heron.core.storage import create_account, delete_account, get_account, list_accounts
from heron.ingest.imap_client import ImapClient, ImapConnectionError

# Shorter than the client's 30s default: a person is waiting on this answer.
CONNECT_TEST_TIMEOUT_SECONDS = 10

router = APIRouter(prefix="/mailboxes", tags=["mailboxes"])


@router.post("", response_model=MailboxOut, status_code=status.HTTP_201_CREATED)
def add_mailbox(body: MailboxCreate, engine: EngineDep, secret_box: SecretBoxDep):
    """Store a new mailbox. The password is encrypted before it touches the database."""
    try:
        account_id = create_account(
            engine,
            secret_box,
            email_address=body.email_address,
            imap_host=body.imap_host,
            imap_port=body.imap_port,
            password=body.password.get_secret_value(),
        )
    except IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="a mailbox with this email address already exists",
        ) from exc
    return MailboxOut.model_validate(get_account(engine, account_id))


@router.get("", response_model=list[MailboxOut])
def list_mailboxes(engine: EngineDep):
    return [MailboxOut.model_validate(row) for row in list_accounts(engine)]


@router.post("/test", response_model=ConnectionTestResult)
def test_credentials(body: MailboxCreate):
    """Try a login without saving anything, for a "Test connection" button before adding."""
    return _try_login(
        host=body.imap_host,
        port=body.imap_port,
        email_address=body.email_address,
        password=body.password.get_secret_value(),
    )


@router.get("/{mailbox_id}", response_model=MailboxOut)
def get_mailbox(mailbox_id: int, engine: EngineDep):
    row = get_account(engine, mailbox_id)
    if row is None:
        raise _not_found()
    return MailboxOut.model_validate(row)


@router.post("/{mailbox_id}/test", response_model=ConnectionTestResult)
def test_saved_mailbox(mailbox_id: int, engine: EngineDep, secret_box: SecretBoxDep):
    """Try a login with a stored mailbox's saved credentials.

    A failed login is a normal answer to this question, so it comes back as
    200 with ok=false rather than as an HTTP error.
    """
    row = get_account(engine, mailbox_id)
    if row is None:
        raise _not_found()
    try:
        password = secret_box.decrypt(row["encrypted_password"])
    except SecretBoxError:
        return ConnectionTestResult(
            ok=False,
            error="the stored password could not be decrypted (was the encryption key changed?)",
        )
    return _try_login(
        host=row["imap_host"],
        port=row["imap_port"],
        email_address=row["email_address"],
        password=password,
    )


@router.delete("/{mailbox_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_mailbox(mailbox_id: int, engine: EngineDep) -> None:
    """Delete a mailbox and, via cascading foreign keys, its emails, jobs, and coverage."""
    if not delete_account(engine, mailbox_id):
        raise _not_found()


def _try_login(*, host: str, port: int, email_address: str, password: str) -> ConnectionTestResult:
    try:
        with ImapClient(
            host, email_address, password, port=port, timeout=CONNECT_TEST_TIMEOUT_SECONDS
        ):
            pass
    except ImapConnectionError as exc:
        return ConnectionTestResult(ok=False, error=str(exc))
    return ConnectionTestResult(ok=True)


def _not_found() -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="mailbox not found")
