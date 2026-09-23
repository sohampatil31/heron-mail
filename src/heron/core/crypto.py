"""Encryption for mailbox app passwords.

Uses Fernet (AES-128-CBC + HMAC-SHA256, from the `cryptography` package) to
encrypt secrets before they are stored in the vault. Fernet, not "AES-256" -
see ARCHITECTURE.md's note on this. What matters more than the algorithm is
key handling, which is what most of this module is about:

- The key lives in `HERON_SECRET_KEY` if the user set it, otherwise it is
  generated on first run and written into the data directory, next to the
  database, so it survives container restarts as long as the data volume
  does.
- Losing the key means every stored password becomes unreadable. There is
  no recovery: the whole point of encryption is that the ciphertext is
  useless without the key. Heron's job is to make that fact visible (a
  clear startup error, not a silent failure) rather than to prevent it.
"""

from __future__ import annotations

from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

KEY_FILENAME = "secret.key"
_KEY_FILE_MODE = 0o600  # owner read/write only - this file is as sensitive as a password


class SecretBoxError(Exception):
    """Raised when a secret cannot be encrypted or decrypted."""


def generate_key() -> str:
    """Generate a new Fernet key, as a string ready to store or set as an env var."""
    return Fernet.generate_key().decode("ascii")


def load_or_create_key_file(data_dir: Path) -> str:
    """Return the encryption key from `<data_dir>/secret.key`, creating it on first run.

    Called only when HERON_SECRET_KEY is not set in the environment (see
    `SecretBox.from_settings`). Restrictive file permissions are best-effort:
    they apply on POSIX systems (Linux, macOS, and the Linux containers Heron
    ships as); Windows ACLs are not set here, since Windows users are expected
    to run Heron via Docker.
    """
    data_dir.mkdir(parents=True, exist_ok=True)
    key_path = data_dir / KEY_FILENAME
    if key_path.exists():
        key = key_path.read_text(encoding="ascii").strip()
        if not key:
            raise SecretBoxError(f"{key_path} exists but is empty")
        return key

    key = generate_key()
    key_path.write_text(key, encoding="ascii")
    try:
        key_path.chmod(_KEY_FILE_MODE)
    except NotImplementedError:
        pass  # chmod is a no-op on some platforms (e.g. certain Windows filesystems)
    return key


class SecretBox:
    """Encrypts and decrypts mailbox passwords and similar short secrets."""

    def __init__(self, key: str) -> None:
        try:
            self._fernet = Fernet(key.encode("ascii") if isinstance(key, str) else key)
        except (ValueError, TypeError) as exc:
            raise SecretBoxError("invalid encryption key") from exc

    @classmethod
    def from_settings(cls, secret_key: str | None, data_dir: Path) -> SecretBox:
        """Build a SecretBox using an explicit key, or the data-dir key file as a fallback.

        `secret_key` is expected to be `settings.secret_key` (from
        `HERON_SECRET_KEY`) - passed in rather than read from `get_settings()`
        directly, so this stays independently testable.
        """
        key = secret_key or load_or_create_key_file(data_dir)
        return cls(key)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a secret (e.g. a mailbox app password) for storage."""
        if not isinstance(plaintext, str):
            raise SecretBoxError("plaintext must be a string")
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, token: str) -> str:
        """Decrypt a value previously produced by `encrypt`.

        Raises SecretBoxError if the token is malformed, was encrypted with a
        different key, or has been tampered with - Fernet authenticates
        ciphertexts (HMAC), so corruption is detected rather than silently
        producing garbage plaintext.
        """
        try:
            return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError) as exc:
            raise SecretBoxError("could not decrypt secret: wrong key or corrupted data") from exc
