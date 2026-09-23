from pathlib import Path

import pytest

from heron.core.crypto import (
    KEY_FILENAME,
    SecretBox,
    SecretBoxError,
    generate_key,
    load_or_create_key_file,
)


def test_generate_key_is_usable_by_secretbox():
    key = generate_key()
    box = SecretBox(key)
    assert box.decrypt(box.encrypt("hunter2")) == "hunter2"


def test_encrypt_then_decrypt_round_trip():
    box = SecretBox(generate_key())
    secret = "an app password with spaces and symbols !@#$"
    assert box.decrypt(box.encrypt(secret)) == secret


def test_encrypt_output_does_not_contain_plaintext():
    box = SecretBox(generate_key())
    secret = "super-secret-app-password"
    token = box.encrypt(secret)
    assert secret not in token


def test_same_plaintext_encrypts_differently_each_time():
    # Fernet includes random IV + timestamp, so ciphertexts are not repeatable
    # even for the same input - this is expected, not a bug.
    box = SecretBox(generate_key())
    a = box.encrypt("same value")
    b = box.encrypt("same value")
    assert a != b
    assert box.decrypt(a) == box.decrypt(b) == "same value"


def test_decrypt_with_wrong_key_raises():
    box_a = SecretBox(generate_key())
    box_b = SecretBox(generate_key())
    token = box_a.encrypt("secret")
    with pytest.raises(SecretBoxError, match="could not decrypt"):
        box_b.decrypt(token)


def test_decrypt_garbage_raises():
    box = SecretBox(generate_key())
    with pytest.raises(SecretBoxError, match="could not decrypt"):
        box.decrypt("not-a-real-token")


def test_decrypt_tampered_token_raises():
    # Fernet authenticates ciphertext (HMAC); flipping a character must be
    # detected, not silently decrypted into wrong plaintext.
    box = SecretBox(generate_key())
    token = box.encrypt("secret")
    tampered = ("A" if token[0] != "A" else "B") + token[1:]
    with pytest.raises(SecretBoxError, match="could not decrypt"):
        box.decrypt(tampered)


def test_invalid_key_raises_on_construction():
    with pytest.raises(SecretBoxError, match="invalid encryption key"):
        SecretBox("not-a-valid-fernet-key")


def test_encrypt_rejects_non_string_plaintext():
    box = SecretBox(generate_key())
    with pytest.raises(SecretBoxError, match="must be a string"):
        box.encrypt(12345)  # type: ignore[arg-type]


def test_load_or_create_key_file_creates_on_first_run(tmp_path: Path):
    key = load_or_create_key_file(tmp_path)
    key_path = tmp_path / KEY_FILENAME
    assert key_path.exists()
    assert key_path.read_text(encoding="ascii").strip() == key
    # Usable immediately.
    SecretBox(key)


def test_load_or_create_key_file_is_stable_across_calls(tmp_path: Path):
    first = load_or_create_key_file(tmp_path)
    second = load_or_create_key_file(tmp_path)
    assert first == second


def test_load_or_create_key_file_creates_missing_data_dir(tmp_path: Path):
    nested = tmp_path / "nested" / "data"
    key = load_or_create_key_file(nested)
    assert (nested / KEY_FILENAME).exists()
    assert key


def test_load_or_create_key_file_rejects_empty_file(tmp_path: Path):
    (tmp_path / KEY_FILENAME).write_text("", encoding="ascii")
    with pytest.raises(SecretBoxError, match="empty"):
        load_or_create_key_file(tmp_path)


def test_from_settings_prefers_explicit_key_over_file(tmp_path: Path):
    explicit_key = generate_key()
    box = SecretBox.from_settings(explicit_key, tmp_path)
    # No key file should have been created when an explicit key was given.
    assert not (tmp_path / KEY_FILENAME).exists()
    assert box.decrypt(box.encrypt("value")) == "value"


def test_from_settings_falls_back_to_key_file(tmp_path: Path):
    box_a = SecretBox.from_settings(None, tmp_path)
    token = box_a.encrypt("mailbox-app-password")
    # A second SecretBox built the same way should read the same key file
    # and therefore be able to decrypt what the first one encrypted.
    box_b = SecretBox.from_settings(None, tmp_path)
    assert box_b.decrypt(token) == "mailbox-app-password"
