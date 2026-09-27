from pathlib import Path

import pytest

from heron.api.auth import (
    TOKEN_FILENAME,
    ApiTokenError,
    load_or_create_token_file,
    resolve_api_token,
)


def test_load_or_create_token_file_creates_on_first_run(tmp_path: Path):
    token = load_or_create_token_file(tmp_path)
    token_path = tmp_path / TOKEN_FILENAME
    assert token_path.exists()
    assert token_path.read_text(encoding="ascii").strip() == token
    assert len(token) > 20  # a real random token, not a placeholder


def test_load_or_create_token_file_is_stable_across_calls(tmp_path: Path):
    first = load_or_create_token_file(tmp_path)
    second = load_or_create_token_file(tmp_path)
    assert first == second


def test_load_or_create_token_file_creates_missing_data_dir(tmp_path: Path):
    nested = tmp_path / "nested" / "data"
    token = load_or_create_token_file(nested)
    assert (nested / TOKEN_FILENAME).exists()
    assert token


def test_load_or_create_token_file_rejects_empty_file(tmp_path: Path):
    (tmp_path / TOKEN_FILENAME).write_text("", encoding="ascii")
    with pytest.raises(ApiTokenError, match="empty"):
        load_or_create_token_file(tmp_path)


def test_two_generated_tokens_are_different(tmp_path: Path):
    # Sanity check that generation is actually random, not a fixed constant.
    token_a = load_or_create_token_file(tmp_path / "a")
    token_b = load_or_create_token_file(tmp_path / "b")
    assert token_a != token_b


def test_resolve_api_token_prefers_explicit_value_over_file(tmp_path: Path):
    token = resolve_api_token("explicit-configured-token", tmp_path)
    assert token == "explicit-configured-token"
    assert not (tmp_path / TOKEN_FILENAME).exists()  # no file created when not needed


def test_resolve_api_token_falls_back_to_file_when_unset(tmp_path: Path):
    first = resolve_api_token(None, tmp_path)
    second = resolve_api_token(None, tmp_path)
    assert first == second
    assert (tmp_path / TOKEN_FILENAME).exists()
