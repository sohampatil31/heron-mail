import pytest
from pydantic import ValidationError

from heron.core.config import Settings, get_settings


def test_defaults(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)  # make sure a real .env is not picked up
    monkeypatch.delenv("HERON_DATA_DIR", raising=False)
    monkeypatch.delenv("HERON_TIMEZONE", raising=False)
    settings = Settings()
    assert settings.timezone == "UTC"
    assert settings.db_path.name == "heron.db"
    assert settings.eml_dir.name == "eml"


def test_environment_overrides_defaults(monkeypatch, tmp_path):
    monkeypatch.setenv("HERON_DATA_DIR", str(tmp_path / "vault"))
    monkeypatch.setenv("HERON_TIMEZONE", "Asia/Kolkata")
    settings = Settings()
    assert settings.data_dir == tmp_path / "vault"
    assert settings.timezone == "Asia/Kolkata"


def test_invalid_timezone_is_rejected(monkeypatch):
    monkeypatch.setenv("HERON_TIMEZONE", "Mars/Olympus")
    with pytest.raises(ValidationError):
        Settings()


def test_ensure_dirs_creates_layout(tmp_path):
    settings = Settings(data_dir=tmp_path / "data")
    settings.ensure_dirs()
    assert settings.data_dir.is_dir()
    assert settings.eml_dir.is_dir()


def test_get_settings_is_cached():
    get_settings.cache_clear()
    first = get_settings()
    assert get_settings() is first
    get_settings.cache_clear()
