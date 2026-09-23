from heron.core.config import Settings


def test_secret_key_defaults_to_none(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("HERON_SECRET_KEY", raising=False)
    assert Settings().secret_key is None


def test_secret_key_read_from_environment(monkeypatch):
    monkeypatch.setenv("HERON_SECRET_KEY", "some-key-value")
    assert Settings().secret_key == "some-key-value"
