"""Application settings, read from HERON_* environment variables or a .env file."""

from functools import lru_cache
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="HERON_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Where the database and raw emails live. Docker images set this to /data.
    data_dir: Path = Path("data")
    # IANA timezone name used to decide what "today" means for the dashboard.
    timezone: str = "UTC"

    @field_validator("timezone")
    @classmethod
    def _valid_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"unknown timezone: {value!r}") from exc
        return value

    @property
    def db_path(self) -> Path:
        return self.data_dir / "heron.db"

    @property
    def eml_dir(self) -> Path:
        return self.data_dir / "eml"

    def ensure_dirs(self) -> None:
        """Create the data directory layout if it does not exist yet."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.eml_dir.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings, loaded once."""
    return Settings()
