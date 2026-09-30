from pydantic_settings import BaseSettings
from sqlalchemy import URL


class Settings(BaseSettings):
    """Configuration read from environment variables (see .env.example)."""

    postgres_user: str
    postgres_password: str
    postgres_db: str
    postgres_host: str = "db"
    postgres_port: int = 5432
    redis_url: str = "redis://redis:6379/0"
    # Longest a scan may take; a scan still queued or running after this is stuck
    scan_timeout_minutes: int = 120
    # GDPR storage limitation (#46): scan results are deleted after this many days
    retention_days: int = 90
    # Breach module (#11): "local" (test dataset) or "hibp" (Have I Been Pwned, #13)
    breach_source: str = "local"
    # JSON dataset for the local source; empty = the bundled BadSecurityInc test data
    breach_dataset: str | None = None

    @property
    def database_url(self) -> URL:
        return URL.create(
            "postgresql+psycopg",
            username=self.postgres_user,
            password=self.postgres_password,
            host=self.postgres_host,
            port=self.postgres_port,
            database=self.postgres_db,
        )


settings = Settings()
