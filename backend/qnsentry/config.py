import ipaddress

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import URL


# The placeholder in .env.example, refused as a real secret
EXAMPLE_SECRET = "change-me-to-at-least-32-random-characters"


class Settings(BaseSettings):
    """Configuration read from environment variables (see .env.example)."""

    # A validation error must not print the value: a secret that is one character too
    # short would otherwise end up literally in the container logs
    model_config = SettingsConfigDict(hide_input_in_errors=True)

    postgres_user: str
    postgres_password: str
    postgres_db: str
    postgres_host: str = "db"
    postgres_port: int = 5432
    redis_url: str = "redis://redis:6379/0"
    # Longest a scan may take; a scan still queued or running after this is stuck
    scan_timeout_minutes: int = Field(120, ge=1)
    # GDPR storage limitation (#46): scan results are deleted after this many days.
    # At least 1: a typo like 0 or -1 in .env would otherwise delete every result each night,
    # so the API and worker refuse to start with a clear error instead
    retention_days: int = Field(90, ge=1)
    # Domain ownership verification (#48): the TXT record is an HMAC of the domain with this
    # secret. Keep it the same to keep existing TXT records valid; at least 32 characters.
    domain_verification_secret: str = Field(min_length=32)
    # Breach module (#11): "local" (test dataset) or "hibp" (Have I Been Pwned, #13)
    breach_source: str = "local"
    # JSON dataset for the local source; empty = the bundled BadSecurityInc test data
    breach_dataset: str | None = None
    # Have I Been Pwned (#13): API key (never commit it) and seconds between requests.
    # 6 seconds fits the smallest plan (10 requests per minute); lower it for a bigger plan.
    hibp_api_key: str | None = None
    hibp_min_interval_seconds: float = 6.0
    # Cert Spotter (#10): without a key only for personal or evaluation use, with a small hourly limit
    certspotter_api_key: str | None = None
    # DNS servers for the lookups of the phishing module (#80), comma-separated; empty = the
    # container's DNS. On some networks Docker's DNS lets every name that does not exist time
    # out instead of answering "does not exist", and phishing looks up hundreds of those
    dns_servers: str = "1.1.1.1,8.8.8.8,9.9.9.9"

    @field_validator("domain_verification_secret")
    @classmethod
    def refuse_example_secret(cls, value: str) -> str:
        # The value from .env.example is public: everyone could compute the TXT records
        if value == EXAMPLE_SECRET:
            raise ValueError("replace the example DOMAIN_VERIFICATION_SECRET with your own, e.g. openssl rand -hex 32")
        return value

    @field_validator("dns_servers")
    @classmethod
    def valid_dns_servers(cls, value: str) -> str:
        # A typo would otherwise only show up as failed lookups during a scan
        servers = []
        for server in filter(None, (part.strip() for part in value.split(","))):
            try:
                servers.append(str(ipaddress.ip_address(server)))
            except ValueError:
                raise ValueError(f"{server} in DNS_SERVERS is not an IP address") from None
        return ",".join(servers)

    @property
    def nameservers(self) -> list[str] | None:
        """DNS_SERVERS as a list; None = the container's DNS."""
        return self.dns_servers.split(",") if self.dns_servers else None

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
