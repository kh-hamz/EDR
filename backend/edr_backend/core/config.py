from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    opensearch_url: str = "http://localhost:9200"
    edr_index_prefix: str = "edr-events"

    postgres_user: str = "edr"
    postgres_password: str
    postgres_db: str = "edr"
    postgres_host: str = "localhost"
    postgres_port: int = 5432

    edr_api_token: str

    # AI copilot (Phase 6). None until set in .env; ai/llm_client.py raises a
    # clear error at call time rather than failing at import/startup, since
    # the rest of the backend must run without it.
    llm_api_key: str | None = None
    llm_model: str = "claude-opus-4-8"

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


settings = Settings()
