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

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


settings = Settings()
