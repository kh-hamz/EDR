from pydantic_settings import BaseSettings, SettingsConfigDict


class AgentSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="EDR_AGENT_", extra="ignore")

    backend_url: str = "http://localhost:8000"
    api_token: str

    falco_log: str = "/var/log/falco/events.json"
    osquery_log: str = "/var/log/osquery/osqueryd.results.log"

    data_dir: str = "/var/lib/edr-agent"

    batch_size: int = 200
    flush_interval: float = 2.0

    # How often the responder polls the backend for pending commands.
    command_poll_interval: float = 5.0

    # Override auto-detected values if needed (e.g. multiple interfaces)
    hostname: str | None = None
    ip: str | None = None

    @property
    def spool_dir(self) -> str:
        return f"{self.data_dir}/spool"

    @property
    def state_path(self) -> str:
        return f"{self.data_dir}/state.json"
