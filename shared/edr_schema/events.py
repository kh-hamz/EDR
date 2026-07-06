"""Normalized event schema, the shared contract between agent and backend.

OCSF-inspired field names per the roadmap (§2.4). The agent's normalizer
imports these models, so producer and consumer cannot drift.
"""

from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field, model_validator

EventType = Literal[
    "process_create",
    "process_terminate",
    "file_event",
    "network_connection",
    "auth_event",
    "inventory",
]

Observer = Literal["falco", "osquery", "sysmon", "test"]


class HostInfo(BaseModel):
    host_id: str | None = None
    hostname: str
    os: str = "linux"
    ip: str | None = None


class UserInfo(BaseModel):
    name: str | None = None
    uid: int | None = None


class ParentProcessInfo(BaseModel):
    pid: int | None = None
    name: str | None = None
    cmdline: str | None = None


class ProcessInfo(BaseModel):
    pid: int
    ppid: int | None = None
    name: str | None = None
    cmdline: str | None = None
    exe: str | None = None
    hash_sha256: str | None = None
    user: UserInfo | None = None
    parent: ParentProcessInfo | None = None


class FileInfo(BaseModel):
    path: str
    action: Literal["create", "modify", "delete", "rename", "read"]
    hash_sha256: str | None = None
    size: int | None = None


class NetworkInfo(BaseModel):
    direction: Literal["inbound", "outbound"] = "outbound"
    proto: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    pid: int | None = None
    process_name: str | None = None


class AuthInfo(BaseModel):
    action: str
    result: Literal["success", "failure"] | None = None
    user: str | None = None
    method: str | None = None
    src_ip: str | None = None


class InventoryInfo(BaseModel):
    """One row from an osquery scheduled query (crontab, users, systemd units...).

    Stateful snapshot/differential data rather than a point-in-time syscall,
    which is why it gets its own event_type instead of being forced into the
    process/file/network shapes.
    """

    query_name: str
    action: str = "snapshot"
    columns: dict[str, str | int | None]


class MitreInfo(BaseModel):
    tactic: str | None = None
    technique_id: str | None = None


_REQUIRED_BODY: dict[str, str] = {
    "process_create": "process",
    "process_terminate": "process",
    "file_event": "file",
    "network_connection": "network",
    "auth_event": "auth",
    "inventory": "inventory",
}


class NormalizedEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    time: datetime
    event_type: EventType
    agent_id: str
    host: HostInfo
    observer: Observer
    mitre: MitreInfo = Field(default_factory=MitreInfo)

    process: ProcessInfo | None = None
    file: FileInfo | None = None
    network: NetworkInfo | None = None
    auth: AuthInfo | None = None
    inventory: InventoryInfo | None = None

    raw: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def _body_matches_type(self) -> "NormalizedEvent":
        body_field = _REQUIRED_BODY[self.event_type]
        if getattr(self, body_field) is None:
            raise ValueError(f"event_type={self.event_type} requires the '{body_field}' body")
        if self.time.tzinfo is None:
            self.time = self.time.replace(tzinfo=timezone.utc)
        return self
