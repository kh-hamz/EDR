from datetime import datetime

from sqlalchemy import DateTime, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..core.db import Base


class AgentRecord(Base):
    __tablename__ = "agents"

    agent_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    os: Mapped[str] = mapped_column(String(32))
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    enrolled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Alert(Base):
    __tablename__ = "alerts"
    # one alert per (rule, event): a detection run that sees the same event
    # again (it re-queries a trailing time window to survive a missed tick)
    # must not create a duplicate.
    __table_args__ = (UniqueConstraint("rule_id", "event_id", name="uq_alert_rule_event"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[str] = mapped_column(String(36), index=True)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16))
    tactic: Mapped[str | None] = mapped_column(String(64), nullable=True)
    technique_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(16), default="open")
