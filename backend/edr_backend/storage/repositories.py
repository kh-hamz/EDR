"""DB access helpers, kept out of routers so SQL doesn't leak into endpoint code."""

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .models import Alert, AgentRecord, Command, Incident


class AgentRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_hostname(self, hostname: str) -> AgentRecord | None:
        return self.db.scalar(select(AgentRecord).where(AgentRecord.hostname == hostname))

    def upsert(self, agent_id: str, hostname: str, os: str, ip: str | None) -> AgentRecord:
        """Re-enrollment from the same hostname updates os/ip in place instead of
        creating a duplicate host, so reinstalling the agent keeps its identity."""
        existing = self.get_by_hostname(hostname)
        if existing is not None:
            existing.os = os
            existing.ip = ip
            self.db.commit()
            return existing

        agent = AgentRecord(
            agent_id=agent_id,
            hostname=hostname,
            os=os,
            ip=ip,
            enrolled_at=datetime.now(timezone.utc),
        )
        self.db.add(agent)
        self.db.commit()
        return agent

    def list_all(self) -> list[AgentRecord]:
        return list(self.db.scalars(select(AgentRecord).order_by(AgentRecord.hostname)))

    def touch_last_seen(self, agent_ids: set[str]) -> None:
        now = datetime.now(timezone.utc)
        for agent_id in agent_ids:
            agent = self.db.get(AgentRecord, agent_id)
            if agent is not None:
                agent.last_seen = now
        self.db.commit()


class AlertRepository:
    def __init__(self, db: Session):
        self.db = db

    def create_if_new(
        self,
        event_id: str,
        rule_id: str,
        title: str,
        severity: str,
        hostname: str,
        tactic: str | None,
        technique_id: str | None,
    ) -> Alert | None:
        """Returns the new Alert, or None if this (rule_id, event_id) pair was
        already alerted on. A detection run re-queries a trailing time window
        (to tolerate a missed tick), so re-seeing the same event is expected,
        not an error."""
        alert = Alert(
            event_id=event_id,
            rule_id=rule_id,
            title=title,
            severity=severity,
            hostname=hostname,
            tactic=tactic,
            technique_id=technique_id,
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(alert)
        try:
            self.db.commit()
        except IntegrityError:
            self.db.rollback()
            return None
        return alert

    def list_all(
        self, status: str | None = None, severity: str | None = None
    ) -> list[Alert]:
        query = select(Alert).order_by(Alert.created_at.desc())
        if status:
            query = query.where(Alert.status == status)
        if severity:
            query = query.where(Alert.severity == severity)
        return list(self.db.scalars(query))

    def update_status(self, alert_id: int, status: str) -> Alert | None:
        alert = self.db.get(Alert, alert_id)
        if alert is None:
            return None
        alert.status = status
        self.db.commit()
        return alert

    def list_unassigned(self) -> list[Alert]:
        """Alerts not yet grouped into an incident, oldest first so the
        correlation pass processes them in arrival order."""
        return list(
            self.db.scalars(
                select(Alert).where(Alert.incident_id.is_(None)).order_by(Alert.created_at)
            )
        )

    def list_by_rule_without_command(self, rule_id: str) -> list[Alert]:
        """Open alerts for a rule that have not yet triggered a command - the
        candidates an auto-playbook still needs to act on."""
        return list(
            self.db.scalars(
                select(Alert)
                .outerjoin(Command, Command.source_alert_id == Alert.id)
                .where(
                    Alert.rule_id == rule_id,
                    Alert.status == "open",
                    Command.id.is_(None),
                )
                .order_by(Alert.created_at)
            )
        )


class IncidentRepository:
    def __init__(self, db: Session):
        self.db = db

    def find_open_since(self, hostname: str, cutoff: datetime) -> Incident | None:
        """Most recent open incident on this host whose last alert is at or
        after `cutoff` - the candidate an incoming alert can join."""
        return self.db.scalar(
            select(Incident)
            .where(
                Incident.hostname == hostname,
                Incident.status == "open",
                Incident.last_alert_at >= cutoff,
            )
            .order_by(Incident.last_alert_at.desc())
            .limit(1)
        )

    def create(self, hostname: str, title: str, severity: str, alert_time: datetime) -> Incident:
        incident = Incident(
            hostname=hostname,
            title=title,
            severity=severity,
            first_alert_at=alert_time,
            last_alert_at=alert_time,
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(incident)
        self.db.commit()
        return incident

    def attach_alert(self, incident: Incident, alert: Alert, severity: str) -> None:
        """Adds the alert and advances the incident's window/severity. The
        caller decides the escalated severity (policy lives in correlation)."""
        alert.incident_id = incident.id
        incident.severity = severity
        if alert.created_at > incident.last_alert_at:
            incident.last_alert_at = alert.created_at
        self.db.commit()

    def list_all(self, status: str | None = None) -> list[tuple[Incident, int]]:
        """Incidents (newest first) paired with their alert count."""
        query = (
            select(Incident, func.count(Alert.id))
            .outerjoin(Alert, Alert.incident_id == Incident.id)
            .group_by(Incident.id)
            .order_by(Incident.last_alert_at.desc())
        )
        if status:
            query = query.where(Incident.status == status)
        return [(incident, count) for incident, count in self.db.execute(query)]

    def get(self, incident_id: int) -> Incident | None:
        return self.db.get(Incident, incident_id)

    def alerts_for(self, incident_id: int) -> list[Alert]:
        return list(
            self.db.scalars(
                select(Alert)
                .where(Alert.incident_id == incident_id)
                .order_by(Alert.created_at)
            )
        )

    def update_status(self, incident_id: int, status: str) -> Incident | None:
        incident = self.db.get(Incident, incident_id)
        if incident is None:
            return None
        incident.status = status
        self.db.commit()
        return incident


class CommandRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(
        self,
        agent_id: str,
        hostname: str,
        action: str,
        params: dict,
        source_alert_id: int | None = None,
    ) -> Command | None:
        """Returns the new Command, or None if an auto-command already exists
        for this source alert (the UniqueConstraint makes the playbook safe to
        re-run). Manual commands (source_alert_id=None) never collide."""
        command = Command(
            agent_id=agent_id,
            hostname=hostname,
            action=action,
            params=params,
            source_alert_id=source_alert_id,
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(command)
        try:
            self.db.commit()
        except IntegrityError:
            self.db.rollback()
            return None
        return command

    def claim_pending(self, agent_id: str) -> list[Command]:
        """Return this agent's pending commands and move them to 'dispatched'
        in one step, so a second poll before the ack doesn't re-deliver them."""
        pending = list(
            self.db.scalars(
                select(Command)
                .where(Command.agent_id == agent_id, Command.status == "pending")
                .order_by(Command.created_at)
            )
        )
        now = datetime.now(timezone.utc)
        for command in pending:
            command.status = "dispatched"
            command.dispatched_at = now
        self.db.commit()
        return pending

    def complete(self, command_id: int, status: str, result: str | None) -> Command | None:
        command = self.db.get(Command, command_id)
        if command is None:
            return None
        command.status = status
        command.result = result
        command.completed_at = datetime.now(timezone.utc)
        self.db.commit()
        return command

    def get(self, command_id: int) -> Command | None:
        return self.db.get(Command, command_id)

    def list_all(self, hostname: str | None = None, status: str | None = None) -> list[Command]:
        query = select(Command).order_by(Command.created_at.desc())
        if hostname:
            query = query.where(Command.hostname == hostname)
        if status:
            query = query.where(Command.status == status)
        return list(self.db.scalars(query))

    def alert_has_command(self, alert_id: int) -> bool:
        return self.db.scalar(
            select(func.count(Command.id)).where(Command.source_alert_id == alert_id)
        ) > 0
