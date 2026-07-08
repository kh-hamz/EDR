"""Issuing a command: resolve the target host to an agent_id, validate the
action, and persist it as pending. Kept out of the router so the same path is
reachable from the auto-playbook.
"""

from sqlalchemy.orm import Session

from ..storage.models import Command
from ..storage.repositories import AgentRepository, CommandRepository
from .actions import ActionError, validate


class IssueError(ValueError):
    """The command could not be issued (unknown host or bad action/params)."""


def issue_command(
    db: Session,
    hostname: str,
    action: str,
    params: dict,
    source_alert_id: int | None = None,
) -> Command:
    """Validate and persist a pending command for `hostname`. Raises
    IssueError if the host was never enrolled or the action is invalid."""
    agent = AgentRepository(db).get_by_hostname(hostname)
    if agent is None:
        raise IssueError(f"no enrolled host named '{hostname}'")

    try:
        cleaned = validate(action, params)
    except ActionError as exc:
        raise IssueError(str(exc)) from exc

    command = CommandRepository(db).create(
        agent_id=agent.agent_id,
        hostname=hostname,
        action=action,
        params=cleaned,
        source_alert_id=source_alert_id,
    )
    if command is None:
        # Only reachable via source_alert_id collision; manual issues never hit this.
        raise IssueError(f"a command already exists for alert {source_alert_id}")
    return command
