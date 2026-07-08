"""The response action allow-list and their parameter contracts.

Single source of truth shared by the API (validate an issue request) and the
playbook (build a command). Keeping it here, not in the router, means the
agent-facing contract lives in one place instead of being re-specified
wherever a command is created.
"""


class ActionError(ValueError):
    """Raised when an action name is unknown or its params are malformed."""


# action -> the params it requires, each mapped to the type it must be.
# An action with no params (host isolation) maps to an empty dict.
_ACTION_PARAMS: dict[str, dict[str, type]] = {
    "kill_process": {"pid": int},
    "isolate_host": {},
    "unisolate_host": {},
    "quarantine_file": {"path": str},
}

VALID_ACTIONS = frozenset(_ACTION_PARAMS)


def validate(action: str, params: dict) -> dict:
    """Return the cleaned params for `action`, or raise ActionError. Rejects
    unknown actions, missing/mis-typed required params, and unexpected extras
    (a typo'd key must not silently pass through to the agent)."""
    if action not in _ACTION_PARAMS:
        raise ActionError(f"unknown action '{action}'; valid: {sorted(VALID_ACTIONS)}")

    spec = _ACTION_PARAMS[action]
    params = params or {}

    extra = set(params) - set(spec)
    if extra:
        raise ActionError(f"action '{action}' got unexpected params: {sorted(extra)}")

    cleaned: dict = {}
    for name, expected_type in spec.items():
        if name not in params:
            raise ActionError(f"action '{action}' requires param '{name}'")
        value = params[name]
        # bool is an int subclass; reject it explicitly so pid=True can't slip in.
        if not isinstance(value, expected_type) or isinstance(value, bool) != (expected_type is bool):
            raise ActionError(
                f"action '{action}' param '{name}' must be {expected_type.__name__}"
            )
        cleaned[name] = value
    return cleaned
