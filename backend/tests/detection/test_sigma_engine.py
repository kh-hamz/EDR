from edr_backend.detection.sigma_engine import load_rules


def test_all_rules_load_and_compile():
    rules = load_rules()
    assert len(rules) == 10
    for rule in rules:
        assert rule.rule_id
        assert rule.title
        assert rule.severity in {"low", "medium", "high", "critical"}
        assert rule.query


def test_rules_are_tagged_with_a_technique():
    rules = load_rules()
    missing = [r.title for r in rules if r.technique_id is None]
    assert missing == []


def test_reverse_shell_rule_compiled_correctly():
    rules = load_rules()
    reverse_shell = next(r for r in rules if r.title == "Reverse shell via netcat")
    assert reverse_shell.technique_id == "T1059"
    assert reverse_shell.severity == "critical"
    assert "nc" in reverse_shell.query
