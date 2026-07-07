from edr_backend.detection.attack_map import parse_attack_tags


def test_parses_tactic_and_technique():
    tactic, technique = parse_attack_tags(["attack.execution", "attack.t1059"])
    assert tactic == "execution"
    assert technique == "T1059"


def test_parses_subtechnique():
    tactic, technique = parse_attack_tags(["attack.persistence", "attack.t1053.003"])
    assert tactic == "persistence"
    assert technique == "T1053.003"


def test_takes_first_of_each_kind():
    tactic, technique = parse_attack_tags(
        ["attack.execution", "attack.command-and-control", "attack.t1059", "attack.t1571"]
    )
    assert tactic == "execution"
    assert technique == "T1059"


def test_no_tags_returns_none():
    assert parse_attack_tags([]) == (None, None)


def test_only_tactic_tag():
    tactic, technique = parse_attack_tags(["attack.persistence"])
    assert tactic == "persistence"
    assert technique is None
