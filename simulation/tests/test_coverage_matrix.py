from simulation.coverage_matrix import (
    RuleTags,
    build_coverage,
    load_rule_tags,
    to_navigator_layer,
)


def test_build_coverage_unions_tactics_and_keeps_max_severity():
    rules = [
        RuleTags("Reverse shell", "critical", ("execution", "command-and-control"), ("T1059", "T1571")),
        RuleTags("Shell from service", "high", ("execution",), ("T1059",)),
    ]
    coverage = {c.technique_id: c for c in build_coverage(rules)}

    # T1059 is covered by both rules: highest severity wins, both titles listed
    assert coverage["T1059"].severity == "critical"
    assert coverage["T1059"].rules == ("Reverse shell", "Shell from service")
    assert set(coverage["T1059"].tactics) == {"execution", "command-and-control"}
    # T1571 only comes from the reverse-shell rule
    assert coverage["T1571"].rules == ("Reverse shell",)


def test_navigator_layer_emits_one_scored_entry_per_technique():
    rules = [
        RuleTags("Reverse shell", "critical", ("execution", "command-and-control"), ("T1059", "T1571")),
        RuleTags("Shell from service", "high", ("execution",), ("T1059",)),
    ]
    layer = to_navigator_layer(build_coverage(rules), "test")

    # one entry per technique, no per-entry tactic (the Navigator places each
    # technique under its own correct tactic column)
    ids = [t["techniqueID"] for t in layer["techniques"]]
    assert ids == ["T1059", "T1571"]
    assert all("tactic" not in t for t in layer["techniques"])
    scores = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    assert scores["T1059"] == 100  # highest severity of the two covering rules
    assert layer["domain"] == "enterprise-attack"


def test_real_rules_cover_the_scoped_techniques():
    # Integration check against the actual detection-content/sigma/ rules.
    coverage = {c.technique_id for c in build_coverage(load_rule_tags())}
    expected = {
        "T1003",
        "T1036",
        "T1053.003",
        "T1059",
        "T1070",
        "T1105",
        "T1136",
        "T1505.003",
        "T1543.002",
        "T1548",
        "T1552",
        "T1571",
    }
    assert expected <= coverage
