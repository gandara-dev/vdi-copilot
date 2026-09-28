import json
from pathlib import Path

import pytest

from vdi_copilot.evidence import load_evidence
from vdi_copilot.rules import evaluate_rules, load_rules

ROOT = Path(__file__).parents[1]


INCIDENTS = sorted(
    path.name for path in (ROOT / "samples" / "incidents").iterdir() if path.is_dir()
)


@pytest.mark.parametrize("incident", INCIDENTS)
def test_synthetic_incident_matches_known_cause(incident: str) -> None:
    directory = ROOT / "samples" / "incidents" / incident
    expected = json.loads((directory / "expected.json").read_text(encoding="utf-8"))
    evidence = load_evidence(directory)

    findings = evaluate_rules(evidence, load_rules())

    assert [finding.rule_id for finding in findings] == expected["finding_ids"]


def test_every_default_rule_has_a_sample_incident() -> None:
    covered = set()
    for incident in INCIDENTS:
        expected = ROOT / "samples" / "incidents" / incident / "expected.json"
        covered.update(json.loads(expected.read_text(encoding="utf-8"))["finding_ids"])

    assert {rule["id"] for rule in load_rules()} == covered


def test_rule_file_rejects_duplicate_ids(tmp_path: Path) -> None:
    rule_file = tmp_path / "rules.json"
    rule = {
        "id": "duplicate",
        "title": "Duplicate",
        "severity": "low",
        "confidence": "low",
        "all": [],
        "any": ["signal"],
        "none": [],
        "recommendations": [],
    }
    rule_file.write_text(
        json.dumps({"schema_version": 1, "rules": [rule, rule]}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unique"):
        load_rules(rule_file)
