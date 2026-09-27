import json
from pathlib import Path

import pytest

from vdi_copilot.evidence import load_evidence
from vdi_copilot.rules import evaluate_rules, load_rules

ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize(
    ("incident", "expected_rule"),
    [
        ("vda-registration-dns", "vda-registration-dns"),
        ("storefront-sta-failure", "storefront-sta-validation"),
    ],
)
def test_synthetic_incident_matches_known_cause(incident: str, expected_rule: str) -> None:
    evidence = load_evidence(ROOT / "samples" / "incidents" / incident)

    findings = evaluate_rules(evidence, load_rules())

    assert [finding.rule_id for finding in findings] == [expected_rule]


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
