"""Regenerate tests/fixtures/analyzer-cases.json from the Python engine.

The Python package is the reference implementation. This script records how it
redacts text, evaluates rules, and rejects invalid rule files. The Node suite
asserts that the browser engine in site/lib/analyzer.js returns exactly the
same results, and pytest fails when this file is out of date. Regenerate with:

    python tests/update_analyzer_fixtures.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from vdi_copilot.models import AnalysisReport, Evidence
from vdi_copilot.redact import redact_text
from vdi_copilot.rules import evaluate_rules, load_rules, validate_rules

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "tests" / "fixtures" / "analyzer-cases.json"

REDACTION_INPUTS = [
    "password=Summer2026! user=svc_vdi",
    "Token: abc123;next=value, Secret = s3cr3t",
    "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
    "Contact alex.smith+vdi@example.test or OPS@Example.COM",
    r"Profile at C:\Users\alex.smith\AppData\Local\Temp",
    "Controller 192.0.2.21, broadcast 10.0.0.255, version 1.2.3.4.5, bad 999.1.1.1",
    "Hosts ddc-01.corp.example.test and files.internal plus sf01.contoso.local",
    "User SID S-1-5-21-1004336348-1177238915-682003330-1001 logged on",
    "Nothing sensitive: STA ticket validation failed for launch 6f919da3.",
    "Mixed pwd:hunter2 at 198.51.100.7 by admin@corp.example.test",
]

CUSTOM_RULES = {
    "schema_version": 1,
    "rules": [
        {
            "id": "b-medium",
            "title": "Medium rule with an exclusion",
            "severity": "medium",
            "confidence": "medium",
            "all": ["logon"],
            "any": ["slow", "delayed"],
            "none": ["expected maintenance"],
            "recommendations": ["Review the logon timeline."],
        },
        {
            "id": "a-medium",
            "title": "Medium rule sorted before b-medium",
            "severity": "medium",
            "confidence": "low",
            "all": [],
            "any": ["GROUP POLICY"],
            "none": [],
            "recommendations": ["Check Group Policy processing time."],
        },
        {
            "id": "z-critical",
            "title": "Critical rule sorted first",
            "severity": "critical",
            "confidence": "high",
            "all": ["broker"],
            "any": [],
            "none": [],
            "recommendations": ["Page the on-call engineer."],
        },
        {
            "id": "custom-severity",
            "title": "Unknown severities sort last",
            "severity": "informational",
            "confidence": "low",
            "all": ["logon"],
            "any": [],
            "none": [],
            "recommendations": [],
        },
    ],
}

CUSTOM_ANALYSES = [
    {
        "name": "terms across sources and severity ordering",
        "rules": "custom",
        "redact": True,
        "evidence": [
            {
                "source": "vda.log",
                "text": "User logon was delayed by group policy on vda-1.corp.test",
            },
            {"source": "broker.log", "text": "Broker service restarted at 10.1.2.3"},
        ],
    },
    {
        "name": "an exclusion term suppresses a rule",
        "rules": "custom",
        "redact": True,
        "evidence": [
            {"source": "vda.log", "text": "Logon slow during expected maintenance window"},
        ],
    },
    {
        "name": "no rule matches",
        "rules": "default",
        "redact": True,
        "evidence": [{"source": "empty.log", "text": "All services healthy."}],
    },
    {
        "name": "redaction disabled keeps identifiers",
        "rules": "default",
        "redact": False,
        "evidence": [
            {
                "source": "vda.log",
                "text": "Citrix Desktop Service: No such host is known ddc-01.corp.example.test",
            }
        ],
    },
]

INVALID_RULE_DOCUMENTS = [
    ("wrong schema version", {"schema_version": 2, "rules": []}),
    ("rules is not a list", {"schema_version": 1, "rules": {}}),
    (
        "missing fields",
        {"schema_version": 1, "rules": [{"id": "x", "title": "X", "severity": "low"}]},
    ),
    (
        "duplicate IDs",
        {
            "schema_version": 1,
            "rules": [CUSTOM_RULES["rules"][1], CUSTOM_RULES["rules"][1]],
        },
    ),
    (
        "no positive matcher",
        {
            "schema_version": 1,
            "rules": [{**CUSTOM_RULES["rules"][1], "id": "empty", "any": []}],
        },
    ),
]


def analyze(evidence: list[dict[str, str]], rules: list[dict], redact: bool) -> dict:
    items = [
        Evidence(item["source"], redact_text(item["text"]) if redact else item["text"])
        for item in evidence
    ]
    report = AnalysisReport(
        findings=evaluate_rules(items, rules),
        sources=[item.source for item in items],
        redacted=redact,
    )
    return {"texts": [item.text for item in items], "report": report.to_dict()}


def build() -> dict:
    default_rules = load_rules()
    custom_rules = validate_rules(CUSTOM_RULES)
    site_data = json.loads((ROOT / "site" / "data" / "analyzer-data.json").read_text("utf-8"))

    analyses = []
    for incident in site_data["incidents"]:
        analyses.append(
            {
                "name": f"incident {incident['id']}",
                "rules": "default",
                "redact": True,
                "evidence": incident["files"],
                **analyze(incident["files"], default_rules, True),
            }
        )
    for case in CUSTOM_ANALYSES:
        rules = custom_rules if case["rules"] == "custom" else default_rules
        analyses.append({**case, **analyze(case["evidence"], rules, case["redact"])})

    invalid = []
    for name, document in INVALID_RULE_DOCUMENTS:
        try:
            validate_rules(document)
        except ValueError as error:
            invalid.append({"name": name, "document": document, "error": str(error)})
        else:
            raise AssertionError(f"Invalid rule document was accepted: {name}")

    return {
        "description": "Generated by tests/update_analyzer_fixtures.py. Do not edit by hand.",
        "redaction": [{"input": text, "output": redact_text(text)} for text in REDACTION_INPUTS],
        "custom_rules": CUSTOM_RULES,
        "analyses": analyses,
        "invalid_rules": invalid,
    }


def main(argv: list[str]) -> int:
    output = Path(argv[1]) if len(argv) > 1 else DEFAULT_OUTPUT
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(build(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
