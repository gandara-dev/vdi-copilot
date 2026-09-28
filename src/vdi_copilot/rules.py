"""Deterministic troubleshooting rules."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .models import Evidence, Finding


def default_rules_path() -> Path:
    return Path(__file__).with_name("default_rules.json")


def load_rules(path: str | Path | None = None) -> list[dict[str, Any]]:
    rule_path = Path(path) if path else default_rules_path()
    return validate_rules(json.loads(rule_path.read_text(encoding="utf-8")))


def validate_rules(data: Any) -> list[dict[str, Any]]:
    """Validate a parsed rule document and return its rules."""

    if (
        not isinstance(data, dict)
        or data.get("schema_version") != 1
        or not isinstance(data.get("rules"), list)
    ):
        raise ValueError("Rule file must use schema_version 1 and contain a rules array.")

    required = {"id", "title", "severity", "confidence", "all", "any", "none", "recommendations"}
    seen: set[str] = set()
    for rule in data["rules"]:
        missing = required - set(rule)
        if missing:
            raise ValueError(f"Rule is missing fields: {', '.join(sorted(missing))}")
        if rule["id"] in seen:
            raise ValueError(f"Rule IDs must be unique: {rule['id']}")
        seen.add(rule["id"])
        if not rule["all"] and not rule["any"]:
            raise ValueError(f"Rule must define at least one positive matcher: {rule['id']}")
    return data["rules"]


def _matching_sources(terms: Iterable[str], evidence: list[Evidence]) -> tuple[str, ...]:
    lowered_terms = [term.casefold() for term in terms]
    return tuple(
        item.source
        for item in evidence
        if any(term in item.text.casefold() for term in lowered_terms)
    )


def evaluate_rules(evidence: list[Evidence], rules: list[dict[str, Any]]) -> list[Finding]:
    """Evaluate case-insensitive substring rules against a combined evidence corpus."""

    corpus = "\n".join(item.text for item in evidence).casefold()
    findings: list[Finding] = []

    for rule in rules:
        all_terms = [str(term).casefold() for term in rule["all"]]
        any_terms = [str(term).casefold() for term in rule["any"]]
        none_terms = [str(term).casefold() for term in rule["none"]]

        matches_all = all(term in corpus for term in all_terms)
        matches_any = not any_terms or any(term in corpus for term in any_terms)
        matches_none = not any(term in corpus for term in none_terms)
        if not (matches_all and matches_any and matches_none):
            continue

        positive_terms = [*rule["all"], *rule["any"]]
        sources = _matching_sources(positive_terms, evidence)
        findings.append(
            Finding(
                rule_id=str(rule["id"]),
                title=str(rule["title"]),
                severity=str(rule["severity"]),
                confidence=str(rule["confidence"]),
                evidence=sources,
                recommendations=tuple(str(item) for item in rule["recommendations"]),
            )
        )

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(findings, key=lambda item: (severity_order.get(item.severity, 99), item.rule_id))
