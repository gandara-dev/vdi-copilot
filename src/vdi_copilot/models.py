"""Core data models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Evidence:
    source: str
    text: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    evidence: tuple[str, ...]
    recommendations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["evidence"] = list(self.evidence)
        result["recommendations"] = list(self.recommendations)
        return result


@dataclass
class AnalysisReport:
    findings: list[Finding] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    explanation: str | None = None
    redacted: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "redacted": self.redacted,
            "sources": self.sources,
            "findings": [finding.to_dict() for finding in self.findings],
            "explanation": self.explanation,
        }
