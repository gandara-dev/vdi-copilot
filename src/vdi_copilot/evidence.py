"""Evidence loading and Windows collection."""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Iterable
from pathlib import Path

from .models import Evidence
from .redact import redact_text

SUPPORTED_SUFFIXES = {".json", ".log", ".txt", ".xml"}
MAX_FILE_BYTES = 2_000_000


def _read_file(path: Path) -> str:
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"Evidence file exceeds {MAX_FILE_BYTES} bytes: {path}")
    return path.read_text(encoding="utf-8", errors="replace")


def load_evidence(path: str | Path, *, redact: bool = True) -> list[Evidence]:
    """Load a bundle, individual file, or supported files below a directory."""

    source_path = Path(path)
    if not source_path.exists():
        raise FileNotFoundError(f"Evidence path does not exist: {source_path}")

    if source_path.is_dir():
        files = sorted(
            candidate
            for candidate in source_path.rglob("*")
            if candidate.is_file() and candidate.suffix.lower() in SUPPORTED_SUFFIXES
        )
        evidence: list[Evidence] = []
        for candidate in files:
            if candidate.name == "expected.json":
                continue
            text = _read_file(candidate)
            evidence.append(
                Evidence(
                    source=str(candidate.relative_to(source_path)),
                    text=redact_text(text) if redact else text,
                )
            )
        return evidence

    raw = _read_file(source_path)
    if source_path.suffix.lower() == ".json":
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict) and isinstance(data.get("evidence"), list):
            return [
                Evidence(
                    source=str(item["source"]),
                    text=redact_text(str(item["text"])) if redact else str(item["text"]),
                )
                for item in data["evidence"]
            ]

    return [Evidence(source=source_path.name, text=redact_text(raw) if redact else raw)]


def collect_windows_events(channels: Iterable[str], max_events: int = 200) -> list[Evidence]:
    """Collect recent Windows events through the built-in wevtutil command."""

    if os.name != "nt":
        raise RuntimeError("Windows event collection is available only on Windows.")

    evidence: list[Evidence] = []
    for channel in channels:
        completed = subprocess.run(
            ["wevtutil", "qe", channel, f"/c:{max_events}", "/rd:true", "/f:xml"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if completed.returncode != 0:
            message = completed.stderr.strip() or "unknown wevtutil error"
            raise RuntimeError(f"Could not collect event channel '{channel}': {message}")
        evidence.append(Evidence(source=f"Windows Event Log/{channel}", text=completed.stdout))
    return evidence


def write_bundle(path: str | Path, evidence: Iterable[Evidence], *, redacted: bool) -> None:
    """Write a portable evidence bundle."""

    payload = {
        "schema_version": 1,
        "redacted": redacted,
        "evidence": [item.to_dict() for item in evidence],
    }
    Path(path).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
