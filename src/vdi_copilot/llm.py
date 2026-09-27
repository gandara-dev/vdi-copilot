"""Optional Ollama-compatible explanation provider."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Iterable

from .models import Evidence, Finding

SYSTEM_PROMPT = """You explain a deterministic VDI troubleshooting report.
Use only the supplied findings and evidence excerpts. Do not invent events,
causes, commands, or confidence. Clearly state uncertainty. Return JSON with a
single string field named summary. Keep the summary below 180 words."""


def explain_with_ollama(
    findings: Iterable[Finding],
    evidence: Iterable[Evidence],
    *,
    endpoint: str = "http://127.0.0.1:11434",
    model: str = "qwen3:4b-instruct",
    api_key: str | None = None,
    timeout: float = 120,
) -> str:
    """Ask an Ollama-compatible /api/chat endpoint to explain existing findings."""

    findings_payload = [finding.to_dict() for finding in findings]
    excerpts = [{"source": item.source, "text": item.text[:1500]} for item in evidence][:12]
    user_payload = json.dumps(
        {"findings": findings_payload, "evidence_excerpts": excerpts},
        ensure_ascii=False,
    )
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_payload},
        ],
        "format": "json",
        "stream": False,
        "think": False,
        "options": {"temperature": 0.1},
    }
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(
        f"{endpoint.rstrip('/')}/api/chat",
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            result = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise RuntimeError(f"LLM request failed: {error}") from error

    try:
        content = json.loads(result["message"]["content"])
        summary = str(content["summary"]).strip()
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("LLM response did not contain a JSON summary.") from error
    if not summary:
        raise RuntimeError("LLM response contained an empty summary.")
    return summary
