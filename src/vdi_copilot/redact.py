"""Best-effort redaction for diagnostic evidence."""

from __future__ import annotations

import re

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"(?i)\b(password|passwd|pwd|secret|token)(\s*[:=]\s*)[^\s;,]+"),
        r"\1\2<REDACTED>",
    ),
    (re.compile(r"(?i)\bAuthorization:\s*Bearer\s+[^\s]+"), "Authorization: Bearer <REDACTED>"),
    (re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"), "<EMAIL>"),
    (re.compile(r"(?i)C:\\Users\\[^\\\s]+"), r"C:\\Users\\<USER>"),
    (re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"), "<IP>"),
    (
        re.compile(r"(?i)\b(?:[a-z0-9-]+\.)+(?:local|internal|corp|com|net|org|test)\b"),
        "<HOST>",
    ),
    (re.compile(r"S-1-5-21-(?:\d+-){2}\d+-\d+"), "<SID>"),
)


def redact_text(text: str) -> str:
    """Remove common credentials and environment identifiers from text."""

    redacted = text
    for pattern, replacement in _PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted
