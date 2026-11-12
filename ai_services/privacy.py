"""Bounded redaction helpers for optional external AI requests."""

from __future__ import annotations

import re


def redact_for_provider(text: str, limit: int = 8_000) -> str:
    """Remove common direct identifiers and credentials before a consented provider call."""
    value = (text or "")[:max(0, limit)]
    value = re.sub(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", "[email redacted]", value, flags=re.I)
    value = re.sub(r"\b(upi pin|recovery code|otp|password|passcode|pin)\b\s*(?:is|:|=)\s*\S+", r"\1 [redacted]", value, flags=re.I)
    value = re.sub(r"\b(otp|upi pin|pin)\b\s+\d{4,8}\b", r"\1 [redacted]", value, flags=re.I)
    value = re.sub(r"(?<!\w)\+?\d[\d ()-]{7,}\d(?!\w)", "[long number redacted]", value)
    value = re.sub(r"\b(?:\d[ -]*?){13,19}\b", "[payment number redacted]", value)
    return value[:limit]
