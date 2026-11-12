"""Shared bounded orchestration for optional provider calls."""

from __future__ import annotations

import hashlib
import json

from .provider import PROMPT_VERSION, ProviderError, get_provider
from .schemas import InvalidModelOutput, validate


def run_analysis(analysis_type, task, payload, schema, *, source_text="", provider=None):
    provider = provider if provider is not None else get_provider()
    packed = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    input_hash = hashlib.sha256(packed.encode("utf-8", errors="replace")).hexdigest()
    base = {"analysis_type": analysis_type, "prompt_version": PROMPT_VERSION,
            "provider": provider.name if provider else "none", "model": provider.model if provider else "",
            "model_version": provider.model_version if provider else "unknown", "input_sha256": input_hash,
            "findings": [], "status": "unavailable"}
    if not provider:
        base["message"] = "AI is not configured. Existing rule-based checks continue to work."
        return base
    try:
        raw = provider.generate_json(task, payload, schema)
        result = validate(schema, raw, source_text=source_text)
        base.update(result)
        base["usage"] = provider.last_usage if isinstance(getattr(provider, "last_usage", {}), dict) else {}
        base["status"] = "available"
        base["message"] = "AI-assisted observations only; not independent verification. Model confidence bands are uncalibrated." 
    except ProviderError as exc:
        base["status"] = "unavailable" if exc.code in {"provider_unavailable", "provider_rejected_request"} else "error"
        base["message"] = "AI analysis could not be completed. Rule-based checks remain available."
        base["error_code"] = exc.code
    except InvalidModelOutput:
        base["status"] = "error"
        base["message"] = "The provider returned a response that did not match the required schema. Rule-based checks remain available."
        base["error_code"] = "invalid_structured_output"
    except Exception:
        base["status"] = "error"
        base["message"] = "AI analysis failed safely. Rule-based checks remain available."
        base["error_code"] = "analysis_error"
    return base
