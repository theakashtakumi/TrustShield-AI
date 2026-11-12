"""Small, strict output schemas shared by provider and service adapters."""

from __future__ import annotations

from .privacy import redact_for_provider

SCHEMAS = {
    "website": {
        "type": "object",
        "properties": {
            "summary": {"type": "string"},
            "findings": {"type": "array", "items": {"type": "object", "properties": {
                "name": {"type": "string"}, "description": {"type": "string"},
                "severity": {"type": "string", "enum": ["low", "moderate", "high"]},
                "confidence": {"type": "string", "enum": ["low", "moderate", "high"]},
                "evidence": {"type": "string"}, "reasoning": {"type": "string"},
                "recommended_action": {"type": "string"},
            }, "required": ["name", "description", "severity", "confidence", "evidence", "reasoning", "recommended_action"]}},
            "limitations": {"type": "array", "items": {"type": "string"}},
        }, "required": ["summary", "findings", "limitations"],
    },
    "complaint": {
        "type": "object",
        "properties": {
            "summary": {"type": "string"},
            "triage": {"type": "string", "enum": ["suspicious_indicators", "no_clear_indicators", "insufficient_information"]},
            "category_alignment": {"type": "string", "enum": ["consistent", "unclear", "inconsistent"]},
            "risk_indicators": {"type": "array", "items": {"type": "object", "properties": {
                "name": {"type": "string"}, "description": {"type": "string"},
                "severity": {"type": "string", "enum": ["low", "moderate", "high"]},
                "confidence": {"type": "string", "enum": ["low", "moderate", "high"]},
                "evidence": {"type": "string"}, "recommended_action": {"type": "string"},
            }, "required": ["name", "description", "severity", "confidence", "evidence", "recommended_action"]}},
            "evidence_overview": {"type": "array", "items": {"type": "string"}},
            "potential_inconsistencies": {"type": "array", "items": {"type": "string"}},
            "missing_information": {"type": "array", "items": {"type": "string"}},
            "suggested_questions": {"type": "array", "items": {"type": "string"}},
        }, "required": ["summary", "triage", "category_alignment", "risk_indicators", "evidence_overview", "potential_inconsistencies", "missing_information", "suggested_questions"],
    },
    "evidence": {
        "type": "object",
        "properties": {
            "evidence_type": {"type": "string"},
            "extracted_information": {"type": "object", "properties": {
                "dates": {"type": "array", "items": {"type": "string"}},
                "amounts": {"type": "array", "items": {"type": "string"}},
                "business_names": {"type": "array", "items": {"type": "string"}},
                "website_domains": {"type": "array", "items": {"type": "string"}},
                "order_ids": {"type": "array", "items": {"type": "string"}},
                "transaction_references": {"type": "array", "items": {"type": "string"}},
            }, "required": ["dates", "amounts", "business_names", "website_domains", "order_ids", "transaction_references"]},
            "relation_to_complaint": {"type": "string", "enum": ["appears_related", "unclear", "possible_mismatch", "not_enough_text"]},
            "potential_inconsistencies": {"type": "array", "items": {"type": "string"}},
            "missing_information": {"type": "array", "items": {"type": "string"}},
            "confidence": {"type": "string", "enum": ["low", "moderate", "high"]},
            "explanation": {"type": "string"},
        }, "required": ["evidence_type", "extracted_information", "relation_to_complaint", "potential_inconsistencies", "missing_information", "confidence", "explanation"],
    },
}


class InvalidModelOutput(ValueError):
    pass


def _text(value, key, limit=800):
    if not isinstance(value, str):
        raise InvalidModelOutput(f"{key} must be text")
    return redact_for_provider(value.strip(), limit)


def _strings(value, key, *, limit=8, item_limit=240):
    if not isinstance(value, list):
        raise InvalidModelOutput(f"{key} must be a list")
    if any(not isinstance(item, str) for item in value):
        raise InvalidModelOutput(f"{key} items must be text")
    return [_text(item, key, item_limit) for item in value[:limit] if item.strip()]


def _items(value, key, source_text, *, max_items=8):
    if not isinstance(value, list):
        raise InvalidModelOutput(f"{key} must be a list")
    items = []
    for raw in value[:max_items]:
        if not isinstance(raw, dict):
            raise InvalidModelOutput(f"{key} items must be objects")
        required = {"name", "description", "severity", "confidence", "evidence", "recommended_action"}
        if key == "findings":
            required.add("reasoning")
        if not required.issubset(raw):
            raise InvalidModelOutput(f"{key} item is missing required fields")
        if raw.get("severity") not in {"low", "moderate", "high"} or raw.get("confidence") not in {"low", "moderate", "high"}:
            raise InvalidModelOutput(f"{key} item has invalid severity or confidence")
        item = {field: _text(raw.get(field, ""), field, 360 if field == "description" else 240)
                for field in ("name", "description")}
        item["severity"] = raw["severity"]
        item["confidence"] = raw["confidence"]
        item["evidence"] = _text(raw.get("evidence", ""), "evidence", 300)
        item["recommended_action"] = _text(raw.get("recommended_action", ""), "recommended_action", 240)
        if "reasoning" in raw:
            item["reasoning"] = _text(raw.get("reasoning", ""), "reasoning", 300)
        # A model may only cite text the service actually provided to it.
        if item["evidence"] and item["evidence"].casefold() not in source_text.casefold():
            continue
        if item["name"] and item["description"]:
            items.append(item)
    return items


def validate(schema_name, value, *, source_text=""):
    if not isinstance(value, dict):
        raise InvalidModelOutput("response must be a JSON object")
    if schema_name == "website":
        if not all(key in value for key in ("summary", "findings", "limitations")):
            raise InvalidModelOutput("website response is incomplete")
        return {"summary": _text(value.get("summary", ""), "summary", 600),
                "findings": _items(value.get("findings", []), "findings", source_text),
                "limitations": _strings(value.get("limitations", []), "limitations", limit=6)}
    if schema_name == "complaint":
        required = ("summary", "triage", "category_alignment", "risk_indicators", "evidence_overview",
                    "potential_inconsistencies", "missing_information", "suggested_questions")
        if not all(key in value for key in required):
            raise InvalidModelOutput("complaint response is incomplete")
        triage = value.get("triage")
        alignment = value.get("category_alignment")
        if triage not in {"suspicious_indicators", "no_clear_indicators", "insufficient_information"}:
            raise InvalidModelOutput("invalid triage")
        if alignment not in {"consistent", "unclear", "inconsistent"}:
            raise InvalidModelOutput("invalid category alignment")
        indicators = _items(value.get("risk_indicators", []), "risk_indicators", source_text)
        return {"summary": _text(value.get("summary", ""), "summary", 600), "triage": triage,
                "category_alignment": alignment, "risk_indicators": indicators,
                "evidence_overview": _strings(value.get("evidence_overview", []), "evidence_overview"),
                "potential_inconsistencies": _strings(value.get("potential_inconsistencies", []), "potential_inconsistencies"),
                "missing_information": _strings(value.get("missing_information", []), "missing_information"),
                "suggested_questions": _strings(value.get("suggested_questions", []), "suggested_questions")}
    if schema_name == "evidence":
        info = value.get("extracted_information")
        if not isinstance(info, dict):
            raise InvalidModelOutput("extracted_information must be an object")
        required = ("evidence_type", "extracted_information", "relation_to_complaint", "potential_inconsistencies",
                    "missing_information", "confidence", "explanation")
        if not all(key in value for key in required):
            raise InvalidModelOutput("evidence response is incomplete")
        relationship = value.get("relation_to_complaint")
        if relationship not in {"appears_related", "unclear", "possible_mismatch", "not_enough_text"}:
            raise InvalidModelOutput("invalid evidence relationship")
        confidence = value.get("confidence")
        if confidence not in {"low", "moderate", "high"}:
            raise InvalidModelOutput("invalid confidence")
        fields = ("dates", "amounts", "business_names", "website_domains", "order_ids", "transaction_references")
        if not all(field in info for field in fields):
            raise InvalidModelOutput("extracted information is incomplete")
        extracted = {field: [item for item in _strings(info.get(field, []), field, limit=8, item_limit=100)
                             if item.casefold() in source_text.casefold()] for field in fields}
        extracted["transaction_references"] = ["••••" + item[-4:] if len(re.sub(r"\W", "", item)) > 4 else item
                                                for item in extracted["transaction_references"]]
        return {"evidence_type": _text(value.get("evidence_type", ""), "evidence_type", 100),
                "extracted_information": extracted, "relation_to_complaint": relationship,
                "potential_inconsistencies": _strings(value.get("potential_inconsistencies", []), "potential_inconsistencies"),
                "missing_information": _strings(value.get("missing_information", []), "missing_information"),
                "confidence": confidence, "explanation": _text(value.get("explanation", ""), "explanation", 600)}
    raise InvalidModelOutput("unknown analysis schema")
