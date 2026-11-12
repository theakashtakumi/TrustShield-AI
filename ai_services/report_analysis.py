"""Compose private OCR, complaint triage, pattern hints, and moderator briefing."""

from __future__ import annotations

from .complaint_intelligence import analyze_complaint
from .evidence_analysis import analyze_evidence_bundle
from .fraud_patterns import find_related_patterns
from .moderation_assistant import moderator_brief
from .provider import get_provider


def analyze_report(report, files, related_reports, *, consent=False, provider=None):
    provider = provider if provider is not None else get_provider()
    evidence = analyze_evidence_bundle(report, files, consent=consent, provider=provider)
    extracted = evidence.get("extracted_information", {})
    overview = [f"{item['name']}: {item['extraction_status']}; {item['characters_extracted']} text characters" for item in evidence.get("files", [])]
    if extracted:
        overview.append("Locally extracted facts: " + ", ".join(
            [*extracted.get("dates", [])[:3], *extracted.get("amounts", [])[:3], *extracted.get("website_domains", [])[:3]]))
    complaint = analyze_complaint(report, evidence_overview=overview, consent=consent, provider=provider)
    patterns = find_related_patterns(report, related_reports)
    return {"version": "1.0.0", "label": "AI-assisted analysis · not independent verification",
            "complaint": complaint, "evidence": evidence, "related_patterns": patterns,
            "moderator_brief": moderator_brief(complaint, evidence, patterns, report.get("evidence_checks", [])),
            "external_processing_consent": bool(consent)}
