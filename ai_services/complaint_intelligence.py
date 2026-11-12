"""Complaint completeness checks and consent-gated AI moderator summaries."""

from __future__ import annotations

from .common import run_analysis
from .privacy import redact_for_provider


CATEGORY_HINTS = {
    "payment": ("payment", "paid", "charge", "transaction", "bank", "upi"),
    "deliver": ("deliver", "order", "tracking", "shipment", "received"),
    "refund": ("refund", "cancel", "cancellation", "return"),
    "phish": ("phishing", "link", "login", "password", "credential"),
    "account": ("account", "login", "password", "access"),
    "impersonat": ("impersonat", "brand", "fake website", "domain"),
    "product": ("product", "advert", "listing", "item", "misleading"),
    "support": ("support", "contact", "phone", "call", "representative"),
}


def rule_based_completeness(report, evidence_file_count=0):
    details = str(report.get("details", ""))
    category = str(report.get("category", "")).lower()
    text = details.lower()
    key = next((key for key in CATEGORY_HINTS if key in category), "")
    aligned = None if not key else any(term in text for term in CATEGORY_HINTS[key])
    missing = []
    if not details.strip():
        missing.append("A short description of what happened")
    elif len(details.strip()) < 40:
        missing.append("More detail about what was expected and what happened")
    if not report.get("incident_date"):
        missing.append("Approximate incident date (optional but useful)")
    if not evidence_file_count:
        missing.append("Supporting records such as an order, message, or receipt (optional)")
    if aligned is False:
        missing.append("Clarification connecting the description to the selected category")
    summary = "Reporter describes a concern in category “{}” for {}. The account is user-provided and awaits independent review.".format(
        str(report.get("category", "other concern"))[:80], str(report.get("domain", "the submitted website"))[:180])
    return {"summary": summary, "missing_information": missing, "category_alignment": "consistent" if aligned else "unclear" if aligned is None else "inconsistent",
            "evidence_count": max(0, int(evidence_file_count)), "source": "Rule-based completeness check"}


def analyze_complaint(report, *, evidence_overview=None, consent=False, provider=None):
    local = rule_based_completeness(report, len(evidence_overview or []))
    if not consent:
        return {"local": local, "ai": {"status": "not_consented", "provider": "none", "findings": [],
                                         "message": "Complaint text was not sent to an AI provider."}}
    details = redact_for_provider(str(report.get("details", "")), 3_500)
    safe_overview = [redact_for_provider(str(item), 160) for item in (evidence_overview or [])[:6]]
    payload = {"category": str(report.get("category", ""))[:100], "reported_domain": str(report.get("domain", ""))[:180],
               "business_name": redact_for_provider(str(report.get("business", "")), 100),
               "incident_date": str(report.get("incident_date", ""))[:10], "complaint_details": details,
               "evidence_overview": safe_overview}
    source_text = details + " " + " ".join(safe_overview)
    result = run_analysis("complaint_intelligence", "Create a neutral moderator brief. Identify missing information, category fit, and questions that could clarify the account. Treat the allegation as unverified and never recommend a status decision.", payload, "complaint", source_text=source_text, provider=provider)
    return {"local": local, "ai": result}
