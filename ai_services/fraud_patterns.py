"""Conservative report-pattern matching; candidates remain moderator leads."""

from __future__ import annotations

import difflib
import re
from datetime import date

from community_service import report_domain


def find_related_patterns(report, candidates, *, limit=8):
    domain = report_domain(str(report.get("url", "")))
    category = str(report.get("category", "")).casefold()
    business = re.sub(r"\W+", " ", str(report.get("business", "")).casefold()).strip()
    details = re.sub(r"\W+", " ", str(report.get("details", "")).casefold()).strip()
    found = []
    for other in candidates:
        other_domain = report_domain(str(other.get("url", "")))
        same_domain = bool(domain and domain == other_domain)
        same_category = category == str(other.get("category", "")).casefold()
        other_business = re.sub(r"\W+", " ", str(other.get("business", "")).casefold()).strip()
        business_match = bool(business and other_business and difflib.SequenceMatcher(None, business, other_business).ratio() >= .85)
        text = re.sub(r"\W+", " ", str(other.get("details", "")).casefold()).strip()
        similarity = difflib.SequenceMatcher(None, details, text).ratio() if details and text else 0
        gap = None
        if report.get("incident_date") and other.get("incident_date"):
            try:
                gap = abs((date.fromisoformat(str(report["incident_date"])) - date.fromisoformat(str(other["incident_date"]))).days)
            except ValueError:
                pass
        if same_domain and same_category and similarity >= .35 and (gap is None or gap <= 90):
            reasons = ["same normalized domain", "same complaint category"]
            if gap is not None:
                reasons.append(f"incident dates within {gap} days")
            found.append({"id": other.get("id"), "similarity": round(similarity, 2), "reasons": reasons, "independent_confirmation": False})
        elif business_match and same_category and similarity >= .5 and (gap is None or gap <= 30):
            found.append({"id": other.get("id"), "similarity": round(similarity, 2),
                          "reasons": ["similar business name", "same complaint category"], "independent_confirmation": False})
    found.sort(key=lambda row: row["similarity"], reverse=True)
    return found[:limit]
