"""Build a private, non-decisional briefing for a human report moderator."""


def moderator_brief(complaint_analysis, evidence_analysis, pattern_matches, deterministic_checks):
    ai = (complaint_analysis or {}).get("ai", {})
    evidence_ai = (evidence_analysis or {}).get("ai", {})
    return {
        "label": "AI-assisted investigation support · human review required",
        "status": "available" if ai.get("status") == "available" or evidence_ai.get("status") == "available" else "unavailable",
        "complaint_summary": ai.get("summary") if ai.get("status") == "available" else (complaint_analysis or {}).get("local", {}).get("summary", ""),
        "risk_indicators": ai.get("risk_indicators", []) if ai.get("status") == "available" else [],
        "evidence_overview": ai.get("evidence_overview", []) if ai.get("status") == "available" else [],
        "extracted_information": ((evidence_analysis or {}).get("ai", {}).get("extracted_information")
                                  if evidence_ai.get("status") == "available" else (evidence_analysis or {}).get("extracted_information", {})),
        "potential_inconsistencies": (ai.get("potential_inconsistencies", []) if ai.get("status") == "available" else []) +
                                      (evidence_analysis or {}).get("potential_inconsistencies", []),
        "missing_information": ai.get("missing_information", []) if ai.get("status") == "available" else (complaint_analysis or {}).get("local", {}).get("missing_information", []),
        "suggested_questions": ai.get("suggested_questions", []) if ai.get("status") == "available" else [],
        "similar_reports": pattern_matches or [], "deterministic_checks": deterministic_checks or [],
        "may_change_report_status": False,
    }
