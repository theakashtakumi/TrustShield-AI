"""Small, deterministic scoring rules kept separate from web request handling."""

from datetime import datetime, timezone

SCANNER_VERSION = "1.2.0"

# Contributions are deliberately small for missing browser headers and wording
# heuristics. Only confirmed external threat intelligence will receive a strong
# contribution once a provider is configured and has been independently tested.
SCORING_WEIGHTS = {
    "connection.http_final": 24,
    "connection.http_redirect": 2,
    "connection.tls_invalid": 25,
    "connection.cross_origin_redirect": 1,
    "response.server_error": 2,
    "header.missing": 1,
    "header.weak": 1,
    "header.invalid": 1,
    "url.impersonation_pattern": 6,
    "content.high_pressure_language": 1,
    "reputation.verified_malicious": 90,
}


def make_finding(rule_id: str, name: str, category: str, status: str, explanation: str,
                 *, source: str, evidence: str = "", contribution: int = 0,
                 observed_at: str | None = None) -> dict:
    """Create a persisted finding with provenance, time, and score impact."""
    allowed = {"PASS", "WARNING", "FAIL", "NOT DETECTED", "UNKNOWN", "NOT APPLICABLE"}
    if status not in allowed:
        raise ValueError(f"Unsupported finding status: {status}")
    if status in {"UNKNOWN", "NOT APPLICABLE", "PASS", "NOT DETECTED"} and contribution < 0:
        raise ValueError("Finding score contributions cannot be negative.")
    return {
        "rule_id": rule_id,
        "name": name,
        "category": category,
        "status": status,
        "explanation": explanation,
        "source": source,
        "evidence": evidence,
        "score_contribution": max(0, int(contribution)),
        "observed_at": observed_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scanner_version": SCANNER_VERSION,
    }


def score_findings(findings: list[dict], *, sufficient_data: bool) -> dict:
    """Score only explicit weighted findings; unknowns and community claims add zero."""
    total = sum(
        min(int(item.get("score_contribution", 0)), SCORING_WEIGHTS.get(item.get("rule_id"), 0))
        for item in findings
        if item.get("status") in {"WARNING", "FAIL", "NOT DETECTED"}
    )
    assessment = classify(total, sufficient_data=sufficient_data)
    return {**assessment, "calculation": {"formula": "100 minus weighted technical warning points", "warning_points": total, "scanner_version": SCANNER_VERSION}}


def classify(warning_points: int, sufficient_data: bool = True) -> dict:
    """Convert weighted warnings into a trust score and explainable risk tier.

    The score is a bounded presentation aid, not a probability or safety claim.
    Unknown findings do not contribute warning points.
    """
    risk_points = max(0, min(100, int(warning_points)))
    if not sufficient_data:
        return {
            "score": 0,
            "risk_points": risk_points,
            "label": "Insufficient Data",
            "summary": "We could not retrieve enough information to assess this site. Missing data is not an endorsement or proof of fraud.",
        }
    if risk_points >= 60:
        label = "Critical Risk"
        summary = "Multiple strong warning signals were observed. Do not share payment or personal information until you independently verify the seller."
    elif risk_points >= 35:
        label = "High Risk"
        summary = "Several observable warning signs merit caution. Independently verify the seller before sharing payment or personal details."
    elif risk_points >= 16:
        label = "Moderate Risk"
        summary = "Some signals need context. Verify the seller and policies through independent channels before making a purchase."
    else:
        label = "Low Risk"
        summary = "The selected checks found few warning signals. A low-risk score is not a guarantee that the seller is legitimate."
    return {"score": 100 - risk_points, "risk_points": risk_points, "label": label, "summary": summary}
