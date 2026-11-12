"""Small, deterministic scoring rules kept separate from web request handling."""


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
