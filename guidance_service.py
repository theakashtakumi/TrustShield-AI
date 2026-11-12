"""Category-specific next-step guidance and configurable official resources."""

from __future__ import annotations
import os
import urllib.parse

OFFICIAL_RESOURCES = {
    "IN": [
        {"id": "cybercrime", "title": "National Cyber Crime Reporting Portal", "url": "https://cybercrime.gov.in/", "domain": "cybercrime.gov.in", "applies": ["payment", "phishing", "support", "impersonation", "information", "account"]},
        {"id": "consumer", "title": "National Consumer Helpline", "url": "https://consumerhelpline.gov.in/public/", "domain": "consumerhelpline.gov.in", "applies": ["payment", "product", "refund", "delivery"]},
    ]
}

GUIDANCE = {
    "delivery": ["Save your order confirmation, payment record, and the product listing.", "Keep screenshots and messages with the seller, including dates.", "Contact the seller through contact details you verify independently.", "Ask your payment provider about its dispute or chargeback process.", "For a consumer grievance in India, consider the National Consumer Helpline.", "If you suspect financial cybercrime, consider reporting it through the official cybercrime channel."],
    "product": ["Save the product page, advertisement, order details, and photos of what arrived.", "Keep messages and record when the listing or product differed from what was promised.", "Contact the seller through independently verified details and keep their response.", "Ask your payment provider or consumer helpline about available complaint routes."],
    "payment": ["Contact your bank, card issuer, or payment app promptly using its official app or number.", "Ask the provider how to secure your account and dispute the transaction.", "Save transaction alerts and reference details; never share an OTP, PIN, or full card number.", "For suspected online financial cybercrime in India, consider contacting the official cybercrime service promptly."],
    "phishing": ["Do not open the link again or reply to the sender.", "Never share an OTP, password, UPI PIN, or recovery code.", "If you entered a password, change it using the service’s official website or app.", "Turn on two-step verification and sign out other sessions where available.", "Contact your bank or service provider using independently verified details if account or payment details were exposed.", "Report the suspicious URL through an official cybercrime reporting channel."],
    "support": ["Stop communicating through the suspicious number or account.", "Contact the business using details from its official website or app.", "Save call logs, messages, payment requests, and the account or number used.", "If you shared a password or payment credential, secure the affected account through its official channel."],
    "refund": ["Save the order, cancellation request, refund promise, and all follow-up messages.", "Contact the seller through independently verified support details and keep a copy of the request.", "Ask your payment provider about its dispute time limits.", "For an unresolved consumer grievance in India, consider the National Consumer Helpline."],
    "impersonation": ["Do not use links or phone numbers from the suspicious page.", "Compare the address with the business’s official website, found independently.", "Save the page address, screenshots, and messages that show the impersonation.", "Tell the impersonated business through its verified contact channel.", "If money or credentials were exposed, contact your provider and consider an official cybercrime report."],
    "information": ["Stop sharing further personal information with the site or contact.", "Change any password you shared, using the real service’s official website.", "Watch relevant accounts for unfamiliar sign-ins or activity and enable two-step verification.", "Contact your bank or service provider if financial or account information was involved.", "Save the page and messages, but remove unnecessary personal details before sharing copies."],
    "account": ["Use the service’s official website or app to change your password immediately.", "Secure the email account used for recovery and turn on two-step verification.", "Sign out other sessions and review recovery details if the service allows it.", "Contact the service through verified support and your bank if payment details are at risk.", "Save account alerts and messages without sharing recovery codes or OTPs."],
    "default": ["Save relevant messages, receipts, screenshots, and dates.", "Contact the business through details you verify independently.", "If money or account access is at risk, contact your bank or service provider through an official channel.", "Avoid sharing passwords, OTPs, full card numbers, or unnecessary identity documents."]
}

def _topic(category: str) -> str:
    value = (category or "").lower()
    if "not delivered" in value or "non-delivery" in value or "delivery" in value: return "delivery"
    if "fake product" in value or "misleading" in value: return "product"
    if "unauthorized" in value or "payment fraud" in value or "suspicious transaction" in value or "payment taken" in value: return "payment" if "not delivered" not in value else "delivery"
    if "phishing" in value or "suspicious link" in value: return "phishing"
    if "customer support" in value: return "support"
    if "refund" in value or "cancellation" in value: return "refund"
    if "impersonat" in value or "trusted brand" in value: return "impersonation"
    if "personal information" in value or "information misuse" in value: return "information"
    if "account compromise" in value or "account takeover" in value: return "account"
    return "default"

def _configured_resources(country: str, topic: str) -> list[dict]:
    resources = OFFICIAL_RESOURCES.get(country, [])
    result = []
    env_names = {"cybercrime.gov.in": "TRUSTSHIELD_CYBERCRIME_URL", "consumerhelpline.gov.in": "TRUSTSHIELD_CONSUMER_URL"}
    for resource in resources:
        if topic not in resource["applies"]: continue
        url = os.environ.get(env_names[resource["domain"]], resource["url"])
        parts = urllib.parse.urlsplit(url)
        # Only show configuration that remains on the independently verified official domain.
        if parts.scheme == "https" and parts.hostname == resource["domain"]:
            result.append({"id": resource["id"], "title": resource["title"], "url": url, "note": "Official Government of India resource. Review its current instructions before sharing information."})
    return result

def guidance_for(category: str, country: str = "IN") -> dict:
    topic = _topic(category)
    return {"country": country, "category": category, "steps": [{"id": f"{topic}-{i+1}", "text": text} for i, text in enumerate(GUIDANCE.get(topic, GUIDANCE["default"]))], "resources": _configured_resources(country, topic), "disclaimer": "These are general safety steps, not legal or financial advice. No action can guarantee recovery of money. Use official contact details you verify independently."}
