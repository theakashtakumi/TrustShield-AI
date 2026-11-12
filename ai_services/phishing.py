"""Explainable URL, IDN, brand similarity, and credential-form checks."""

from __future__ import annotations

import difflib
import ipaddress
import json
import re
import urllib.parse
from pathlib import Path

BRAND_DATA = Path(__file__).with_name("brand_domains.json")


def _ascii_host(value: str) -> str:
    try:
        host = urllib.parse.urlsplit(value if "://" in value else "https://" + value).hostname or ""
        return host.rstrip(".").lower().encode("idna").decode("ascii")
    except (ValueError, UnicodeError):
        return ""


def _registrable_label(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return ""
    except ValueError:
        pass
    labels = [label for label in host.split(".") if label]
    if len(labels) < 2:
        return labels[0] if labels else ""
    suffix2 = {"co.in", "com.in", "net.in", "org.in", "co.uk", "com.au", "co.nz", "co.jp"}
    suffix = ".".join(labels[-2:])
    return labels[-3] if suffix in suffix2 and len(labels) >= 3 else labels[-2]


def _load_brands(path=None):
    try:
        rows = json.loads(Path(path or BRAND_DATA).read_text(encoding="utf-8"))
        return [row for row in rows if isinstance(row, dict) and isinstance(row.get("brand"), str)
                and isinstance(row.get("domains"), list) and row["domains"]]
    except (OSError, ValueError, TypeError):
        return []


def analyze_phishing(url: str, *, page_text="", password_input_count=0, password_form_actions=None, redirects=None, brand_file=None):
    host = _ascii_host(url)
    findings = []

    def add(code, name, severity, evidence, explanation, action):
        findings.append({"id": code, "name": name, "severity": severity, "evidence": str(evidence)[:240],
                         "explanation": explanation, "recommended_action": action, "source": "Automated heuristic"})

    if not host:
        return {"findings": [], "threat_intelligence": {"status": "not_configured", "message": "No threat-intelligence provider is configured."},
                "assessment": "No usable hostname was available for heuristic checks."}
    labels = host.split(".")
    unicode_host = urllib.parse.unquote(host)
    idn = any(label.startswith("xn--") for label in labels)
    if idn:
        add("phishing.idn", "Internationalized domain name", "moderate", host,
            "The hostname contains an IDN/punycode label. Some IDNs can resemble other scripts; this alone does not show impersonation.",
            "Compare the address with the brand's independently verified official domain before entering credentials.")
    raw_host = urllib.parse.urlsplit(url if "://" in url else "https://" + url).hostname or ""
    if raw_host and not raw_host.isascii() and not idn:
        add("phishing.unicode_host", "Unicode hostname", "low", raw_host,
            "The submitted address uses Unicode characters. Browser display and IDN normalization can vary.",
            "Check the normalized address and reach the business through a trusted bookmark or known official site.")

    host_label = re.sub(r"[^a-z0-9]", "", _registrable_label(host))
    brands = _load_brands(brand_file)
    for entry in brands:
        brand = entry["brand"]
        official = [_ascii_host(domain) for domain in entry["domains"]]
        if any(host == domain or host.endswith("." + domain) for domain in official if domain):
            continue
        raw_label = _registrable_label(host)
        label_tokens = re.split(r"[^a-z0-9]+", raw_label)
        matched_domain = next((domain for domain in official if host_label and domain and
                               (difflib.SequenceMatcher(None, host_label, re.sub(r"[^a-z0-9]", "", _registrable_label(domain))).ratio() >= 0.76
                                or _registrable_label(domain) in label_tokens)), None)
        if matched_domain:
            similarity = round(difflib.SequenceMatcher(None, host_label, re.sub(r"[^a-z0-9]", "", _registrable_label(matched_domain))).ratio(), 2)
            add("phishing.brand_similarity", f"Possible {brand} domain similarity", "moderate", host,
                f"The registrable hostname resembles a configured {brand} reference domain (string similarity {similarity:.2f}). Similarity is a lead for review, not proof of impersonation.",
                "Do not sign in from this link. Compare with the official domain listed in a trusted source.")
            break

    actions = password_form_actions or []
    unrelated_actions = [action for action in actions if action and _ascii_host(action) and
                         not (_ascii_host(action) == host or _ascii_host(action).endswith("." + host) or host.endswith("." + _ascii_host(action)))]
    if password_input_count and unrelated_actions:
        add("phishing.cross_domain_password_form", "Password form sends to a different domain", "high", unrelated_actions[0],
            "A password field's form action points outside the page domain. Legitimate identity providers exist, so the relationship still needs verification.",
            "Do not submit credentials until the destination is confirmed through the service's official sign-in flow.")
    elif password_input_count and urllib.parse.urlsplit(url if "://" in url else "https://" + url).scheme.lower() != "https":
        add("phishing.password_over_http", "Password form on an unencrypted page", "high", host,
            "A password field was observed on a page using HTTP. Credentials could be exposed in transit.",
            "Do not enter a password. Navigate to the service using its independently verified HTTPS address.")

    if redirects:
        cross_host = [item for item in redirects if _ascii_host(item.get("to", "")) and _ascii_host(item.get("from", "")) != _ascii_host(item.get("to", ""))]
        if cross_host:
            add("phishing.cross_host_redirect", "Cross-domain redirect observed", "low", cross_host[-1].get("to", ""),
                "The scan followed a redirect to another hostname. Redirects are common, but the destination should match the expected service.",
                "Review the final address before entering account or payment information.")

    return {"findings": findings, "threat_intelligence": {"status": "not_configured", "message": "No threat-intelligence provider was queried; there is no threat-feed match result."},
            "assessment": "Heuristic indicators only. A lookalike name or login form is not a fraud verdict."}
