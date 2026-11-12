"""Value-aware validators for browser-facing HTTP security headers."""

from __future__ import annotations

import re
import urllib.parse

PASS = "PASS"
WARNING = "WARNING"
FAIL = "FAIL"
NOT_DETECTED = "NOT DETECTED"
UNKNOWN = "UNKNOWN"
NOT_APPLICABLE = "NOT APPLICABLE"


def _result(status: str, explanation: str, contribution: int = 0, evidence: str = "") -> dict:
    return {"status": status, "explanation": explanation, "contribution": contribution, "evidence": evidence}


def validate_hsts(value: str | None, *, is_https: bool = True) -> dict:
    if not is_https:
        return _result(NOT_APPLICABLE, "HSTS is only accepted by browsers when delivered over HTTPS.", evidence=value or "")
    if value is None:
        return _result(NOT_DETECTED, "The HTTPS response did not include HSTS. This is a hardening opportunity, not evidence of fraud.", 1)
    directives: dict[str, str | None] = {}
    for item in value.split(";"):
        piece = item.strip()
        if not piece:
            continue
        name, sep, raw = piece.partition("=")
        key = name.strip().lower()
        if not re.fullmatch(r"[a-z][a-z0-9-]*", key) or key in directives:
            return _result(FAIL, "The HSTS value contains an invalid or duplicate directive.", 2, value)
        directives[key] = raw.strip().strip('"') if sep else None
    age = directives.get("max-age")
    if age is None or not age.isdigit():
        return _result(FAIL, "HSTS must include a non-negative integer max-age directive.", 2, value)
    if int(age) == 0:
        return _result(WARNING, "HSTS is present, but max-age=0 disables the browser's HSTS protection.", 1, value)
    unknown = set(directives) - {"max-age", "includesubdomains", "preload"}
    if unknown:
        return _result(WARNING, f"HSTS is active, but contains unrecognized directives: {', '.join(sorted(unknown))}.", 1, value)
    scope = "including subdomains" if "includesubdomains" in directives else "this host only"
    preload = "; preload is declared" if "preload" in directives else "; preload is not declared (optional)"
    return _result(PASS, f"HSTS is active for {scope} with max-age={age}{preload}.", evidence=value)


def _split_csp(value: str) -> tuple[list[tuple[str, list[str]]], str | None]:
    directives: list[tuple[str, list[str]]] = []
    seen = set()
    for raw in value.split(";"):
        tokens = raw.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if not re.fullmatch(r"[a-z][a-z0-9-]*", name):
            return [], "A directive name is malformed."
        if name in seen:
            return [], f"The {name} directive appears more than once."
        seen.add(name)
        values = tokens[1:]
        for token in values:
            if token.startswith("'") != token.endswith("'"):
                return [], f"The {name} directive contains an unmatched quote."
        directives.append((name, values))
    if not directives:
        return [], "No valid policy directives were found."
    return directives, None


def validate_csp(value: str | None) -> dict:
    if value is None:
        return _result(NOT_DETECTED, "No Content-Security-Policy was returned. CSP helps restrict the sources a page may load.", 1)
    directives, error = _split_csp(value)
    if error:
        return _result(FAIL, f"The Content-Security-Policy could not be parsed: {error}", 2, value)
    values = dict(directives)
    script_sources = values.get("script-src", values.get("default-src", []))
    unsafe = {token.lower() for token in script_sources} & {"'unsafe-inline'", "'unsafe-eval'", "*", "http:"}
    concerns = []
    if unsafe:
        concerns.append(f"script policy permits {', '.join(sorted(unsafe))}")
    if "script-src" not in values and "default-src" not in values:
        concerns.append("no script-src or default-src fallback is defined")
    if "object-src" not in values or "'none'" not in {token.lower() for token in values.get("object-src", [])}:
        concerns.append("object-src 'none' is not defined")
    if concerns:
        return _result(WARNING, "CSP syntax is valid, but " + "; ".join(concerns) + ".", 1, value)
    return _result(PASS, "CSP syntax is valid and includes a script source policy and object-src 'none'. Review all directives for the site's needs.", evidence=value)


def validate_x_content_type_options(value: str | None) -> dict:
    if value is None:
        return _result(NOT_DETECTED, "X-Content-Type-Options was not returned. Browsers may MIME-sniff some responses.", 1)
    if value.strip().lower() == "nosniff":
        return _result(PASS, "The response uses nosniff, which asks browsers to respect the declared content type.", evidence=value)
    return _result(FAIL, "The header value is not the expected nosniff token.", 1, value)


def validate_x_frame_options(value: str | None) -> dict:
    if value is None:
        return _result(NOT_DETECTED, "X-Frame-Options was not returned. A CSP frame-ancestors directive can provide modern framing control.", 1)
    normalized = value.strip().upper()
    if normalized == "DENY":
        return _result(PASS, "DENY blocks this page from being framed by any site.", evidence=value)
    if normalized == "SAMEORIGIN":
        return _result(PASS, "SAMEORIGIN allows framing by pages from the same origin.", evidence=value)
    if normalized.startswith("ALLOW-FROM"):
        return _result(WARNING, "ALLOW-FROM is obsolete and is not consistently enforced by modern browsers. Use CSP frame-ancestors.", 1, value)
    return _result(FAIL, "The X-Frame-Options value is not a supported DENY or SAMEORIGIN policy.", 1, value)


REFERRER_POLICIES = {
    "no-referrer": "sends no referrer information",
    "no-referrer-when-downgrade": "sends the full referrer except on downgrades",
    "origin": "sends only the origin",
    "origin-when-cross-origin": "sends the origin cross-site and the full URL same-site",
    "same-origin": "sends referrer information only to the same origin",
    "strict-origin": "sends only the origin, and not on downgrades",
    "strict-origin-when-cross-origin": "sends the origin cross-site, the full URL same-site, and not on downgrades",
    "unsafe-url": "can send the full URL, including its path and query, cross-site",
}
STRONG_REFERRER_POLICIES = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}


def validate_referrer_policy(value: str | None) -> dict:
    if value is None:
        return _result(NOT_DETECTED, "Referrer-Policy was not returned. The browser's default behavior may apply.", 1)
    tokens = [token.strip().lower() for token in value.split(",") if token.strip()]
    if not tokens or any(token not in REFERRER_POLICIES for token in tokens):
        return _result(FAIL, "The Referrer-Policy value contains an unrecognized policy token.", 1, value)
    effective = tokens[-1]
    if effective in STRONG_REFERRER_POLICIES:
        return _result(PASS, f"{effective} {REFERRER_POLICIES[effective]}.", evidence=value)
    return _result(WARNING, f"{effective} is valid, but {REFERRER_POLICIES[effective]}; consider a stricter policy.", 1, value)


def _split_policy_members(value: str) -> list[str] | None:
    members, current = [], []
    depth, quoted, escaped = 0, False, False
    for char in value:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\" and quoted:
            current.append(char)
            escaped = True
            continue
        if char == '"':
            quoted = not quoted
        elif not quoted and char == "(":
            depth += 1
        elif not quoted and char == ")":
            depth -= 1
            if depth < 0:
                return None
        if char == "," and not quoted and depth == 0:
            members.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if quoted or depth != 0:
        return None
    members.append("".join(current).strip())
    return members


def validate_permissions_policy(value: str | None) -> dict:
    if value is None:
        return _result(NOT_DETECTED, "Permissions-Policy was not returned. This header can limit browser features such as camera and geolocation.", 0)
    members = _split_policy_members(value)
    if members is None or not members or any(not member for member in members):
        return _result(FAIL, "The Permissions-Policy dictionary has malformed separators or parentheses.", 1, value)
    seen = set()
    broad = []
    for member in members:
        match = re.fullmatch(r"\s*([a-z][a-z0-9_.*-]*)\s*=\s*(\*|\((.*)\))\s*", member, re.I)
        if not match:
            return _result(FAIL, "A Permissions-Policy member does not match feature=allowlist syntax.", 1, value)
        feature = match.group(1).lower()
        if feature in seen:
            return _result(FAIL, f"The {feature} feature is declared more than once.", 1, value)
        seen.add(feature)
        raw_allowlist = match.group(2)
        if raw_allowlist == "*":
            broad.append(feature)
            continue
        content = (match.group(3) or "").strip()
        if not content:
            continue
        tokens = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"|([^\s]+)', content)
        parsed = [quoted or bare for quoted, bare in tokens]
        normalized_content = re.sub(r'"([^"\\]*(?:\\.[^"\\]*)*)"', lambda match: match.group(1).replace('\\"', '"'), content)
        if not parsed or " ".join(parsed) != normalized_content:
            return _result(FAIL, f"The {feature} allowlist contains malformed values.", 1, value)
        for token in parsed:
            lowered = token.lower()
            if lowered in {"self", "src", "'self'", "'src'", "'none'"}:
                continue
            if token == "*":
                broad.append(feature)
                continue
            origin = urllib.parse.urlsplit(token)
            if origin.scheme not in {"https", "http"} or not origin.hostname or origin.username or origin.password or origin.path not in {"", "/"} or origin.query or origin.fragment:
                return _result(FAIL, f"The {feature} allowlist contains an invalid origin.", 1, value)
    if broad:
        return _result(WARNING, f"The policy is syntactically valid, but {', '.join(sorted(set(broad)))} uses a wildcard allowlist.", 1, value)
    return _result(PASS, "The policy dictionary parsed successfully. Its allowlists do not use wildcards; explicitly listed origins remain limited to those origins.", evidence=value)


VALIDATORS = (
    ("Strict-Transport-Security", validate_hsts),
    ("Content-Security-Policy", validate_csp),
    ("X-Content-Type-Options", validate_x_content_type_options),
    ("X-Frame-Options", validate_x_frame_options),
    ("Referrer-Policy", validate_referrer_policy),
    ("Permissions-Policy", validate_permissions_policy),
)


def validate_security_headers(headers, *, is_https: bool) -> list[dict]:
    """Validate actual response values and preserve the exact observed value."""
    findings = []
    for header, validator in VALIDATORS:
        value = headers.get(header)
        result = validator(value, is_https=is_https) if header == "Strict-Transport-Security" else validator(value)
        findings.append({"name": header, **result})
    return findings
