"""Deterministic evidence triage. Results are review aids, never proof of fraud."""
from __future__ import annotations
import difflib
import hashlib
import ipaddress
import re
import urllib.parse


def url_host(value: str) -> str:
    try:
        parts = urllib.parse.urlsplit(value if "://" in value else "https://" + value)
        host = (parts.hostname or "").lower().rstrip(".")
        return host.encode("idna").decode("ascii")
    except (ValueError, UnicodeError):
        return ""

def related_hosts(left: str, right: str) -> bool:
    a, b = url_host(left), url_host(right)
    if not a or not b: return False
    # Treat the conventional www host as the bare site for subdomain comparisons.
    if a.startswith("www."): a = a[4:]
    if b.startswith("www."): b = b[4:]
    try:
        ipaddress.ip_address(a)
        ipaddress.ip_address(b)
        return a == b
    except ValueError:
        return a == b or a.endswith("." + b) or b.endswith("." + a)

def inspect_file(name: str, mime: str, data: bytes) -> dict:
    valid = bool(data)
    readable = False
    if mime == "image/png":
        valid = data.startswith(b"\x89PNG\r\n\x1a\n")
        readable = valid and len(data) >= 24 and data[12:16] == b"IHDR"
    elif mime == "image/jpeg":
        valid = data.startswith(b"\xff\xd8\xff") and data.rstrip().endswith(b"\xff\xd9")
        readable = valid and len(data) > 4
    elif mime == "image/webp":
        valid = len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP"
        readable = valid
    elif mime == "application/pdf":
        valid = data.startswith(b"%PDF-")
        readable = valid and b"%%EOF" in data[-2048:]
    elif mime == "text/plain":
        try:
            decoded = data.decode("utf-8")
            readable = bool(decoded.strip())
            valid = readable and "\x00" not in decoded
        except UnicodeDecodeError:
            valid = readable = False
    return {"valid": valid, "readable": readable, "sha256": hashlib.sha256(data).hexdigest(), "name": name, "mime_type": mime, "size_bytes": len(data)}

def analyze_evidence(report: dict, files: list[dict], related_reports: list[dict], duplicate_hashes: set[str]) -> dict:
    category = str(report.get("category", "")).lower()
    details = str(report.get("details", ""))
    submitted_urls = [line.strip() for line in str(report.get("links", "")).splitlines() if line.strip()]
    host = url_host(str(report.get("url", "")))
    checks = []
    def add(check_id, label, status, explanation, evidence=""):
        checks.append({"id": check_id, "label": label, "status": status, "explanation": explanation, "evidence": evidence})
    add("evidence_authenticity", "Evidence authenticity", "NOT ASSESSED", "File structure and readable content cannot establish who created a file or whether it was altered. No cryptographic signature or independent source verification is available.")
    add("claim_support", "Claim support", "NOT DETERMINED", "A receipt or screenshot may support a specific event, but this system does not decide whether the overall allegation is true. A moderator must compare the claim with all available information.")
    if files:
        valid_files = [item for item in files if item.get("valid") and item.get("readable")]
        add("file_readability", "File validity and readability", "PASS" if len(valid_files) == len(files) else "WARNING",
            f"{len(valid_files)} of {len(files)} attached file(s) passed basic format/readability checks. This does not verify authenticity.", ", ".join(item["name"] for item in files))
        hash_counts = {}
        for item in files:
            hash_counts[item.get("sha256")] = hash_counts.get(item.get("sha256"), 0) + 1
        duplicates = [item["name"] for item in files if item.get("sha256") in duplicate_hashes or hash_counts.get(item.get("sha256"), 0) > 1]
        add("duplicate_file", "Duplicate file check", "WARNING" if duplicates else "PASS",
            "Matching file content exists in another report; moderators should compare context. This does not establish independent evidence." if duplicates else "No matching file hash was found in the current report store.", ", ".join(duplicates))
        category_terms = {
            "payment": ("receipt", "payment", "transaction", "order", "bank", "upi"),
            "product": ("product", "listing", "advert", "photo", "order"),
            "deliver": ("order", "tracking", "delivery", "receipt", "seller"),
            "refund": ("refund", "cancel", "order", "receipt", "seller"),
            "phish": ("link", "url", "email", "message", "phish"),
            "support": ("support", "contact", "phone", "message", "call"),
            "impersonat": ("brand", "business", "website", "domain", "logo"),
            "information": ("account", "privacy", "personal", "data", "email"),
            "account": ("account", "login", "password", "security", "email"),
        }
        keywords = next((value for key, value in category_terms.items() if key in category), ())
        relevant = any(any(word in (item["name"] + " " + item.get("ocr_text", "")).lower() for word in keywords) for item in files)
        add("category_relevance", "Category relevance", "WARNING" if not relevant else "PASS",
            "Filename hints do not clearly match the selected category; a moderator should review relevance." if not relevant else "File naming provides a limited category hint only. A moderator must assess its actual relevance.", ", ".join(item["name"] for item in files))
    else:
        add("file_readability", "File validity and readability", "NOT PROVIDED", "No supporting file was attached.")
        add("duplicate_file", "Duplicate file check", "NOT APPLICABLE", "There are no files to compare.")
        add("category_relevance", "Category relevance", "UNKNOWN", "There is no attachment to assess for category relevance.")
    incident_date = str(report.get("incident_date", ""))
    created = str(report.get("created_at", ""))[:10]
    try:
        from datetime import datetime, timedelta
        submitted_at = datetime.fromisoformat(str(report.get("created_at", "")).replace("Z", "+00:00"))
        timezone_offset = int(report.get("timezone_offset_minutes", 0))
        if -840 <= timezone_offset <= 840:
            created = (submitted_at - timedelta(minutes=timezone_offset)).date().isoformat()
    except (ValueError, TypeError):
        pass
    date_ok = not incident_date or (bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}", incident_date)) and incident_date <= created)
    add("date_consistency", "Date consistency", "PASS" if date_ok else "WARNING",
        "The stated incident date is not later than the submission date in the reporter’s local timezone. Dates are user supplied and are not independently verified." if date_ok else "The incident date appears later than the report submission date or is malformed; ask the reporter to clarify.", incident_date or "No incident date supplied")
    unrelated = [item for item in submitted_urls if not related_hosts(item, host)]
    add("url_relationship", "Related URL check", "WARNING" if unrelated else "PASS",
        "Some submitted links use a different domain. This may be expected; moderators should review their relationship." if unrelated else "Submitted links are on the reported domain or a related subdomain." if submitted_urls else "No additional URLs were supplied.", ", ".join(unrelated or submitted_urls))
    enough = len(details.strip()) >= 40 and bool(host) and bool(category)
    add("review_completeness", "Information for review", "PASS" if enough else "WARNING",
        "The report includes a website, category, and a description of useful length." if enough else "The report may need clearer event details, dates, or supporting material before review.", f"description characters: {len(details.strip())}")
    possible = []
    normalized = re.sub(r"\W+", " ", details.lower()).strip()
    for other in related_reports:
        ratio = difflib.SequenceMatcher(None, normalized, re.sub(r"\W+", " ", str(other.get("details", "")).lower()).strip()).ratio()
        date_gap = None
        if report.get("incident_date") and other.get("incident_date"):
            try:
                from datetime import date
                date_gap = abs((date.fromisoformat(report["incident_date"]) - date.fromisoformat(other["incident_date"])).days)
            except ValueError:
                pass
        if ratio >= .72 and (date_gap is None or date_gap <= 30):
            possible.append({"id": other["id"], "similarity": round(ratio, 2), "date_proximity_days": date_gap})
    return {"version": "1.0.0", "checks": checks, "possible_duplicates": possible, "assessment": "Needs human review. These checks can identify consistency questions but cannot authenticate evidence or establish wrongdoing."}
