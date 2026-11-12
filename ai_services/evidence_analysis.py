"""Local OCR/text extraction and consent-gated structured evidence analysis."""

from __future__ import annotations

import re
import urllib.parse

from .common import run_analysis
from .privacy import redact_for_provider

MAX_EXTRACT_CHARS = 12_000


def extract_evidence_text(name, mime_type, data):
    """Extract text locally. Optional OCR libraries are imported only when needed."""
    if mime_type == "text/plain":
        try:
            return {"status": "extracted", "text": data.decode("utf-8-sig", errors="replace")[:MAX_EXTRACT_CHARS], "method": "utf-8"}
        except (AttributeError, TypeError):
            return {"status": "invalid", "text": "", "method": "none"}
    if mime_type == "application/pdf":
        try:
            import fitz
        except ImportError:
            return {"status": "dependency_missing", "text": "", "method": "none", "message": "PDF extraction is unavailable; install optional PyMuPDF to enable it."}
        try:
            document = fitz.open(stream=data, filetype="pdf")
            if document.is_encrypted or document.page_count <= 0:
                return {"status": "unreadable", "text": "", "method": "pymupdf"}
            pages = []
            for page in document[:10]:
                pages.append(page.get_text("text")[:MAX_EXTRACT_CHARS])
                if sum(map(len, pages)) >= MAX_EXTRACT_CHARS:
                    break
            text = "\n".join(pages)[:MAX_EXTRACT_CHARS]
            return {"status": "extracted" if text.strip() else "no_text", "text": text, "method": "pymupdf"}
        except Exception:
            return {"status": "unreadable", "text": "", "method": "pymupdf"}
    if mime_type in {"image/png", "image/jpeg", "image/webp"}:
        try:
            from PIL import Image
            import pytesseract
        except ImportError:
            return {"status": "dependency_missing", "text": "", "method": "none", "message": "OCR is unavailable; install Pillow, pytesseract, and the Tesseract OCR executable to enable it."}
        try:
            import io
            image = Image.open(io.BytesIO(data))
            image.verify()
            image = Image.open(io.BytesIO(data))
            if image.width <= 0 or image.height <= 0 or image.width * image.height > 20_000_000:
                return {"status": "size_limited", "text": "", "method": "tesseract"}
            text = pytesseract.image_to_string(image, timeout=5)[:MAX_EXTRACT_CHARS]
            return {"status": "extracted" if text.strip() else "no_text", "text": text, "method": "tesseract"}
        except Exception:
            return {"status": "ocr_failed", "text": "", "method": "tesseract"}
    return {"status": "unsupported", "text": "", "method": "none"}


def extract_entities(text, report=None):
    text = text or ""
    dates = re.findall(r"\b(?:20\d{2}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]20\d{2})\b", text)[:8]
    amounts = re.findall(r"(?:(?:INR|USD|EUR|GBP|Rs\.?|₹|\$|€|£)\s*)\d[\d,]*(?:\.\d{1,2})?", text, re.I)[:8]
    domains = []
    for value in re.findall(r"(?:https?://|www\.)[^\s<>\]\[()\"']+", text, re.I)[:8]:
        host = urllib.parse.urlsplit(value if "://" in value else "https://" + value).hostname
        if host and host not in domains:
            domains.append(host.lower())
    refs = []
    for value in re.findall(r"\b(?:order|transaction|txn|reference|receipt|invoice|payment)\s*(?:id|no\.?|number|ref(?:erence)?)?\s*[:#-]?\s*([A-Z0-9-]{5,32})\b", text, re.I)[:8]:
        refs.append("••••" + value[-4:])
    order_ids = ["••••" + value[-4:] for value in re.findall(r"\border\s*(?:id|no\.?|number)\s*[:#-]?\s*([A-Z0-9-]{5,32})\b", text, re.I)[:8]]
    businesses = re.findall(r"\b(?:merchant|seller|business|store)\s*[:#-]\s*([^\n\r,;]{2,100})", text, re.I)[:6]
    return {"dates": list(dict.fromkeys(dates)), "amounts": list(dict.fromkeys(amounts)),
            "business_names": list(dict.fromkeys(([str(report.get("business", ""))[:100]] if report and report.get("business") else []) + [value.strip() for value in businesses])),
            "website_domains": domains, "order_ids": list(dict.fromkeys(order_ids)), "transaction_references": list(dict.fromkeys(refs))}


def analyze_evidence_bundle(report, files, *, consent=False, provider=None):
    extracted_files = []
    text_parts = []
    text_items = []
    for item in files[:4]:
        extraction = extract_evidence_text(item.get("name", ""), item.get("mime_type", ""), item.get("content", b""))
        text = extraction.get("text", "")
        if text:
            text_parts.append(f"[{item.get('name', 'attachment')} | {item.get('mime_type', 'unknown')}]:\n{text}")
        text_items.append({"name": item.get("name", "evidence"), "mime_type": item.get("mime_type", ""), "text": text})
        extracted_files.append({"name": item.get("name", "Evidence file"), "mime_type": item.get("mime_type", ""),
                                "extraction_status": extraction["status"], "method": extraction.get("method", "none"),
                                "characters_extracted": len(text)})
    joined = "\n\n".join(text_parts)[:MAX_EXTRACT_CHARS]
    entities = extract_entities(joined, report)
    incident_date = str(report.get("incident_date", ""))
    inconsistencies = []
    if incident_date and entities["dates"] and incident_date not in entities["dates"]:
        inconsistencies.append("The report date differs from dates extracted from the attached text. Date formats may differ; moderator review is needed.")
    report_host = urllib.parse.urlsplit(str(report.get("url", ""))).hostname or ""
    unrelated_domains = [host for host in entities["website_domains"] if host != report_host and not host.endswith("." + report_host) and not report_host.endswith("." + host)]
    if unrelated_domains:
        inconsistencies.append("Extracted website addresses include a domain different from the reported website: " + ", ".join(unrelated_domains[:4]) + ".")
    submitted_amount = re.search(r"(?:INR|USD|EUR|GBP|Rs\.?|₹|\$|€|£)\s*([\d,]+(?:\.\d{1,2})?)", str(report.get("amount", "")), re.I)
    if submitted_amount and entities["amounts"]:
        reported_number = submitted_amount.group(1).replace(",", "")
        extracted_numbers = {match.group(1).replace(",", "") for value in entities["amounts"] if (match := re.search(r"([\d,]+(?:\.\d{1,2})?)\s*$", value))}
        if extracted_numbers and reported_number not in extracted_numbers:
            inconsistencies.append("The submitted amount differs from amount text extracted from the evidence. Currency or OCR errors may explain the difference; moderator review is needed.")
    local = {"status": "local_only", "label": "Local extraction · not independent verification", "files": extracted_files,
             "extracted_information": entities, "potential_inconsistencies": inconsistencies,
             "text_available": bool(joined), "text_characters": len(joined),
             "limitations": "Text extraction/OCR can be incomplete or wrong. It does not establish file authenticity, payment, identity, or truth."}
    if not consent:
        local["ai"] = {"status": "not_consented", "provider": "none", "findings": [],
                       "message": "Private evidence was not sent to an AI provider. Local extraction only."}
        return local
    if not joined:
        local["ai"] = {"status": "skipped", "provider": "none", "findings": [],
                       "message": "No extractable text was available for AI analysis."}
        return local
    sanitized_files = [{"name": redact_for_provider(item["name"], 100), "mime_type": item["mime_type"],
                        "text": redact_for_provider(item["text"], 5_000)} for item in text_items]
    payload = {"category": str(report.get("category", ""))[:100], "reported_domain": report_host,
               "incident_date": str(report.get("incident_date", ""))[:10],
               "complaint_summary": redact_for_provider(str(report.get("details", "")), 2_000),
               "attachments": sanitized_files[:4]}
    provider_text = "\n".join(item["text"] for item in sanitized_files if item["text"])
    result = run_analysis("evidence", "Extract limited transaction and date facts from the provided OCR/text. Compare only to the supplied complaint. Do not authenticate documents, infer truth, expose full identifiers, or declare fraud.", payload, "evidence", source_text=provider_text, provider=provider)
    local["ai"] = result
    return local
