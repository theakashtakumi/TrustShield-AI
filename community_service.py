"""Database-backed, privacy-safe community query helpers."""
from __future__ import annotations
import urllib.parse
import re

PUBLIC_STATUSES = ("Under Review", "More Information Required", "Partially Supported", "Verified Findings", "Inconsistencies Found", "Disputed")


def report_domain(url: str) -> str:
    try:
        host = (urllib.parse.urlsplit(url).hostname or "").lower().rstrip(".")
        return host[4:] if host.startswith("www.") else host
    except ValueError:
        return ""

def safe_description(value: str) -> str:
    """Keep public summaries useful while removing common contact/credential leaks."""
    text = " ".join((value or "").split())
    text = re.sub(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", "[email hidden]", text, flags=re.I)
    text = re.sub(r"(?<!\w)(?:\+?\d[\d ()-]{7,}\d)(?!\w)", "[number hidden]", text)
    text = re.sub(r"\b(otp|password|passcode|pin)\s*(?:is|:|=)?\s*\S+", r"\1 [hidden]", text, flags=re.I)
    return text

def public_counts(conn, domain: str) -> dict:
    domain = domain.lower().removeprefix("www.")
    count_statuses = ("Submitted", *PUBLIC_STATUSES)
    placeholders = ",".join("?" for _ in count_statuses)
    rows = [dict(row) for row in conn.execute(
        f"SELECT id,url,domain,category,status,created_at,((evidence_name<>'') OR EXISTS(SELECT 1 FROM report_attachments a WHERE a.report_id=reports.id) OR EXISTS(SELECT 1 FROM report_followups f WHERE f.report_id=reports.id AND f.evidence_path<>'')) AS evidence_any FROM reports WHERE domain=? AND status IN ({placeholders}) ORDER BY created_at DESC",
        (domain, *count_statuses))]
    by_status, by_category = {}, {}
    for row in rows:
        by_status[row["status"]] = by_status.get(row["status"], 0) + 1
        by_category[row["category"]] = by_category.get(row["category"], 0) + 1
    return {"domain": domain, "total": len(rows), "under_review": by_status.get("Under Review", 0),
            "more_information_required": by_status.get("More Information Required", 0),
            "partially_supported": by_status.get("Partially Supported", 0), "verified_findings": by_status.get("Verified Findings", 0),
            "disputed": by_status.get("Disputed", 0), "unverified_submitted": by_status.get("Submitted", 0),
            "reviewed_evidence_reports": sum(1 for row in rows if row["evidence_any"] and row["status"] in {"Partially Supported", "Verified Findings"}),
            "by_status": by_status, "by_category": by_category,
            "reports": [{"id": r["id"], "category": r["category"], "status": r["status"], "created_at": r["created_at"], "evidence_reviewed": bool(r["evidence_any"] and r["status"] in {"Partially Supported", "Verified Findings"})} for r in rows if r["status"] in PUBLIC_STATUSES][:20]}

def community_search(conn, *, query="", status="all", category="all", sort="latest", page=1, per_page=20, admin=False):
    visible = tuple(["Submitted", *PUBLIC_STATUSES, "Rejected"] if admin else PUBLIC_STATUSES)
    if status not in {"all", *visible}: status = "all"
    safe_page = max(1, min(int(page), 100000))
    where = ["status IN (" + ",".join("?" for _ in visible) + ")"]
    args: list[object] = list(visible)
    if status != "all":
        where.append("status=?"); args.append(status)
    if category != "all":
        where.append("category=?"); args.append(category)
    query = query.lower().strip()
    if query:
        searchable_description = "details" if admin else "public_summary"
        where.append(f"lower(url || ' ' || domain || ' ' || coalesce(business,'') || ' ' || category || ' ' || {searchable_description}) LIKE ?")
        args.append("%" + query.replace("%", "\\%").replace("_", "\\_") + "%")
    where_sql = " AND ".join(where)
    total = conn.execute(f"SELECT COUNT(*) FROM reports WHERE {where_sql}", args).fetchone()[0]
    order = "(SELECT COUNT(*) FROM reports r2 WHERE r2.domain=reports.domain AND r2.status IN (" + ",".join("?" for _ in visible) + ")) DESC, created_at DESC" if sort == "most_discussed" else "created_at DESC"
    query_args = list(args) + (list(visible) if sort == "most_discussed" else []) + [per_page, (safe_page - 1) * per_page]
    rows = [dict(row) for row in conn.execute(
        f"SELECT id,url,domain,business,category,public_summary,details,status,created_at,((evidence_name<>'') OR EXISTS(SELECT 1 FROM report_attachments a WHERE a.report_id=reports.id) OR EXISTS(SELECT 1 FROM report_followups f WHERE f.report_id=reports.id AND f.evidence_path<>'')) AS evidence_any,(SELECT COUNT(*) FROM reports r2 WHERE r2.domain=reports.domain AND r2.id<>reports.id AND r2.status IN ({','.join('?' for _ in visible)})) AS related_count FROM reports WHERE {where_sql} ORDER BY {order} LIMIT ? OFFSET ?",
        list(visible) + args + (list(visible) if sort == "most_discussed" else []) + [per_page, (safe_page - 1) * per_page])]
    for row in rows:
        row["description"] = safe_description(row.pop("public_summary", "") or row.get("details", ""))[:240]
        row.pop("details", None)
        row["evidence_submitted"] = bool(row.pop("evidence_any", False))
        row["evidence_reviewed"] = row["evidence_submitted"] and row["status"] in {"Partially Supported", "Verified Findings"}
        row["reference_code"] = f"TSH-{row['id']:06d}"
    return {"reports": rows, "page": safe_page, "per_page": per_page, "total": total, "pages": (total + per_page - 1) // per_page}
