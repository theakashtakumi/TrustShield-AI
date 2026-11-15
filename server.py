"""TrustShield AI: evidence-based website checks and community reports."""

from __future__ import annotations

import ipaddress
import json
import base64
from contextlib import contextmanager
import http.client
import hashlib
import hmac
import os
import re
import secrets
import socket
import sqlite3
import ssl
import time
from http.cookies import SimpleCookie, CookieError
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from security_headers import validate_security_headers, UNKNOWN, NOT_APPLICABLE, NOT_DETECTED, PASS, WARNING, FAIL
from trust_engine import SCANNER_VERSION, SCORING_WEIGHTS, make_finding, score_findings
from guidance_service import guidance_for
from evidence_service import analyze_evidence, inspect_file, related_hosts, url_host
from community_service import PUBLIC_STATUSES, community_search, public_counts, report_domain, safe_description
from ai_services.website_content import analyze_website_content
from ai_services.phishing import analyze_phishing
from ai_services.report_analysis import analyze_report as analyze_report_intelligence
from ai_services.provider import get_provider, provider_status
from ai_services.learning import evaluate_predictions

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "trustshield.db"
UPLOAD_DIR = ROOT / "uploads"
# Three 2 MiB uploads in base64 need a little over 8 MiB including JSON framing.
MAX_BODY = 9_000_000
TIMEOUT = 9
MAX_REDIRECTS = 5
RATE_BUCKETS = {}
RATE_LOCK = __import__("threading").Lock()
UPLOAD_MIMES = {"image/png": ".png", "image/jpeg": ".jpg", "image/webp": ".webp", "application/pdf": ".pdf", "text/plain": ".txt"}
REPORT_STATUSES = ("Submitted", "Under Review", "More Information Required", "Partially Supported", "Verified Findings", "Inconsistencies Found", "Rejected", "Disputed")
STATUS_TRANSITIONS = {
    "Submitted": {"Under Review", "More Information Required", "Rejected", "Disputed"},
    "Under Review": {"More Information Required", "Partially Supported", "Verified Findings", "Inconsistencies Found", "Rejected", "Disputed"},
    "More Information Required": {"Under Review", "Partially Supported", "Inconsistencies Found", "Rejected", "Disputed"},
    "Partially Supported": {"Under Review", "More Information Required", "Verified Findings", "Inconsistencies Found", "Rejected", "Disputed"},
    "Verified Findings": {"Under Review", "Inconsistencies Found", "Disputed"},
    "Inconsistencies Found": {"Under Review", "More Information Required", "Partially Supported", "Rejected", "Disputed"},
    "Rejected": {"Under Review", "Disputed"},
    "Disputed": {"Under Review", "More Information Required", "Partially Supported", "Verified Findings", "Inconsistencies Found", "Rejected"},
}


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Validate each redirect before urllib makes the next network request."""
    def __init__(self, max_redirects=MAX_REDIRECTS):
        super().__init__()
        self.max_redirects = max_redirects
        self.redirects = 0
        self.hops = []
        self.resolution_cache = {}

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.redirects += 1
        if self.redirects > self.max_redirects:
            raise ValueError("The website redirected too many times.")
        absolute = urllib.parse.urljoin(req.full_url, newurl)
        parts = urllib.parse.urlsplit(absolute)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
            raise ValueError("The website redirected to an invalid address.")
        self.resolution_cache[parts.hostname.lower()] = safe_public_host(parts.hostname)
        self.hops.append({"from": req.full_url, "to": absolute, "status": code})
        return super().redirect_request(req, fp, code, msg, headers, absolute)


class PinnedHTTPConnection(http.client.HTTPConnection):
    """Connect to the validated IP while preserving the original Host header."""
    def __init__(self, host, *, pinned_ip, timeout, **kwargs):
        self.pinned_ip = pinned_ip
        super().__init__(host, timeout=timeout, **kwargs)

    def connect(self):
        if self._tunnel_host:
            raise OSError("HTTP proxy tunnels are disabled for website scans.")
        self.sock = socket.create_connection((self.pinned_ip, self.port), self.timeout, self.source_address)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """TLS connection pinned to a checked IP; certificate validation uses the URL host."""
    def __init__(self, host, *, pinned_ip, tls_name, timeout, context, **kwargs):
        self.pinned_ip = pinned_ip
        self.tls_name = tls_name
        self.certificate = None
        super().__init__(host, timeout=timeout, context=context, **kwargs)

    def connect(self):
        if self._tunnel_host:
            raise OSError("HTTP proxy tunnels are disabled for website scans.")
        raw = socket.create_connection((self.pinned_ip, self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.tls_name)
        self.certificate = self.sock.getpeercert()


class PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, resolution_cache=None):
        super().__init__()
        self.resolution_cache = resolution_cache if resolution_cache is not None else {}

    def http_open(self, req):
        parts = urllib.parse.urlsplit(req.full_url)
        addresses = self.resolution_cache.get(parts.hostname.lower())
        if addresses is None:
            addresses = safe_public_host(parts.hostname)
            self.resolution_cache[parts.hostname.lower()] = addresses
        ip = addresses[0]
        return self.do_open(lambda host, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, **kwargs:
                            PinnedHTTPConnection(host, pinned_ip=ip, timeout=timeout, **kwargs), req)


class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, context, resolution_cache=None):
        super().__init__(context=context)
        self.connections = []
        self.resolution_cache = resolution_cache if resolution_cache is not None else {}

    def https_open(self, req):
        parts = urllib.parse.urlsplit(req.full_url)
        addresses = self.resolution_cache.get(parts.hostname.lower())
        if addresses is None:
            addresses = safe_public_host(parts.hostname)
            self.resolution_cache[parts.hostname.lower()] = addresses
        ip = addresses[0]
        def factory(host, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, **kwargs):
            connection = PinnedHTTPSConnection(host, pinned_ip=ip, tls_name=parts.hostname,
                                               timeout=timeout, context=self._context, **kwargs)
            self.connections.append(connection)
            return connection
        return self.do_open(factory, req)


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def audit_admin_action(conn, actor_id, action, resource_type, resource_id="", *, previous=None, new=None, metadata=None):
    """Append an administrator action without storing secrets or private report text."""
    conn.execute(
        "INSERT INTO admin_audit_events(actor_id,action,resource_type,resource_id,previous_json,new_json,metadata_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
        (actor_id, str(action)[:80], str(resource_type)[:60], str(resource_id)[:100],
         json.dumps(previous or {}, ensure_ascii=False), json.dumps(new or {}, ensure_ascii=False),
         json.dumps(metadata or {}, ensure_ascii=False), now()),
    )


def scanner_configuration():
    with db() as conn:
        values = {row["setting_key"]: row["setting_value"] for row in conn.execute("SELECT setting_key,setting_value FROM scanner_settings")}
    return {
        "request_timeout_seconds": max(3, min(20, int(values.get("request_timeout_seconds", TIMEOUT)))),
        "max_redirects": max(0, min(10, int(values.get("max_redirects", MAX_REDIRECTS)))),
        "phishing_heuristics_enabled": values.get("phishing_heuristics_enabled", "true") == "true",
        "ai_content_analysis_enabled": values.get("ai_content_analysis_enabled", "true") == "true",
    }


def persist_ai_results(conn, resource_type, resource_id, value, *, user_consented=False):
    """Persist model provenance and validated outputs only; never store prompt/input text."""
    saved = []
    if isinstance(value, dict):
        if value.get("analysis_type") and value.get("provider") not in {None, "", "none"}:
            created = now()
            domain_row = conn.execute("SELECT domain FROM scans WHERE id=?", (int(resource_id),)).fetchone() if resource_type == "scan" else conn.execute("SELECT domain FROM reports WHERE id=?", (int(resource_id),)).fetchone()
            resource_domain = str(domain_row[0] if domain_row else "")[:253]
            cursor = conn.execute(
                "INSERT INTO ai_runs(resource_type,resource_id,domain,analysis_type,provider,model,model_version,prompt_version,input_sha256,status,result_json,usage_json,user_consented,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (resource_type, int(resource_id), resource_domain, str(value.get("analysis_type", ""))[:80], str(value.get("provider", ""))[:40],
                 str(value.get("model", ""))[:120], str(value.get("model_version", "unknown"))[:80],
                 str(value.get("prompt_version", ""))[:80], str(value.get("input_sha256", ""))[:64],
                 str(value.get("status", "error"))[:30], json.dumps(value, ensure_ascii=False), json.dumps(value.get("usage", {})), int(user_consented), created))
            value["analysis_id"] = cursor.lastrowid
            saved.append(cursor.lastrowid)
        for child in list(value.values()):
            if isinstance(child, dict):
                saved.extend(persist_ai_results(conn, resource_type, resource_id, child, user_consented=user_consented))
    elif isinstance(value, list):
        for child in value:
            saved.extend(persist_ai_results(conn, resource_type, resource_id, child, user_consented=user_consented))
    return saved


def collect_report_evidence(report_id, report_row):
    """Read only bounded files inside the private evidence directory."""
    sources = []
    if report_row["evidence_path"]:
        sources.append((report_row["evidence_name"], report_row["evidence_path"], ""))
    with db() as conn:
        for item in conn.execute("SELECT evidence_name,evidence_path,mime_type FROM report_attachments WHERE report_id=? ORDER BY id DESC LIMIT 4", (report_id,)):
            sources.append((item["evidence_name"], item["evidence_path"], item["mime_type"]))
        for item in conn.execute("SELECT evidence_name,evidence_path FROM report_followups WHERE report_id=? AND evidence_path<>'' ORDER BY id DESC LIMIT 4", (report_id,)):
            sources.append((item["evidence_name"], item["evidence_path"], ""))
    result = []
    allowed = {".png": "image/png", ".jpg": "image/jpeg", ".webp": "image/webp", ".pdf": "application/pdf", ".txt": "text/plain"}
    base = UPLOAD_DIR.resolve()
    for name, relative, mime in sources:
        if len(result) >= 4:
            break
        path = (UPLOAD_DIR / relative).resolve()
        if not relative or not path.is_relative_to(base) or not path.is_file() or path.stat().st_size > 2_097_152:
            continue
        mime = mime or allowed.get(path.suffix.lower(), "")
        if mime not in UPLOAD_MIMES:
            continue
        result.append({"name": name, "mime_type": mime, "content": path.read_bytes()})
    return result


def similar_report_candidates(conn, report):
    domain = report_domain(str(report.get("url", "")))
    candidates = [dict(item) for item in conn.execute(
        "SELECT id,url,category,business,details,incident_date FROM reports WHERE id<>? ORDER BY id DESC LIMIT 300",
        (int(report.get("id", 0)),))]
    return [item for item in candidates if report_domain(item["url"]) == domain or
            (report.get("business") and str(report["business"]).casefold() in str(item.get("business", "")).casefold())]


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    UPLOAD_DIR.mkdir(exist_ok=True)
    with db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL,
                domain TEXT NOT NULL, score INTEGER NOT NULL, label TEXT NOT NULL,
                summary TEXT NOT NULL, checks TEXT NOT NULL, created_at TEXT NOT NULL,
                user_id INTEGER REFERENCES users(id), scanner_version TEXT NOT NULL DEFAULT '1.0.0',
                calculation TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL,
                category TEXT NOT NULL, details TEXT NOT NULL, evidence TEXT NOT NULL,
                email TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS moderation_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
                moderator_id INTEGER REFERENCES users(id), old_status TEXT NOT NULL, new_status TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER REFERENCES users(id), guest_token_hash TEXT NOT NULL DEFAULT '',
                report_id INTEGER REFERENCES reports(id) ON DELETE CASCADE, kind TEXT NOT NULL, title TEXT NOT NULL,
                message TEXT NOT NULL, is_read INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS report_guidance_actions (
                report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE, action_id TEXT NOT NULL,
                user_id INTEGER REFERENCES users(id), guest_token_hash TEXT NOT NULL DEFAULT '', completed INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL, PRIMARY KEY(report_id,action_id,user_id,guest_token_hash)
            );
            CREATE TABLE IF NOT EXISTS report_followups (
                id INTEGER PRIMARY KEY AUTOINCREMENT, report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
                user_id INTEGER REFERENCES users(id), guest_token_hash TEXT NOT NULL DEFAULT '', details TEXT NOT NULL,
                evidence_name TEXT NOT NULL DEFAULT '', evidence_path TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS evidence_hashes (
                id INTEGER PRIMARY KEY AUTOINCREMENT, report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
                sha256 TEXT NOT NULL, evidence_name TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS report_attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT, report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
                evidence_name TEXT NOT NULL, evidence_path TEXT NOT NULL, mime_type TEXT NOT NULL, sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS report_flags (
                id INTEGER PRIMARY KEY AUTOINCREMENT, report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
                user_id INTEGER REFERENCES users(id), type TEXT NOT NULL DEFAULT 'inaccuracy', reason TEXT NOT NULL,
                contact TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'Pending review',
                reviewed_by INTEGER REFERENCES users(id), reviewed_at TEXT NOT NULL DEFAULT '', review_note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ai_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, resource_type TEXT NOT NULL, resource_id INTEGER NOT NULL,
                domain TEXT NOT NULL DEFAULT '', analysis_type TEXT NOT NULL, provider TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '',
                model_version TEXT NOT NULL DEFAULT 'unknown', prompt_version TEXT NOT NULL DEFAULT '',
                input_sha256 TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, result_json TEXT NOT NULL DEFAULT '{}', usage_json TEXT NOT NULL DEFAULT '{}',
                user_consented INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ai_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER NOT NULL REFERENCES ai_runs(id),
                moderator_id INTEGER NOT NULL REFERENCES users(id), finding_key TEXT NOT NULL,
                decision TEXT NOT NULL CHECK(decision IN ('accepted','rejected')), note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ai_training_labels (
                id INTEGER PRIMARY KEY AUTOINCREMENT, report_id INTEGER NOT NULL REFERENCES reports(id),
                run_id INTEGER REFERENCES ai_runs(id), moderator_id INTEGER NOT NULL REFERENCES users(id),
                category TEXT NOT NULL, label TEXT NOT NULL, review_note TEXT NOT NULL DEFAULT '',
                partition_name TEXT NOT NULL CHECK(partition_name IN ('training','evaluation','unassigned')),
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS admin_audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER REFERENCES users(id),
                action TEXT NOT NULL, resource_type TEXT NOT NULL, resource_id TEXT NOT NULL DEFAULT '',
                previous_json TEXT NOT NULL DEFAULT '{}', new_json TEXT NOT NULL DEFAULT '{}',
                metadata_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scanner_settings (
                setting_key TEXT PRIMARY KEY, setting_value TEXT NOT NULL, updated_by INTEGER REFERENCES users(id),
                updated_at TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS threat_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL, category TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('verified','false_positive')),
                source_report_id INTEGER NOT NULL UNIQUE REFERENCES reports(id),
                created_by INTEGER NOT NULL REFERENCES users(id), reviewer_id INTEGER NOT NULL REFERENCES users(id),
                verification_note TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, severity TEXT NOT NULL
                    CHECK(severity IN ('low','medium','high','critical')),
                status TEXT NOT NULL CHECK(status IN ('new','investigating','contained','resolved','closed')),
                assigned_to INTEGER REFERENCES users(id), created_by INTEGER NOT NULL REFERENCES users(id),
                resolution_note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS incident_reports (
                incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
                PRIMARY KEY(incident_id,report_id)
            );
            CREATE TABLE IF NOT EXISTS incident_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                actor_id INTEGER REFERENCES users(id), event_type TEXT NOT NULL,
                previous_json TEXT NOT NULL DEFAULT '{}', new_json TEXT NOT NULL DEFAULT '{}',
                note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS admin_report_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT, report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
                author_id INTEGER NOT NULL REFERENCES users(id), note TEXT NOT NULL, created_at TEXT NOT NULL
            );
        """)
        user_columns = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
        if "status" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
        columns = {row[1] for row in conn.execute("PRAGMA table_info(reports)")}
        additions = {
            "business": "TEXT NOT NULL DEFAULT ''", "incident_date": "TEXT NOT NULL DEFAULT ''",
            "amount": "TEXT NOT NULL DEFAULT ''", "reference": "TEXT NOT NULL DEFAULT ''",
            "links": "TEXT NOT NULL DEFAULT ''", "status": "TEXT NOT NULL DEFAULT 'Submitted'",
            "user_id": "INTEGER REFERENCES users(id)", "evidence_name": "TEXT NOT NULL DEFAULT ''",
            "guest_token_hash": "TEXT NOT NULL DEFAULT ''",
            "evidence_path": "TEXT NOT NULL DEFAULT ''", "moderated_by": "INTEGER REFERENCES users(id)",
            "moderated_at": "TEXT NOT NULL DEFAULT ''", "moderation_note": "TEXT NOT NULL DEFAULT ''"
            , "evidence_analysis": "TEXT NOT NULL DEFAULT '{}'", "public_update": "TEXT NOT NULL DEFAULT ''",
            "domain": "TEXT NOT NULL DEFAULT ''", "public_summary": "TEXT NOT NULL DEFAULT ''",
            "ai_analysis": "TEXT NOT NULL DEFAULT '{}'", "ai_consent": "INTEGER NOT NULL DEFAULT 0",
            "assigned_to": "INTEGER REFERENCES users(id)", "priority": "TEXT NOT NULL DEFAULT 'normal'"
        }
        for name, spec in additions.items():
            if name not in columns:
                conn.execute(f"ALTER TABLE reports ADD COLUMN {name} {spec}")
        scan_columns = {row[1] for row in conn.execute("PRAGMA table_info(scans)")}
        if "user_id" not in scan_columns:
            conn.execute("ALTER TABLE scans ADD COLUMN user_id INTEGER REFERENCES users(id)")
        for name, spec in {"scanner_version": "TEXT NOT NULL DEFAULT '1.0.0'", "calculation": "TEXT NOT NULL DEFAULT '{}'"}.items():
            if name not in scan_columns:
                conn.execute(f"ALTER TABLE scans ADD COLUMN {name} {spec}")
        scan_columns = {row[1] for row in conn.execute("PRAGMA table_info(scans)")}
        for name, spec in {"ai_analysis": "TEXT NOT NULL DEFAULT '{}'", "phishing_analysis": "TEXT NOT NULL DEFAULT '{}'"}.items():
            if name not in scan_columns:
                conn.execute(f"ALTER TABLE scans ADD COLUMN {name} {spec}")
        conn.execute("CREATE INDEX IF NOT EXISTS reports_url ON reports(url)")
        conn.execute("CREATE INDEX IF NOT EXISTS reports_created_at ON reports(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS notifications_user_created ON notifications(user_id,created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS reports_status_created ON reports(status,created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS reports_category_created ON reports(category,created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS reports_domain_created ON reports(domain,created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS followups_report_created ON report_followups(report_id,created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS evidence_hash_lookup ON evidence_hashes(sha256)")
        conn.execute("CREATE INDEX IF NOT EXISTS attachments_report_created ON report_attachments(report_id,created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS ai_runs_resource ON ai_runs(resource_type,resource_id,created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS ai_training_partition ON ai_training_labels(partition_name,category,report_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS admin_audit_created ON admin_audit_events(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS threat_records_domain_status ON threat_records(domain,status)")
        conn.execute("CREATE INDEX IF NOT EXISTS incidents_status_updated ON incidents(status,updated_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS incident_events_incident_created ON incident_events(incident_id,created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS admin_report_notes_report_created ON admin_report_notes(report_id,created_at)")
        for key, value in {"request_timeout_seconds": str(TIMEOUT), "max_redirects": str(MAX_REDIRECTS),
                           "phishing_heuristics_enabled": "true", "ai_content_analysis_enabled": "true"}.items():
            conn.execute("INSERT OR IGNORE INTO scanner_settings(setting_key,setting_value) VALUES(?,?)", (key, value))
        conn.execute("UPDATE reports SET status='More Information Required' WHERE status='Evidence Requested'")
        conn.execute("UPDATE reports SET status='Partially Supported' WHERE status='Partially Verified'")
        conn.execute("UPDATE reports SET status='Verified Findings' WHERE status='Verified'")
        for row in conn.execute("SELECT id,url FROM reports WHERE domain='' OR domain IS NULL"):
            conn.execute("UPDATE reports SET domain=? WHERE id=?", (report_domain(row["url"]), row["id"]))
        for row in conn.execute("SELECT id,details FROM reports WHERE public_summary='' OR public_summary IS NULL"):
            conn.execute("UPDATE reports SET public_summary=? WHERE id=?", (safe_description(row["details"])[:240], row["id"]))


def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"


def verify_password(password, saved):
    try:
        algorithm, salt_text, digest_text = saved.split("$", 2)
        if algorithm != "scrypt":
            return False
        salt = base64.urlsafe_b64decode(salt_text)
        expected = base64.urlsafe_b64decode(digest_text)
        actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def token_digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def stored_upload(file):
    if not file:
        return None
    mime = str(file.get("mime_type", ""))
    encoded = str(file.get("data", ""))
    if mime not in UPLOAD_MIMES:
        raise ValueError("Use a PNG, JPG, WEBP, PDF or TXT attachment.")
    try:
        content = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error):
        raise ValueError("The attachment could not be read.")
    if not content or len(content) > 2 * 1024 * 1024:
        raise ValueError("Choose a non-empty file no larger than 2 MB.")
    signatures = {"image/png": b"\x89PNG\r\n\x1a\n", "image/jpeg": b"\xff\xd8\xff", "image/webp": b"RIFF", "application/pdf": b"%PDF", "text/plain": None}
    if signatures[mime] and not content.startswith(signatures[mime]):
        raise ValueError("The attachment content does not match its file type.")
    if mime == "image/webp" and (len(content) < 12 or content[8:12] != b"WEBP"):
        raise ValueError("The attachment content does not match its file type.")
    if mime == "text/plain":
        try:
            content.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("Text attachments must use UTF-8 encoding.")
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", str(file.get("name", "evidence")))[:120] or "evidence"
    return {"name": name, "mime_type": mime, "content": content, "path": secrets.token_hex(24) + UPLOAD_MIMES[mime], **inspect_file(name, mime, content)}


def notify_report_owner(conn, report, kind, title, message):
    if report["user_id"]:
        conn.execute("INSERT INTO notifications(user_id,report_id,kind,title,message,created_at) VALUES(?,?,?,?,?,?)",
                     (report["user_id"], report["id"], kind, title, message, now()))
    elif report["guest_token_hash"]:
        conn.execute("INSERT INTO notifications(guest_token_hash,report_id,kind,title,message,created_at) VALUES(?,?,?,?,?,?)",
                     (report["guest_token_hash"], report["id"], kind, title, message, now()))


def actor_owns_report(row, user, guest_hashes):
    return bool((user and row["user_id"] == user["id"]) or
                (row["user_id"] is None and row["guest_token_hash"] and row["guest_token_hash"] in guest_hashes))


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.links = []
        self.title = False
        self.title_text = []
        self.ignored_depth = 0
        self.password_input_count = 0
        self.password_form_actions = []
        self.current_form_action = ""

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "title":
            self.title = True
        if tag in {"script", "style", "noscript", "svg"}:
            self.ignored_depth += 1
        if tag == "a" and attrs.get("href"):
            self.links.append((attrs["href"], attrs.get("aria-label", "")))
        if tag == "form":
            self.current_form_action = attrs.get("action", "")
        if tag == "input" and str(attrs.get("type", "")).lower() == "password":
            self.password_input_count += 1
            self.password_form_actions.append(self.current_form_action)

    def handle_endtag(self, tag):
        if tag == "title":
            self.title = False
        if tag == "form":
            self.current_form_action = ""
        if tag in {"script", "style", "noscript", "svg"} and self.ignored_depth:
            self.ignored_depth -= 1

    def handle_data(self, data):
        if self.ignored_depth:
            return
        if data.strip():
            self.text.append(data.strip())
            if self.title:
                self.title_text.append(data.strip())


def safe_public_host(host):
    """Resolve once, reject every non-public answer, and return pinned addresses."""
    normalized = (host or "").rstrip(".").lower()
    blocked_names = {"localhost", "localhost.localdomain", "metadata.google.internal", "metadata.google", "instance-data"}
    blocked_suffixes = (".localhost", ".local", ".internal", ".test", ".invalid")
    if not normalized or normalized in blocked_names or normalized.endswith(blocked_suffixes) or "%" in normalized:
        raise ValueError("Enter a public website address.")
    try:
        addresses = {ipaddress.ip_address(host.split("%", 1)[0])}
    except ValueError:
        try:
            addresses = {ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
        except (socket.gaierror, OSError):
            raise ValueError("The domain could not be resolved. Check the address and try again.")
    normalized_addresses = {address.ipv4_mapped if getattr(address, "ipv4_mapped", None) else address for address in addresses}
    if not normalized_addresses or any(not address.is_global for address in normalized_addresses):
        raise ValueError("This address points to a private or reserved network and cannot be scanned.")
    return tuple(sorted((str(address) for address in normalized_addresses), key=lambda item: (ipaddress.ip_address(item).version, item)))


def normalize_url(raw):
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Enter a website address to scan.")
    if len(raw) > 2048:
        raise ValueError("The website address is too long.")
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    parts = urllib.parse.urlsplit(raw)
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
        raise ValueError("Enter a valid public http or https website address.")
    try:
        parts.port
    except ValueError:
        raise ValueError("The website address has an invalid port.")
    safe_public_host(parts.hostname)
    return urllib.parse.urlunsplit((parts.scheme.lower(), parts.netloc, parts.path or "/", parts.query, ""))


def scan_site(raw, user_id=None):
    config = scanner_configuration()
    url = normalize_url(raw)
    initial = urllib.parse.urlsplit(url)
    domain = initial.hostname.encode("idna").decode("ascii").lower()
    checks = []
    observed_at = now()

    def add(rule_id, name, category, status, explanation, *, source, evidence="", contribution=0):
        checks.append(make_finding(rule_id, name, category, status, explanation, source=source,
                                   evidence=evidence, contribution=contribution, observed_at=observed_at))

    addresses = safe_public_host(initial.hostname)
    add("domain.dns_addresses", "Public DNS addresses", "Domain intelligence", PASS,
        "The hostname resolved only to globally routable IP addresses. DNS resolution does not identify the site's operator.",
        source="System DNS resolver", evidence=", ".join(addresses))
    for rule, name, explanation in (
        ("domain.registration_age", "Domain registration age", "No registrar provider is configured; registration and expiration dates were not checked."),
        ("domain.nameservers", "Nameserver information", "Nameserver records are unavailable from the configured system resolver."),
        ("reputation.threat_intelligence", "Threat intelligence", "No Google Safe Browsing, URLhaus, or PhishTank provider is configured; no reputation lookup was performed."),
    ):
        category = "Reputation and threat intelligence" if rule.startswith("reputation.") else "Domain intelligence"
        add(rule, name, category, UNKNOWN, explanation, source="External data unavailable")

    request = urllib.request.Request(url, headers={"User-Agent": "TrustShield-Research/1.1 (+website safety scan)", "Accept": "text/html,application/xhtml+xml"})
    status_code, headers, body, final_url, fetch_error, tls_error = None, {}, b"", url, None, None
    redirect_handler = SafeRedirect(config["max_redirects"])
    redirect_handler.resolution_cache[initial.hostname.lower()] = addresses
    tls_handler = PinnedHTTPSHandler(ssl.create_default_context(), redirect_handler.resolution_cache)
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), redirect_handler, PinnedHTTPHandler(redirect_handler.resolution_cache), tls_handler)
        with opener.open(request, timeout=config["request_timeout_seconds"]) as response:
            final_url = response.geturl()
            status_code, headers = response.status, response.headers
            body = response.read(MAX_BODY)
    except urllib.error.HTTPError as exc:
        final_url, status_code, headers = exc.geturl(), exc.code, exc.headers or {}
        try:
            body = exc.read(MAX_BODY)
        except OSError:
            pass
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        tls_error = reason if isinstance(reason, ssl.SSLCertVerificationError) else None
        fetch_error = str(reason)[:180]

    final_parts = urllib.parse.urlsplit(final_url)
    final_display = urllib.parse.urlunsplit((final_parts.scheme, final_parts.netloc, final_parts.path, "", ""))
    if tls_error:
        add("connection.tls_invalid", "TLS certificate validation", "Connection security", FAIL,
            "The TLS certificate did not pass certificate or hostname validation. Page-content checks remain unavailable.",
            source="TLS handshake", evidence=str(tls_error)[:240], contribution=SCORING_WEIGHTS["connection.tls_invalid"])
    elif fetch_error:
        add("connection.tls", "TLS certificate validation", "Connection security", UNKNOWN,
            "The connection did not reach a verifiable HTTPS response, so certificate details are unavailable.",
            source="Live scan", evidence=fetch_error)
    elif final_parts.scheme == "http":
        add("connection.http_final", "Encrypted connection", "Connection security", FAIL,
            "The final page uses HTTP, so the browser-to-site connection is not encrypted. This is a connection concern, not proof of fraud.",
            source="Final response URL", evidence=final_display, contribution=SCORING_WEIGHTS["connection.http_final"])
    else:
        certificate = next((item.certificate for item in reversed(tls_handler.connections) if item.certificate), None)
        if certificate:
            remaining_days = max(0, (ssl.cert_time_to_seconds(certificate.get("notAfter", "")) - int(time.time())) // 86400)
            issuer = ", ".join("=".join(pair) for group in certificate.get("issuer", ()) for pair in group)
            add("connection.tls_valid", "TLS certificate", "Connection security", PASS,
                f"TLS hostname and trust-chain validation passed; the certificate expires in about {remaining_days} days." + (f" Issuer: {issuer}." if issuer else ""),
                source="Verified TLS certificate", evidence=f"Host: {final_parts.hostname}; expires: {certificate.get('notAfter', 'unavailable')}")
            add("connection.tls_expiration", "Certificate expiration", "Connection security", PASS,
                f"The validated certificate is currently within its validity period; about {remaining_days} days remain.",
                source="Verified TLS certificate", evidence=certificate.get("notAfter", ""))
        else:
            add("connection.tls_valid", "TLS certificate", "Connection security", UNKNOWN,
                "The HTTPS response was received, but certificate details could not be extracted.", source="TLS connection")

    visible_text, title, text, links = "", "", "", []
    password_input_count, password_form_actions = 0, []
    if status_code is None:
        add("http.response", "Page retrieval", "HTTP security", UNKNOWN,
            "The page response could not be retrieved. Content and HTTP configuration checks are unknown, not failed.",
            source="Live scan", evidence=fetch_error or "No response")
        header_findings = [{"name": name, "status": UNKNOWN, "explanation": "No response headers were available, so this header could not be checked.", "evidence": ""}
                           for name, _validator in __import__("security_headers").VALIDATORS]
        for item in header_findings:
            add(f"header.{item['name'].lower()}", item["name"], "HTTP security", UNKNOWN, item["explanation"], source="No response")
        content_type = ""
    else:
        if 200 <= status_code < 400:
            response_status, contribution = PASS, 0
        elif status_code >= 500:
            response_status, contribution = FAIL, SCORING_WEIGHTS["response.server_error"]
        else:
            response_status, contribution = WARNING, 0
        add("http.response", "Page retrieval", "HTTP security", response_status,
            f"The server returned HTTP {status_code}. An access or availability response is not a fraud verdict.",
            source="HTTP response", evidence=str(status_code), contribution=contribution)
        content_type = headers.get("Content-Type", "")
        add("http.content_type", "Content type", "HTTP security", PASS if content_type else NOT_DETECTED,
            f"The response declared {content_type}." if content_type else "The response did not include a Content-Type header.",
            source="HTTP response", evidence=content_type)
        from security_headers import validate_security_headers
        for item in validate_security_headers(headers, is_https=final_parts.scheme == "https"):
            rule = {NOT_DETECTED: "header.missing", WARNING: "header.weak", FAIL: "header.invalid"}.get(item["status"])
            contribution = SCORING_WEIGHTS.get(rule, 0) if rule else 0
            add(f"header.{item['name'].lower()}", item["name"], "HTTP security", item["status"], item["explanation"],
                source="HTTP response header", evidence=item["evidence"], contribution=contribution)

        cookie_headers = headers.get_all("Set-Cookie", []) if hasattr(headers, "get_all") else []
        if not cookie_headers:
            add("http.cookie_attributes", "Cookie security attributes", "HTTP security", NOT_APPLICABLE,
                "This response did not set cookies, so cookie attributes do not apply.", source="HTTP response")
        else:
            cookie_notes, parse_failed = [], False
            for raw_cookie in cookie_headers[:20]:
                jar = SimpleCookie()
                try:
                    jar.load(raw_cookie)
                except CookieError:
                    parse_failed = True
                    continue
                for cookie_name, morsel in jar.items():
                    missing = [name for name, present in (("Secure", bool(morsel["secure"])), ("HttpOnly", bool(morsel["httponly"])), ("SameSite", bool(morsel["samesite"]))) if not present]
                    cookie_notes.append(f"{cookie_name}: " + ("missing " + ", ".join(missing) if missing else "Secure, HttpOnly and SameSite set"))
            if cookie_notes:
                add("http.cookie_attributes", "Cookie security attributes", "HTTP security", WARNING,
                    "Review cookie flags in context: " + "; ".join(cookie_notes) + ". Some cookies are intentionally readable by scripts.",
                    source="Set-Cookie response fields", evidence="; ".join(cookie_notes))
            elif parse_failed:
                add("http.cookie_attributes", "Cookie security attributes", "HTTP security", UNKNOWN,
                    "Cookie fields were returned but could not be parsed reliably.", source="Set-Cookie response fields")
            else:
                add("http.cookie_attributes", "Cookie security attributes", "HTTP security", PASS,
                    "Returned cookies had Secure, HttpOnly, and SameSite attributes.", source="Set-Cookie response fields")

        server_header = headers.get("Server", "")
        add("http.server_header", "Server response information", "HTTP security", PASS if server_header else NOT_DETECTED,
            "A Server header was returned; this is informational." if server_header else "No Server header was disclosed; this is informational.",
            source="HTTP response", evidence=server_header)

        is_html = "html" in content_type.lower() or not content_type
        parser = PageParser()
        if is_html:
            try:
                charset = headers.get_content_charset() or "utf-8"
                parser.feed(body.decode(charset, errors="replace"))
            except (LookupError, UnicodeError, AttributeError):
                parser.feed(body.decode("utf-8", errors="replace"))
        visible_text = " ".join(parser.text)[:12_000]
        text = visible_text.lower()
        links = [urllib.parse.urljoin(final_url, href).lower() + " " + label.lower() for href, label in parser.links]
        title = " ".join(parser.title_text)[:160]
        password_input_count = parser.password_input_count
        password_form_actions = [urllib.parse.urljoin(final_url, action) if action else final_url for action in parser.password_form_actions]

    final_origin = (final_parts.scheme.lower(), final_parts.hostname.lower() if final_parts.hostname else "", final_parts.port)
    cross_origin = any(
        (urllib.parse.urlsplit(hop["from"]).scheme.lower(), urllib.parse.urlsplit(hop["from"]).hostname, urllib.parse.urlsplit(hop["from"]).port)
        != (urllib.parse.urlsplit(hop["to"]).scheme.lower(), urllib.parse.urlsplit(hop["to"]).hostname, urllib.parse.urlsplit(hop["to"]).port)
        for hop in redirect_handler.hops
    )
    if redirect_handler.hops and initial.scheme == "http" and final_parts.scheme == "https":
        add("connection.http_redirect", "HTTP to HTTPS redirect", "Connection security", WARNING,
            "The final page uses HTTPS, but the initial HTTP request can be intercepted before it redirects.",
            source="Redirect chain", evidence=" → ".join(urllib.parse.urlsplit(hop["to"]).netloc for hop in redirect_handler.hops),
            contribution=SCORING_WEIGHTS["connection.http_redirect"])
    elif redirect_handler.hops and not cross_origin:
        add("connection.redirect_chain", "Redirect behavior", "HTTP security", PASS,
            f"The response used {len(redirect_handler.hops)} validated redirect(s) without changing origin.",
            source="Redirect chain", evidence=" → ".join(urllib.parse.urlsplit(hop["to"]).netloc for hop in redirect_handler.hops))
    elif not redirect_handler.hops:
        add("connection.redirect_chain", "Redirect behavior", "HTTP security", PASS,
            "The submitted URL did not redirect.", source="Live scan", evidence=final_display)
    if cross_origin:
        add("connection.cross_origin_redirect", "Redirect destination", "HTTP security", WARNING,
            "A redirect changed origin. Verify that the destination belongs to the seller; cross-origin redirects are not inherently suspicious.",
            source="Redirect chain", evidence=" → ".join(urllib.parse.urlsplit(hop["to"]).netloc for hop in redirect_handler.hops),
            contribution=SCORING_WEIGHTS["connection.cross_origin_redirect"])

    if status_code is None:
        for rule, name in (("website.contact", "Contact information"), ("website.privacy", "Privacy policy"),
                           ("website.terms", "Terms and conditions"), ("website.about", "About page"),
                           ("website.business", "Business information"), ("content.high_pressure_language", "High-pressure language")):
            add(rule, name, "Website characteristics", UNKNOWN, "The page content was unavailable, so this check could not be completed.", source="Live scan")
    elif content_type and "html" not in content_type.lower():
        for rule, name in (("website.contact", "Contact information"), ("website.privacy", "Privacy policy"),
                           ("website.terms", "Terms and conditions"), ("website.about", "About page"),
                           ("website.business", "Business information"), ("content.high_pressure_language", "High-pressure language")):
            add(rule, name, "Website characteristics", NOT_APPLICABLE, "The retrieved response was not HTML, so page text and link checks do not apply.", source="Content-Type", evidence=content_type)
    else:
        for rule, name, terms in (
            ("website.contact", "Contact information", ("contact", "customer service", "support")),
            ("website.privacy", "Privacy policy", ("privacy policy", "privacy")),
            ("website.terms", "Terms and conditions", ("terms and conditions", "terms of service", "terms")),
            ("website.returns", "Return and refund information", ("return policy", "refund policy", "returns", "refunds")),
            ("website.about", "About page", ("about us", "about")),
            ("website.business", "Business information", ("company registration", "registered office", "business address", "company number")),
        ):
            match = next((term for term in terms if term in text or any(term in link for link in links)), None)
            add(rule, name, "Website characteristics", PASS if match else NOT_DETECTED,
                f"Observed '{match}' on the retrieved page." if match else "No matching wording or link was found on this page. It may exist elsewhere; absence is not proof of fraud.",
                source="Retrieved page text and links", evidence=match or "Not found")
        urgency_terms = ("act now", "limited time", "only today", "last chance", "guaranteed profit", "100% guaranteed")
        matches = [term for term in urgency_terms if term in text]
        add("content.high_pressure_language", "High-pressure language", "Website characteristics", WARNING if matches else PASS,
            (f"Selected promotional phrases were observed: {', '.join(matches[:3])}. This is a weak context signal, not a fraud finding." if matches else "No selected high-pressure phrases were observed in the retrieved page text."),
            source="Retrieved page text", evidence=", ".join(matches[:3]),
            contribution=min(len(matches), 3) * SCORING_WEIGHTS["content.high_pressure_language"])

    patterns = ("paypa1", "amaz0n", "app1e", "support-verify", "secure-login")
    matched = next((pattern for pattern in patterns if pattern in domain), None)
    add("url.impersonation_pattern", "URL wording pattern", "Website characteristics", WARNING if matched else PASS,
        (f"The hostname contains '{matched}'. Verify the domain through the brand's official channels; this heuristic can be wrong." if matched else "No selected impersonation-style hostname pattern was observed."),
        source="Submitted URL hostname", evidence=matched or domain,
        contribution=SCORING_WEIGHTS["url.impersonation_pattern"] if matched else 0)

    phishing_analysis = analyze_phishing(url, page_text=visible_text, password_input_count=password_input_count,
                                         password_form_actions=password_form_actions, redirects=redirect_handler.hops) if config["phishing_heuristics_enabled"] else {
                                             "status": "disabled", "findings": [], "assessment": "Phishing heuristics were disabled by the current scanner configuration.",
                                             "threat_intelligence": {"available": False, "message": "No external threat feed was queried."}}
    for signal in phishing_analysis["findings"]:
        add(signal["id"], signal["name"], "Phishing and impersonation", WARNING,
            signal["explanation"] + " " + signal["recommended_action"], source=signal["source"], evidence=signal["evidence"])
    ai_analysis = analyze_website_content(final_display, title, visible_text) if config["ai_content_analysis_enabled"] else {
        "status": "disabled", "provider": "none", "findings": [], "message": "Optional AI page analysis is disabled by the current scanner configuration."}

    assessment = score_findings(checks, sufficient_data=status_code is not None)
    score, label, summary = assessment["score"], assessment["label"], assessment["summary"]
    created_at = now()
    with db() as conn:
        cur = conn.execute("INSERT INTO scans(url,domain,score,label,summary,checks,created_at,user_id,scanner_version,calculation,ai_analysis,phishing_analysis) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                           (url, domain, score, label, summary, json.dumps(checks), created_at, user_id,
                            SCANNER_VERSION, json.dumps(assessment["calculation"]), json.dumps(ai_analysis), json.dumps(phishing_analysis)))
        scan_id = cur.lastrowid
        persist_ai_results(conn, "scan", scan_id, ai_analysis)
        conn.execute("UPDATE scans SET ai_analysis=? WHERE id=?", (json.dumps(ai_analysis), scan_id))
        threat_row = conn.execute("SELECT id,domain,category,verification_note,first_seen,last_seen,updated_at FROM threat_records WHERE status='verified' AND (?=domain OR ? LIKE '%.'||domain) ORDER BY length(domain) DESC LIMIT 1", (domain, domain)).fetchone()
        threat_match = dict(threat_row) if threat_row else None
    return {"id": scan_id, "url": url, "domain": domain, "title": title, "score": score,
            "label": label, "summary": summary, "checks": checks, "findings": checks,
            "calculation": assessment["calculation"], "scanner_version": SCANNER_VERSION,
            "created_at": created_at, "status_code": status_code, "final_url": final_display,
            "ai_analysis": ai_analysis, "phishing_analysis": phishing_analysis,
            "verified_threat_match": threat_match}


class Handler(BaseHTTPRequestHandler):
    server_version = "TrustShield/1.0"

    def send_json(self, value, status=200):
        data = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(data)

    def read_json(self):
        size = int(self.headers.get("Content-Length", "0"))
        if size > 9_000_000:
            raise ValueError("Request is too large.")
        return json.loads(self.rfile.read(size) or b"{}")

    def current_user(self):
        cookie = self.headers.get("Cookie", "")
        token = next((part.strip().split("=", 1)[1] for part in cookie.split(";") if part.strip().startswith("trustshield_session=")), "")
        if not token:
            return None
        with db() as conn:
            row = conn.execute("SELECT u.id,u.name,u.email,u.role,u.status FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND u.status='active'", (token_digest(token), int(time.time()))).fetchone()
            return dict(row) if row else None

    def guest_token_hashes(self):
        # Guest tokens belong to an anonymous browser session. Never let a signed-in
        # account inherit that browser's guest reports or notifications.
        if self.current_user():
            return []
        raw = self.headers.get("X-TrustShield-Guest-Tokens", "")
        tokens = [token.strip() for token in raw.split(",")[:30] if token.strip()]
        return [token_digest(token) for token in tokens if len(token) <= 100]

    def require_user(self, role=None):
        user = self.current_user()
        if not user:
            self.send_json({"error": "Sign in to continue."}, 401)
            return None
        if role and user["role"] != role:
            self.send_json({"error": "Administrator access is required."}, 403)
            return None
        return user

    def rate_limit(self, key, maximum, window=3600):
        now_time = time.time()
        ip = self.client_address[0]
        bucket = f"{ip}:{key}:{int(now_time // window)}"
        with RATE_LOCK:
            count = RATE_BUCKETS.get(bucket, 0) + 1
            RATE_BUCKETS[bucket] = count
            if len(RATE_BUCKETS) > 10_000:
                for old in [k for k in RATE_BUCKETS if not k.endswith(f":{int(now_time // window)}")]:
                    RATE_BUCKETS.pop(old, None)
        if count > maximum:
            self.send_json({"error": "Too many requests. Please wait and try again."}, 429)
            return False
        return True

    def set_session(self, user_id):
        token = secrets.token_urlsafe(32)
        expires = int(time.time()) + 60 * 60 * 24 * 14
        with db() as conn:
            conn.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)", (token_digest(token), user_id, expires))
        return token

    def session_cookie(self, token, max_age=60 * 60 * 24 * 14):
        secure = "; Secure" if os.environ.get("TRUSTSHIELD_SECURE_COOKIE", "").lower() in {"1", "true", "yes"} else ""
        return f"trustshield_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{secure}"

    def handle_admin_get(self, path, query):
        routes = {
            "/api/admin/overview", "/api/admin/users", "/api/admin/scans", "/api/admin/reports",
            "/api/admin/threats", "/api/admin/scanner/settings", "/api/admin/incidents",
            "/api/admin/audit", "/api/admin/ai",
        }
        user_match = re.fullmatch(r"/api/admin/users/(\d+)", path)
        report_match = re.fullmatch(r"/api/admin/reports/(\d+)", path)
        incident_match = re.fullmatch(r"/api/admin/incidents/(\d+)", path)
        if path not in routes and not (user_match or report_match or incident_match):
            return False
        user = self.require_user("admin")
        if not user:
            return True
        q = (query.get("q", [""])[0] or "").strip()[:120]
        status = (query.get("status", [""])[0] or "").strip()[:40]
        try: page = max(1, min(100_000, int((query.get("page", ["1"])[0] or "1"))))
        except (ValueError, TypeError): page = 1
        try: limit = max(1, min(100, int((query.get("limit", ["25"])[0] or "25"))))
        except (ValueError, TypeError): limit = 25
        offset = (page - 1) * limit
        with db() as conn:
            if path == "/api/admin/overview":
                try: days = max(7, min(90, int((query.get("days", ["30"])[0] or "30"))))
                except (ValueError, TypeError): days = 30
                today = datetime.now(timezone.utc).date().isoformat()
                metrics = conn.execute("""
                    SELECT (SELECT COUNT(*) FROM users) total_users,
                      (SELECT COUNT(*) FROM users WHERE status='active') active_users,
                      (SELECT COUNT(*) FROM scans) total_scans,
                      (SELECT COUNT(*) FROM scans WHERE substr(created_at,1,10)=?) scans_today,
                      (SELECT COUNT(DISTINCT domain) FROM scans WHERE label='Moderate Risk') suspicious_websites,
                      (SELECT COUNT(DISTINCT domain) FROM scans WHERE label='High Risk') high_risk_websites,
                      (SELECT COUNT(*) FROM scans WHERE label='Critical Risk') critical_risk_scans,
                      (SELECT COUNT(*) FROM reports WHERE status IN ('Submitted','Under Review','More Information Required','Disputed')) pending_complaints,
                      (SELECT COUNT(*) FROM threat_records WHERE status='verified') verified_threats,
                      (SELECT COUNT(*) FROM scans WHERE label='Insufficient Data') failed_scans,
                      (SELECT COUNT(*) FROM incidents WHERE status NOT IN ('resolved','closed')) open_incidents
                """, (today,)).fetchone()
                chart_rows = conn.execute("SELECT substr(created_at,1,10) day,COUNT(*) count FROM scans WHERE created_at>=datetime('now',?) GROUP BY day ORDER BY day", (f"-{days} days",)).fetchall()
                counts = {row["day"]: row["count"] for row in chart_rows}
                chart = [{"date": (datetime.now(timezone.utc).date() - timedelta(days=days - index - 1)).isoformat(), "count": 0} for index in range(days)]
                for item in chart:
                    item["count"] = counts.get(item["date"], 0)
                activity = [dict(row) for row in conn.execute("""
                    SELECT * FROM (
                      SELECT event.id,event.actor_id,event.action,event.resource_type,event.resource_id,event.previous_json,event.new_json,event.metadata_json,event.created_at,users.name actor_name
                      FROM admin_audit_events event LEFT JOIN users ON users.id=event.actor_id
                      UNION ALL
                      SELECT event.id,event.moderator_id,'report.status_changed','report',CAST(event.report_id AS TEXT),
                        json_object('status',event.old_status),json_object('status',event.new_status),json_object('note',event.note),event.created_at,users.name
                      FROM moderation_events event LEFT JOIN users ON users.id=event.moderator_id
                    ) ORDER BY created_at DESC LIMIT 12
                """)]
                try:
                    ai_state = provider_status()
                    health = {"api": "available", "database": "available", "ai_provider": ai_state.get("status", "not configured")}
                except Exception:
                    health = {"api": "available", "database": "available", "ai_provider": "status unavailable"}
                return self.send_json({"metrics": dict(metrics), "scans_by_day": chart, "activity": activity, "health": health}) or True
            if path == "/api/admin/users":
                where, args = [], []
                if q:
                    where.append("(u.name LIKE ? OR u.email LIKE ? OR CAST(u.id AS TEXT)=?)")
                    args.extend([f"%{q}%", f"%{q}%", q.lstrip("#")])
                if status in {"active", "suspended"}:
                    where.append("u.status=?"); args.append(status)
                role = (query.get("role", [""])[0] or "").strip()
                if role in {"user", "admin"}:
                    where.append("u.role=?"); args.append(role)
                condition = " WHERE " + " AND ".join(where) if where else ""
                total = conn.execute("SELECT COUNT(*) FROM users u" + condition, args).fetchone()[0]
                rows = [dict(row) for row in conn.execute("""
                    SELECT u.id,u.name,u.email,u.role,u.status,u.created_at,
                    (SELECT COUNT(*) FROM scans s WHERE s.user_id=u.id) scan_count,
                    (SELECT COUNT(*) FROM reports r WHERE r.user_id=u.id) report_count
                    FROM users u
                """ + condition + " ORDER BY u.id DESC LIMIT ? OFFSET ?", (*args, limit, offset))]
                return self.send_json({"users": rows, "total": total, "page": page, "limit": limit}) or True
            if user_match:
                target_id = int(user_match.group(1))
                target = conn.execute("SELECT id,name,email,role,status,created_at FROM users WHERE id=?", (target_id,)).fetchone()
                if not target:
                    self.send_json({"error": "User not found."}, 404); return True
                scans = [dict(row) for row in conn.execute("SELECT id,url,domain,score,label,created_at FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 50", (target_id,))]
                reports = [dict(row) for row in conn.execute("SELECT id,url,domain,category,status,created_at FROM reports WHERE user_id=? ORDER BY id DESC LIMIT 50", (target_id,))]
                return self.send_json({"user": dict(target), "scans": scans, "reports": reports}) or True
            if path == "/api/admin/scans":
                where, args = [], []
                if q:
                    where.append("(s.domain LIKE ? OR s.url LIKE ? OR u.email LIKE ? OR CAST(s.id AS TEXT)=?)")
                    args.extend([f"%{q}%", f"%{q}%", f"%{q}%", q.lstrip("#")])
                if status:
                    where.append("s.label=?"); args.append(status)
                condition = " WHERE " + " AND ".join(where) if where else ""
                total = conn.execute("SELECT COUNT(*) FROM scans s LEFT JOIN users u ON u.id=s.user_id" + condition, args).fetchone()[0]
                rows = [dict(row) for row in conn.execute("SELECT s.id,s.url,s.domain,s.score,s.label,s.summary,s.checks,s.ai_analysis,s.phishing_analysis,s.created_at,s.scanner_version,u.name user_name,u.email user_email FROM scans s LEFT JOIN users u ON u.id=s.user_id" + condition + " ORDER BY s.id DESC LIMIT ? OFFSET ?", (*args, limit, offset))]
                for row in rows:
                    try: row["checks"] = json.loads(row["checks"] or "[]")
                    except json.JSONDecodeError: row["checks"] = []
                    try: row["ai_analysis"] = json.loads(row["ai_analysis"] or "null")
                    except (json.JSONDecodeError, TypeError): row["ai_analysis"] = None
                    try: row["phishing_analysis"] = json.loads(row["phishing_analysis"] or "null")
                    except (json.JSONDecodeError, TypeError): row["phishing_analysis"] = None
                return self.send_json({"scans": rows, "total": total, "page": page, "limit": limit}) or True
            if path == "/api/admin/reports":
                where, args = [], []
                if q:
                    where.append("(r.url LIKE ? OR r.domain LIKE ? OR r.business LIKE ? OR r.category LIKE ? OR r.details LIKE ? OR CAST(r.id AS TEXT)=?)")
                    args.extend([f"%{q}%"] * 5 + [q.lstrip("#")])
                if status in REPORT_STATUSES:
                    where.append("r.status=?"); args.append(status)
                priority = (query.get("priority", [""])[0] or "").strip()
                if priority in {"low", "normal", "high", "urgent"}:
                    where.append("r.priority=?"); args.append(priority)
                condition = " WHERE " + " AND ".join(where) if where else ""
                total = conn.execute("SELECT COUNT(*) FROM reports r" + condition, args).fetchone()[0]
                rows = [dict(row) for row in conn.execute("""
                    SELECT r.id,r.url,r.domain,r.business,r.category,r.status,r.priority,r.assigned_to,r.created_at,r.public_summary,
                      u.name assigned_name,(CASE WHEN r.evidence_name<>'' THEN 1 ELSE 0 END + (SELECT COUNT(*) FROM report_attachments a WHERE a.report_id=r.id) + (SELECT COUNT(*) FROM report_followups f WHERE f.report_id=r.id AND f.evidence_path<>'')) evidence_count,
                      (CASE WHEN r.ai_analysis IS NOT NULL AND r.ai_analysis<>'' AND r.ai_analysis<>'null' THEN 1 ELSE 0 END) has_ai
                    FROM reports r LEFT JOIN users u ON u.id=r.assigned_to
                """ + condition + " ORDER BY CASE r.priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END, r.created_at DESC LIMIT ? OFFSET ?", (*args, limit, offset))]
                return self.send_json({"reports": rows, "total": total, "page": page, "limit": limit}) or True
            if report_match:
                report_id = int(report_match.group(1))
                report = conn.execute("SELECT r.*,u.name assigned_name FROM reports r LEFT JOIN users u ON u.id=r.assigned_to WHERE r.id=?", (report_id,)).fetchone()
                if not report:
                    self.send_json({"error": "Report not found."}, 404); return True
                result = dict(report)
                result["notes"] = [dict(row) for row in conn.execute("SELECT n.id,n.note,n.created_at,u.name author_name FROM admin_report_notes n JOIN users u ON u.id=n.author_id WHERE n.report_id=? ORDER BY n.id DESC", (report_id,))]
                result["timeline"] = [dict(row) for row in conn.execute("SELECT e.id,e.old_status,e.new_status,e.note,e.created_at,u.name moderator FROM moderation_events e LEFT JOIN users u ON u.id=e.moderator_id WHERE e.report_id=? ORDER BY e.id", (report_id,))]
                result["attachments"] = [dict(row) for row in conn.execute("SELECT id,evidence_name,mime_type,size_bytes,created_at FROM report_attachments WHERE report_id=? ORDER BY id", (report_id,))]
                return self.send_json(result) or True
            if path == "/api/admin/threats":
                where, args = [], []
                if q: where.append("(t.domain LIKE ? OR t.category LIKE ? OR r.url LIKE ?)"); args.extend([f"%{q}%"] * 3)
                if status in {"verified", "false_positive"}: where.append("t.status=?"); args.append(status)
                condition = " WHERE " + " AND ".join(where) if where else ""
                total = conn.execute("SELECT COUNT(*) FROM threat_records t JOIN reports r ON r.id=t.source_report_id" + condition, args).fetchone()[0]
                rows = [dict(row) for row in conn.execute("SELECT t.*,r.category report_category,r.status report_status,u.name reviewer_name,(SELECT COUNT(*) FROM reports related WHERE related.domain=t.domain) related_report_count FROM threat_records t JOIN reports r ON r.id=t.source_report_id LEFT JOIN users u ON u.id=t.reviewer_id" + condition + " ORDER BY t.updated_at DESC LIMIT ? OFFSET ?", (*args, limit, offset))]
                return self.send_json({"threats": rows, "total": total, "page": page, "limit": limit}) or True
            if path == "/api/admin/scanner/settings":
                return self.send_json({"settings": scanner_configuration(), "fixed_checks": ["DNS public-address validation", "TLS certificate validation", "HTTP security headers", "redirect destination validation"], "unavailable": ["rate limiting (deployment-level configuration)", "WHOIS/registration age", "external threat feeds"]}) or True
            if path == "/api/admin/incidents":
                where, args = [], []
                if q: where.append("(i.title LIKE ? OR CAST(i.id AS TEXT)=?)"); args.extend([f"%{q}%", q.lstrip("#")])
                if status in {"new", "investigating", "contained", "resolved", "closed"}: where.append("i.status=?"); args.append(status)
                severity = (query.get("severity", [""])[0] or "").strip()
                if severity in {"low", "medium", "high", "critical"}: where.append("i.severity=?"); args.append(severity)
                condition = " WHERE " + " AND ".join(where) if where else ""
                total = conn.execute("SELECT COUNT(*) FROM incidents i" + condition, args).fetchone()[0]
                rows = [dict(row) for row in conn.execute("SELECT i.*,assignee.name assigned_name,(SELECT COUNT(*) FROM incident_reports ir WHERE ir.incident_id=i.id) report_count FROM incidents i LEFT JOIN users assignee ON assignee.id=i.assigned_to" + condition + " ORDER BY i.updated_at DESC LIMIT ? OFFSET ?", (*args, limit, offset))]
                return self.send_json({"incidents": rows, "total": total, "page": page, "limit": limit}) or True
            if incident_match:
                incident_id = int(incident_match.group(1))
                incident = conn.execute("SELECT i.*,assignee.name assigned_name,creator.name creator_name FROM incidents i LEFT JOIN users assignee ON assignee.id=i.assigned_to JOIN users creator ON creator.id=i.created_by WHERE i.id=?", (incident_id,)).fetchone()
                if not incident:
                    self.send_json({"error": "Incident not found."}, 404); return True
                result = dict(incident)
                result["reports"] = [dict(row) for row in conn.execute("SELECT r.id,r.url,r.domain,r.category,r.status FROM incident_reports ir JOIN reports r ON r.id=ir.report_id WHERE ir.incident_id=?", (incident_id,))]
                result["events"] = [dict(row) for row in conn.execute("SELECT e.id,e.event_type,e.previous_json,e.new_json,e.note,e.created_at,u.name actor_name FROM incident_events e LEFT JOIN users u ON u.id=e.actor_id WHERE e.incident_id=? ORDER BY e.id DESC", (incident_id,))]
                return self.send_json(result) or True
            if path == "/api/admin/audit":
                audit_union = """
                      SELECT a.id,'admin_action' event_type,a.actor_id,u.name actor_name,a.action,a.resource_type,a.resource_id,a.previous_json,a.new_json,a.metadata_json,a.created_at
                      FROM admin_audit_events a LEFT JOIN users u ON u.id=a.actor_id
                      UNION ALL
                      SELECT e.id,'report_moderation',e.moderator_id,u.name,'report.status_changed','report',CAST(e.report_id AS TEXT),json_object('status',e.old_status),json_object('status',e.new_status),json_object('note',e.note),e.created_at
                      FROM moderation_events e LEFT JOIN users u ON u.id=e.moderator_id
                      UNION ALL
                      SELECT e.id,'incident_event',e.actor_id,u.name,e.event_type,'incident',CAST(e.incident_id AS TEXT),e.previous_json,e.new_json,json_object('note',e.note),e.created_at
                      FROM incident_events e LEFT JOIN users u ON u.id=e.actor_id
                      UNION ALL
                      SELECT f.id,'ai_feedback',f.moderator_id,u.name,'ai.finding_feedback','ai_run',CAST(f.run_id AS TEXT),'{}',json_object('finding_key',f.finding_key,'decision',f.decision),json_object('note',f.note),f.created_at
                      FROM ai_feedback f LEFT JOIN users u ON u.id=f.moderator_id
                """
                filter_clause = "(?='' OR action LIKE ? OR resource_type LIKE ? OR resource_id LIKE ? OR actor_name LIKE ? OR event_type LIKE ?)"
                filter_args = (q, f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%")
                total = conn.execute(f"SELECT COUNT(*) FROM ({audit_union}) WHERE {filter_clause}", filter_args).fetchone()[0]
                rows = [dict(row) for row in conn.execute(f"SELECT * FROM ({audit_union}) WHERE {filter_clause} ORDER BY created_at DESC LIMIT ? OFFSET ?", (*filter_args, limit, offset))]
                return self.send_json({"events": rows, "page": page, "limit": limit, "total": total}) or True
            if path == "/api/admin/ai":
                counts = dict(conn.execute("SELECT COUNT(*) total_runs,COUNT(DISTINCT provider) providers,MAX(created_at) latest_run FROM ai_runs").fetchone())
                recent = [dict(row) for row in conn.execute("SELECT id,resource_type,resource_id,domain,analysis_type,provider,model,model_version,status,user_consented,created_at FROM ai_runs ORDER BY id DESC LIMIT 30")]
                feedback = conn.execute("SELECT COUNT(*) total, SUM(decision='accepted') accepted, SUM(decision='rejected') rejected FROM ai_feedback").fetchone()
                labels = conn.execute("SELECT COUNT(*) total,COUNT(DISTINCT report_id) reports FROM ai_training_labels").fetchone()
                return self.send_json({"provider": provider_status(), "counts": counts, "feedback": dict(feedback), "human_labels": dict(labels), "recent_runs": recent}) or True
        return False

    def handle_admin_post(self, path, payload):
        note_match = re.fullmatch(r"/api/admin/reports/(\d+)/notes", path)
        incident_event_match = re.fullmatch(r"/api/admin/incidents/(\d+)/events", path)
        if path not in {"/api/admin/threats", "/api/admin/incidents"} and not (note_match or incident_event_match):
            return False
        user = self.require_user("admin")
        if not user:
            return True
        with db() as conn:
            if note_match:
                report_id = int(note_match.group(1))
                note = str(payload.get("note", "")).strip()[:2000]
                if len(note) < 8:
                    self.send_json({"error": "Add an internal note of at least 8 characters."}, 400); return True
                if not conn.execute("SELECT id FROM reports WHERE id=?", (report_id,)).fetchone():
                    self.send_json({"error": "Report not found."}, 404); return True
                cursor = conn.execute("INSERT INTO admin_report_notes(report_id,author_id,note,created_at) VALUES(?,?,?,?)", (report_id, user["id"], note, now()))
                audit_admin_action(conn, user["id"], "report.internal_note_added", "report", report_id, new={"note_id": cursor.lastrowid})
                self.send_json({"ok": True, "id": cursor.lastrowid}, 201); return True
            if path == "/api/admin/threats":
                try: report_id = int(payload.get("report_id", 0))
                except (TypeError, ValueError): report_id = 0
                note = str(payload.get("verification_note", "")).strip()[:1200]
                if not report_id or len(note) < 20:
                    self.send_json({"error": "Select a report and record a verification note of at least 20 characters."}, 400); return True
                report = conn.execute("SELECT id,url,domain,category,status FROM reports WHERE id=?", (report_id,)).fetchone()
                if not report:
                    self.send_json({"error": "Report not found."}, 404); return True
                if report["status"] != "Verified Findings":
                    self.send_json({"error": "Only a report with the human-reviewed status Verified Findings can be added to threat intelligence."}, 409); return True
                domain = report["domain"] or report_domain(report["url"])
                stamp = now()
                existing = conn.execute("SELECT * FROM threat_records WHERE source_report_id=?", (report_id,)).fetchone()
                if existing:
                    previous = {"status": existing["status"], "verification_note": existing["verification_note"]}
                    conn.execute("UPDATE threat_records SET status='verified',reviewer_id=?,verification_note=?,last_seen=?,updated_at=? WHERE id=?", (user["id"], note, stamp, stamp, existing["id"]))
                    threat_id = existing["id"]
                    audit_admin_action(conn, user["id"], "threat.reverified", "threat", threat_id, previous=previous, new={"status": "verified", "verification_note": note, "source_report_id": report_id})
                else:
                    cursor = conn.execute("INSERT INTO threat_records(domain,category,status,source_report_id,created_by,reviewer_id,verification_note,first_seen,last_seen,created_at,updated_at) VALUES(?,?,'verified',?,?,?,?,?,?,?,?)", (domain, report["category"], report_id, user["id"], user["id"], note, stamp, stamp, stamp, stamp))
                    threat_id = cursor.lastrowid
                    audit_admin_action(conn, user["id"], "threat.verified", "threat", threat_id, new={"domain": domain, "category": report["category"], "source_report_id": report_id, "status": "verified"})
                self.send_json({"ok": True, "id": threat_id, "domain": domain}, 201); return True
            if path == "/api/admin/incidents":
                title = str(payload.get("title", "")).strip()[:160]
                severity = str(payload.get("severity", "medium"))
                resolution_note = str(payload.get("note", "")).strip()[:2000]
                try: assigned_to = int(payload["assigned_to"]) if payload.get("assigned_to") not in {None, ""} else None
                except (TypeError, ValueError): assigned_to = -1
                report_ids = payload.get("report_ids", [])
                if not isinstance(report_ids, list) or len(report_ids) > 20:
                    self.send_json({"error": "Link no more than 20 reports."}, 400); return True
                try: report_ids = sorted(set(int(item) for item in report_ids))
                except (TypeError, ValueError):
                    self.send_json({"error": "Report references must be valid IDs."}, 400); return True
                if len(title) < 5 or severity not in {"low", "medium", "high", "critical"}:
                    self.send_json({"error": "Enter an incident title and choose a supported severity."}, 400); return True
                if assigned_to is not None and not conn.execute("SELECT id FROM users WHERE id=? AND role='admin' AND status='active'", (assigned_to,)).fetchone():
                    self.send_json({"error": "Assign the incident to an active administrator."}, 400); return True
                if report_ids:
                    marks = ",".join("?" for _ in report_ids)
                    found = conn.execute(f"SELECT COUNT(*) FROM reports WHERE id IN ({marks})", report_ids).fetchone()[0]
                    if found != len(report_ids):
                        self.send_json({"error": "One or more linked reports do not exist."}, 400); return True
                stamp = now()
                cursor = conn.execute("INSERT INTO incidents(title,severity,status,assigned_to,created_by,resolution_note,created_at,updated_at) VALUES(?,?,'new',?,?,?, ?,?)", (title, severity, assigned_to, user["id"], resolution_note, stamp, stamp))
                incident_id = cursor.lastrowid
                conn.executemany("INSERT INTO incident_reports(incident_id,report_id) VALUES(?,?)", [(incident_id, report_id) for report_id in report_ids])
                conn.execute("INSERT INTO incident_events(incident_id,actor_id,event_type,new_json,note,created_at) VALUES(?,?,'incident.created',?,?,?)", (incident_id, user["id"], json.dumps({"title": title, "severity": severity, "assigned_to": assigned_to, "report_ids": report_ids}), resolution_note, stamp))
                audit_admin_action(conn, user["id"], "incident.created", "incident", incident_id, new={"title": title, "severity": severity, "status": "new", "assigned_to": assigned_to, "report_ids": report_ids})
                self.send_json({"ok": True, "id": incident_id}, 201); return True
            incident_id = int(incident_event_match.group(1))
            note = str(payload.get("note", "")).strip()[:2000]
            if len(note) < 3 or not conn.execute("SELECT id FROM incidents WHERE id=?", (incident_id,)).fetchone():
                self.send_json({"error": "Incident not found or note is too short."}, 400); return True
            cursor = conn.execute("INSERT INTO incident_events(incident_id,actor_id,event_type,note,created_at) VALUES(?,?,'note',?,?)", (incident_id, user["id"], note, now()))
            audit_admin_action(conn, user["id"], "incident.note_added", "incident", incident_id, new={"event_id": cursor.lastrowid})
            self.send_json({"ok": True, "id": cursor.lastrowid}, 201); return True

    def handle_admin_patch(self, path, payload):
        user_match = re.fullmatch(r"/api/admin/users/(\d+)/(status|role)", path)
        report_match = re.fullmatch(r"/api/admin/reports/(\d+)", path)
        threat_match = re.fullmatch(r"/api/admin/threats/(\d+)/status", path)
        incident_match = re.fullmatch(r"/api/admin/incidents/(\d+)", path)
        if path != "/api/admin/scanner/settings" and not (user_match or report_match or threat_match or incident_match):
            return False
        user = self.require_user("admin")
        if not user:
            return True
        with db() as conn:
            if user_match:
                target_id, field = int(user_match.group(1)), user_match.group(2)
                target = conn.execute("SELECT id,name,email,role,status FROM users WHERE id=?", (target_id,)).fetchone()
                value = str(payload.get(field, ""))
                if not target:
                    self.send_json({"error": "User not found."}, 404); return True
                if target_id == user["id"]:
                    self.send_json({"error": "You cannot change your own account status or role."}, 409); return True
                if field == "status":
                    if value not in {"active", "suspended"}:
                        self.send_json({"error": "Choose active or suspended."}, 400); return True
                    if target["role"] == "admin" and target["status"] == "active" and value == "suspended":
                        active_admins = conn.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND status='active'").fetchone()[0]
                        if active_admins <= 1:
                            self.send_json({"error": "The last active administrator cannot be suspended."}, 409); return True
                    conn.execute("UPDATE users SET status=? WHERE id=?", (value, target_id))
                    if value == "suspended": conn.execute("DELETE FROM sessions WHERE user_id=?", (target_id,))
                else:
                    if value not in {"user", "admin"}:
                        self.send_json({"error": "Choose user or admin."}, 400); return True
                    if target["role"] == "admin" and value == "user" and target["status"] == "active":
                        active_admins = conn.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND status='active'").fetchone()[0]
                        if active_admins <= 1:
                            self.send_json({"error": "The last active administrator cannot be demoted."}, 409); return True
                    conn.execute("UPDATE users SET role=? WHERE id=?", (value, target_id))
                previous_value = target[field]
                audit_admin_action(conn, user["id"], f"user.{field}_changed", "user", target_id, previous={field: previous_value}, new={field: value})
                self.send_json({"ok": True, "id": target_id, field: value}, 200); return True
            if report_match:
                report_id = int(report_match.group(1))
                report = conn.execute("SELECT assigned_to,priority,status FROM reports WHERE id=?", (report_id,)).fetchone()
                if not report:
                    self.send_json({"error": "Report not found."}, 404); return True
                old = dict(report); updates = {}
                if "assigned_to" in payload:
                    try: assigned = int(payload["assigned_to"]) if payload["assigned_to"] not in {None, ""} else None
                    except (TypeError, ValueError): assigned = -1
                    if assigned is not None and not conn.execute("SELECT id FROM users WHERE id=? AND role='admin' AND status='active'", (assigned,)).fetchone():
                        self.send_json({"error": "Assign the report to an active administrator or leave it unassigned."}, 400); return True
                    updates["assigned_to"] = assigned
                if "priority" in payload:
                    priority = str(payload["priority"])
                    if priority not in {"low", "normal", "high", "urgent"}:
                        self.send_json({"error": "Choose a supported priority."}, 400); return True
                    updates["priority"] = priority
                if not updates:
                    self.send_json({"error": "No supported report fields were provided."}, 400); return True
                conn.execute("UPDATE reports SET " + ",".join(f"{key}=?" for key in updates) + " WHERE id=?", (*updates.values(), report_id))
                audit_admin_action(conn, user["id"], "report.assignment_or_priority_changed", "report", report_id, previous=old, new={**old, **updates})
                self.send_json({"ok": True, "report_id": report_id, **updates}); return True
            if threat_match:
                threat_id = int(threat_match.group(1)); status = str(payload.get("status", "")); note = str(payload.get("note", "")).strip()[:1200]
                if status not in {"verified", "false_positive"} or len(note) < 10:
                    self.send_json({"error": "Choose verified or false positive and record a review note of at least 10 characters."}, 400); return True
                threat = conn.execute("SELECT * FROM threat_records WHERE id=?", (threat_id,)).fetchone()
                if not threat:
                    self.send_json({"error": "Threat record not found."}, 404); return True
                stamp = now(); previous = {"status": threat["status"], "verification_note": threat["verification_note"]}
                conn.execute("UPDATE threat_records SET status=?,reviewer_id=?,verification_note=?,last_seen=?,updated_at=? WHERE id=?", (status, user["id"], note, stamp, stamp, threat_id))
                audit_admin_action(conn, user["id"], "threat.reviewed", "threat", threat_id, previous=previous, new={"status": status, "verification_note": note})
                self.send_json({"ok": True, "id": threat_id, "status": status}); return True
            if path == "/api/admin/scanner/settings":
                allowed = {"request_timeout_seconds", "max_redirects", "phishing_heuristics_enabled", "ai_content_analysis_enabled"}
                if not payload or set(payload) - allowed:
                    self.send_json({"error": "Only runtime-supported scanner settings can be changed."}, 400); return True
                current = scanner_configuration(); changed = {}
                for key, raw in payload.items():
                    if key == "request_timeout_seconds":
                        try: value = int(raw)
                        except (TypeError, ValueError): value = -1
                        if not 3 <= value <= 20:
                            self.send_json({"error": "Request timeout must be between 3 and 20 seconds."}, 400); return True
                    elif key == "max_redirects":
                        try: value = int(raw)
                        except (TypeError, ValueError): value = -1
                        if not 0 <= value <= 10:
                            self.send_json({"error": "Maximum redirects must be between 0 and 10."}, 400); return True
                    else:
                        if not isinstance(raw, bool):
                            self.send_json({"error": f"{key} must be a boolean."}, 400); return True
                        value = raw
                    if current[key] != value: changed[key] = value
                stamp = now()
                for key, value in changed.items():
                    conn.execute("INSERT INTO scanner_settings(setting_key,setting_value,updated_by,updated_at) VALUES(?,?,?,?) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value,updated_by=excluded.updated_by,updated_at=excluded.updated_at", (key, str(value).lower() if isinstance(value, bool) else str(value), user["id"], stamp))
                if changed: audit_admin_action(conn, user["id"], "scanner.settings_changed", "scanner", "runtime", previous=current, new={**current, **changed})
                self.send_json({"ok": True, "settings": {**current, **changed}}); return True
            incident_id = int(incident_match.group(1))
            incident = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if not incident:
                self.send_json({"error": "Incident not found."}, 404); return True
            old = dict(incident); new = dict(old)
            for key, allowed_values in (("status", {"new", "investigating", "contained", "resolved", "closed"}), ("severity", {"low", "medium", "high", "critical"})):
                if key in payload:
                    value = str(payload[key])
                    if value not in allowed_values:
                        self.send_json({"error": f"Choose a supported incident {key}."}, 400); return True
                    new[key] = value
            if "assigned_to" in payload:
                try: assigned = int(payload["assigned_to"]) if payload["assigned_to"] not in {None, ""} else None
                except (TypeError, ValueError): assigned = -1
                if assigned is not None and not conn.execute("SELECT id FROM users WHERE id=? AND role='admin' AND status='active'", (assigned,)).fetchone():
                    self.send_json({"error": "Assign the incident to an active administrator or leave it unassigned."}, 400); return True
                new["assigned_to"] = assigned
            if "resolution_note" in payload:
                new["resolution_note"] = str(payload["resolution_note"]).strip()[:2000]
            if new["status"] in {"resolved", "closed"} and len(new["resolution_note"]) < 8:
                self.send_json({"error": "Add a resolution note before resolving or closing an incident."}, 400); return True
            changed = {key: new[key] for key in ("status", "severity", "assigned_to", "resolution_note") if new[key] != old[key]}
            if not changed:
                self.send_json({"error": "No incident changes were provided."}, 400); return True
            new["updated_at"] = now()
            conn.execute("UPDATE incidents SET status=?,severity=?,assigned_to=?,resolution_note=?,updated_at=? WHERE id=?", (new["status"], new["severity"], new["assigned_to"], new["resolution_note"], new["updated_at"], incident_id))
            conn.execute("INSERT INTO incident_events(incident_id,actor_id,event_type,previous_json,new_json,note,created_at) VALUES(?,?,'incident.updated',?,?,?,?)", (incident_id, user["id"], json.dumps({key: old[key] for key in changed}), json.dumps(changed), str(payload.get("note", "")).strip()[:1000], new["updated_at"]))
            audit_admin_action(conn, user["id"], "incident.updated", "incident", incident_id, previous={key: old[key] for key in changed}, new=changed)
            self.send_json({"ok": True, "id": incident_id, **changed}); return True

    def do_GET(self):
        parsed_request = urllib.parse.urlsplit(self.path)
        path = parsed_request.path
        if path.startswith("/api/admin/") and self.handle_admin_get(path, urllib.parse.parse_qs(parsed_request.query)):
            return
        if path == "/api/ai/status":
            status = provider_status()
            status["capabilities"] = ["website content analysis", "complaint assistance", "evidence text analysis"]
            status["evidence_privacy"] = "Private report/evidence text is sent to the configured provider only after explicit user consent."
            return self.send_json(status)
        if path == "/api/admin/ai/evaluation":
            user = self.require_user("admin")
            if not user:
                return
            with db() as conn:
                rows = conn.execute("""
                    SELECT label.report_id,label.category,label.label,run.result_json
                    FROM ai_training_labels AS label
                    LEFT JOIN ai_runs AS run ON run.id=label.run_id
                    WHERE label.partition_name='evaluation'
                      AND label.id=(SELECT MAX(latest.id) FROM ai_training_labels AS latest WHERE latest.report_id=label.report_id)
                    ORDER BY label.id
                """).fetchall()
            records = []
            for row in rows:
                try:
                    result = json.loads(row["result_json"] or "{}")
                except json.JSONDecodeError:
                    result = {}
                records.append({"case_id": row["report_id"], "category": row["category"], "label": row["label"], "prediction": result.get("triage")})
            return self.send_json(evaluate_predictions(records))
        if path == "/api/community":
            params = urllib.parse.parse_qs(parsed_request.query)
            query = str(params.get("q", [""])[0])[:160]
            status = str(params.get("status", ["all"])[0])[:60]
            category = str(params.get("category", ["all"])[0])[:100]
            sort = str(params.get("sort", ["latest"])[0])
            try: page = int(params.get("page", ["1"])[0])
            except ValueError: page = 1
            user = self.current_user()
            with db() as conn:
                result = community_search(conn, query=query, status=status, category=category, sort=sort, page=page, admin=bool(user and user["role"] == "admin"))
                result["categories"] = [row[0] for row in conn.execute("SELECT DISTINCT category FROM reports WHERE status IN (" + ",".join("?" for _ in PUBLIC_STATUSES) + ") ORDER BY category", PUBLIC_STATUSES)]
            return self.send_json(result)
        if path.startswith("/api/community/domain/"):
            domain = path.rsplit("/", 1)[-1].lower().rstrip(".")
            if domain.startswith("www."):
                domain = domain[4:]
            if not re.fullmatch(r"[a-z0-9.-]{1,253}", domain):
                return self.send_json({"error": "Enter a valid domain."}, 400)
            with db() as conn:
                result = public_counts(conn, domain)
            return self.send_json(result)
        if path == "/api/notifications":
            user = self.current_user()
            guest_hashes = self.guest_token_hashes()
            with db() as conn:
                if user:
                    if guest_hashes:
                        slots = ",".join("?" for _ in guest_hashes)
                        items = [dict(row) for row in conn.execute(f"SELECT id,report_id,kind,title,message,is_read,created_at FROM notifications WHERE user_id=? OR guest_token_hash IN ({slots}) ORDER BY id DESC LIMIT 50", (user["id"], *guest_hashes))]
                    else:
                        items = [dict(row) for row in conn.execute("SELECT id,report_id,kind,title,message,is_read,created_at FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 50", (user["id"],))]
                elif guest_hashes:
                    slots = ",".join("?" for _ in guest_hashes)
                    items = [dict(row) for row in conn.execute(f"SELECT id,report_id,kind,title,message,is_read,created_at FROM notifications WHERE guest_token_hash IN ({slots}) ORDER BY id DESC LIMIT 50", guest_hashes)]
                else:
                    items = []
            return self.send_json({"notifications": items, "unread": sum(not item["is_read"] for item in items)})
        if path == "/api/auth/me":
            user = self.current_user()
            return self.send_json(user or {"user": None}, 200 if user else 401)
        if path == "/api/history":
            user = self.current_user()
            guest_hashes = self.guest_token_hashes()
            with db() as conn:
                scans = [dict(row) for row in conn.execute("SELECT id,url,domain,score,label,summary,checks,created_at,scanner_version,calculation,ai_analysis,phishing_analysis FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 20", (user["id"],))] if user else []
                placeholders_public = ",".join("?" for _ in PUBLIC_STATUSES)
                reports = [dict(row) for row in conn.execute(f"SELECT id,url,category,details,business,status,created_at,evidence_name FROM reports WHERE status IN ({placeholders_public}) ORDER BY id DESC LIMIT 100", PUBLIC_STATUSES)]
                if user:
                    own = [dict(row) for row in conn.execute("SELECT id,url,category,business,status,created_at,public_update,user_id,guest_token_hash FROM reports WHERE user_id=? ORDER BY id DESC LIMIT 50", (user["id"],))]
                    if guest_hashes:
                        placeholders = ",".join("?" for _ in guest_hashes)
                        own.extend(dict(row) for row in conn.execute(f"SELECT id,url,category,business,status,created_at,public_update,user_id,guest_token_hash FROM reports WHERE user_id IS NULL AND guest_token_hash IN ({placeholders}) ORDER BY id DESC LIMIT 30", guest_hashes))
                elif guest_hashes:
                    placeholders = ",".join("?" for _ in guest_hashes)
                    own = [dict(row) for row in conn.execute(f"SELECT id,url,category,business,status,created_at,public_update,user_id,guest_token_hash FROM reports WHERE guest_token_hash IN ({placeholders}) ORDER BY id DESC LIMIT 30", guest_hashes)]
                else:
                    own = []
                if user and user["role"] == "admin":
                    reports = [dict(row) for row in conn.execute("SELECT id,url,category,details,business,incident_date,amount,evidence_name,status,created_at FROM reports ORDER BY id DESC LIMIT 100")]
                    stats_row = conn.execute("SELECT (SELECT COUNT(*) FROM users) AS users,(SELECT COUNT(*) FROM reports) AS reports,(SELECT COUNT(*) FROM scans) AS scans,(SELECT COUNT(*) FROM reports WHERE status IN ('Submitted','Under Review','More Information Required','Disputed')) AS review_queue,(SELECT COUNT(*) FROM reports WHERE status='Verified Findings') AS verified,(SELECT COUNT(*) FROM reports WHERE status='Under Review') AS under_investigation,(SELECT COUNT(*) FROM reports WHERE status='Disputed') AS disputed,(SELECT COUNT(*) FROM report_flags WHERE status='Pending review') AS pending_flags").fetchone()
                    admin_stats = dict(stats_row)
                else:
                    admin_stats = None
                scan_count = conn.execute("SELECT COUNT(*) FROM scans WHERE user_id=?", (user["id"],)).fetchone()[0] if user else 0
                if user:
                    report_count = conn.execute("SELECT COUNT(*) FROM reports WHERE user_id=?", (user["id"],)).fetchone()[0]
                    if guest_hashes:
                        slots = ",".join("?" for _ in guest_hashes)
                        report_count += conn.execute(f"SELECT COUNT(*) FROM reports WHERE user_id IS NULL AND guest_token_hash IN ({slots})", guest_hashes).fetchone()[0]
                    owner_condition = "(user_id=? OR guest_token_hash IN (" + (",".join("?" for _ in guest_hashes) if guest_hashes else "''") + "))"
                    owner_args = (user["id"], *guest_hashes)
                elif guest_hashes:
                    slots = ",".join("?" for _ in guest_hashes)
                    report_count = conn.execute(f"SELECT COUNT(*) FROM reports WHERE user_id IS NULL AND guest_token_hash IN ({slots})", guest_hashes).fetchone()[0]
                    owner_condition = f"user_id IS NULL AND guest_token_hash IN ({slots})"
                    owner_args = tuple(guest_hashes)
                else:
                    report_count = 0
                    owner_condition, owner_args = "0", ()
                awaiting_count = conn.execute(f"SELECT COUNT(*) FROM reports WHERE {owner_condition} AND status IN ('Submitted','Under Review')", owner_args).fetchone()[0]
                info_count = conn.execute(f"SELECT COUNT(*) FROM reports WHERE {owner_condition} AND status='More Information Required'", owner_args).fetchone()[0]
                overview = {"scans": scan_count, "reports": report_count, "awaiting_review": awaiting_count, "more_information_required": info_count}
            for scan in scans:
                scan["checks"] = json.loads(scan["checks"])
                scan["findings"] = scan["checks"]
                scan["calculation"] = json.loads(scan.get("calculation") or "{}")
                scan["ai_analysis"] = json.loads(scan.get("ai_analysis") or "{}")
                scan["phishing_analysis"] = json.loads(scan.get("phishing_analysis") or "{}")
                with db() as conn:
                    threat = conn.execute("SELECT id,domain,category,verification_note,first_seen,last_seen,updated_at FROM threat_records WHERE status='verified' AND (?=domain OR ? LIKE '%.'||domain) ORDER BY length(domain) DESC LIMIT 1", (scan["domain"], scan["domain"])).fetchone()
                    scan["verified_threat_match"] = dict(threat) if threat else None
                scan["label"] = scan["label"]
            admin_view = bool(user and user["role"] == "admin")
            for report in reports:
                report["domain"] = urllib.parse.urlsplit(report["url"]).hostname or ""
                report["description"] = safe_description(report.get("details", ""))[:240]
                if not admin_view:
                    report.pop("details", None)
                report["evidence_submitted"] = bool(report.pop("evidence_name", ""))
                report["evidence_reviewed"] = report["evidence_submitted"] and report["status"] in {"Partially Supported", "Verified Findings"}
                report.pop("email", None)
                report.pop("reference", None)
                report.pop("links", None)
                if not admin_view:
                    report.pop("amount", None)
            for item in own:
                action_actor_user = item.get("user_id")
                action_actor_guest = item.get("guest_token_hash") or ""
                steps = guidance_for(item["category"])["steps"]
                with db() as conn:
                    completed = conn.execute("SELECT COUNT(*) FROM report_guidance_actions WHERE report_id=? AND completed=1 AND user_id IS ? AND guest_token_hash=?", (item["id"], action_actor_user, action_actor_guest)).fetchone()[0]
                item["guidance_total"] = len(steps)
                item["guidance_completed"] = completed
                item["guidance_pending"] = max(0, len(steps) - completed)
                item["reference_code"] = f"TSH-{int(item['id']):06d}"
                item["domain"] = report_domain(item["url"])
                item.pop("user_id", None)
                item.pop("guest_token_hash", None)
            return self.send_json({"scans": scans, "reports": reports, "my_reports": own, "admin_stats": admin_stats, "overview": overview})
        detail_match = re.fullmatch(r"/api/reports/(\d+)", path)
        if detail_match:
            report_id = int(detail_match.group(1))
            user = self.current_user()
            guest_hashes = self.guest_token_hashes()
            with db() as conn:
                row = conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
                if not row:
                    return self.send_json({"error": "Report not found."}, 404)
                is_admin = bool(user and user["role"] == "admin")
                is_owner = actor_owns_report(row, user, guest_hashes)
                is_public = row["status"] in PUBLIC_STATUSES
                if not (is_admin or is_owner or is_public):
                    return self.send_json({"error": "Report not found."}, 404)
                history_rows = conn.execute("SELECT old_status,new_status,note,created_at FROM moderation_events WHERE report_id=? ORDER BY id", (report_id,)).fetchall()
                related_rows = [item for item in conn.execute("SELECT id,url,category,status,created_at,evidence_name FROM reports WHERE id<>? AND category=? AND status IN (" + ",".join("?" for _ in PUBLIC_STATUSES) + ")", (report_id, row["category"], *PUBLIC_STATUSES)).fetchall() if report_domain(item["url"]) == report_domain(row["url"])]
                followups = conn.execute("SELECT id,details,evidence_name,created_at FROM report_followups WHERE report_id=? ORDER BY id", (report_id,)).fetchall() if is_admin or is_owner else []
                attachments = conn.execute("SELECT id,evidence_name,created_at FROM report_attachments WHERE report_id=? ORDER BY id", (report_id,)).fetchall() if is_admin or is_owner else []
                attachment_count = conn.execute("SELECT (CASE WHEN evidence_name<>'' THEN 1 ELSE 0 END)+(SELECT COUNT(*) FROM report_attachments WHERE report_id=?)+(SELECT COUNT(*) FROM report_followups WHERE report_id=? AND evidence_path<>'') FROM reports WHERE id=?", (report_id, report_id, report_id)).fetchone()[0]
                flags = conn.execute("SELECT id,type,reason,contact,status,review_note,created_at FROM report_flags WHERE report_id=? ORDER BY id DESC", (report_id,)).fetchall() if is_admin else []
                ai_feedback = [dict(item) for item in conn.execute("SELECT f.run_id,f.finding_key,f.decision,f.note,f.created_at,u.name AS moderator FROM ai_feedback AS f JOIN ai_runs AS run ON run.id=f.run_id JOIN users AS u ON u.id=f.moderator_id WHERE run.resource_type='report' AND run.resource_id=? ORDER BY f.id", (report_id,)).fetchall()] if is_admin else []
                guidance_actions = conn.execute("SELECT action_id,completed FROM report_guidance_actions WHERE report_id=? AND ((user_id=? AND ? IS NOT NULL) OR guest_token_hash IN (" + (",".join("?" for _ in guest_hashes) if guest_hashes else "''") + "))", (report_id, user["id"] if user else None, user["id"] if user else None, *guest_hashes)).fetchall() if is_owner else []
            if not is_admin and not is_owner and not is_public:
                return self.send_json({"error": "Report not found."}, 404)
            result = dict(row)
            result["domain"] = report_domain(result["url"])
            result["reference_code"] = f"TSH-{report_id:06d}"
            result["can_manage"] = bool(is_admin or is_owner)
            result["is_owner"] = bool(is_owner)
            result["is_admin"] = is_admin
            result["available_transitions"] = sorted(STATUS_TRANSITIONS.get(result["status"], set())) if is_admin else []
            result["evidence_analysis"] = json.loads(result.get("evidence_analysis") or "{}")
            result["ai_analysis"] = json.loads(result.get("ai_analysis") or "{}")
            if not is_admin:
                result.pop("assigned_to", None)
                result.pop("priority", None)
            result["guidance"] = guidance_for(result["category"])
            result["completed_guidance_actions"] = [item["action_id"] for item in guidance_actions if item["completed"]]
            result["verification_history"] = [{"old_status": item["old_status"], "new_status": item["new_status"], "event_label": "Additional information received" if item["old_status"] == item["new_status"] and item["note"] == "Reporter supplied additional information." else item["new_status"], "created_at": item["created_at"], **({"note": item["note"]} if is_admin else {})} for item in history_rows]
            result["related_reports"] = [{"id": item["id"], "domain": report_domain(item["url"]), "category": item["category"], "status": item["status"], "created_at": item["created_at"], "evidence_reviewed": bool(item["evidence_name"] and item["status"] in {"Partially Supported", "Verified Findings"})} for item in related_rows]
            result["followups"] = [dict(item) for item in followups]
            result["evidence_files"] = ([{"id": 0, "name": result.get("evidence_name"), "kind": "submitted"}] if result.get("evidence_name") else []) + [{"id": item["id"], "name": item["evidence_name"], "kind": "additional"} for item in attachments] + [{"id": item["id"], "name": item["evidence_name"], "kind": "follow-up"} for item in followups if item["evidence_name"]]
            result["disputes"] = [dict(item) for item in flags]
            if is_admin:
                result["ai_feedback"] = ai_feedback
            result["evidence_submitted"] = bool(attachment_count)
            result["evidence_file_count"] = attachment_count
            result["evidence_reviewed"] = result["evidence_submitted"] and result["status"] in {"Partially Supported", "Verified Findings"}
            result["evidence_summary"] = "Evidence submitted; basic format and consistency checks only. Authenticity and claim support require human review." if result["evidence_submitted"] else "No supporting file has been submitted."
            result["description"] = safe_description(result.get("details", ""))
            if not is_admin and not is_owner:
                for key in ("details", "amount", "reference", "links", "evidence_name", "evidence_path", "evidence", "email", "user_id", "guest_token_hash", "moderation_note", "moderated_by", "moderated_at", "evidence_analysis", "ai_analysis", "ai_consent", "followups", "disputes"):
                    result.pop(key, None)
                result["details"] = result.pop("description")
            else:
                for key in ("user_id", "guest_token_hash", "evidence_path", "evidence", "email"):
                    result.pop(key, None)
                if not is_admin:
                    result.pop("moderation_note", None)
            return self.send_json(result)
        attachment_evidence = re.fullmatch(r"/api/reports/(\d+)/evidence/attachment/(\d+)", path)
        if attachment_evidence:
            report_id, attachment_id = map(int, attachment_evidence.groups())
            user = self.current_user()
            with db() as conn:
                row = conn.execute("SELECT r.user_id,r.guest_token_hash,a.evidence_path,a.evidence_name,a.mime_type FROM reports r JOIN report_attachments a ON a.report_id=r.id WHERE r.id=? AND a.id=?", (report_id, attachment_id)).fetchone()
            guest_access = row and row["user_id"] is None and row["guest_token_hash"] in self.guest_token_hashes()
            if not row or not (guest_access or (user and (user["role"] == "admin" or row["user_id"] == user["id"]))):
                return self.send_json({"error": "Evidence not found."}, 404)
            file_path = (UPLOAD_DIR / row["evidence_path"]).resolve()
            if not row["evidence_path"] or not file_path.is_relative_to(UPLOAD_DIR.resolve()) or not file_path.is_file():
                return self.send_json({"error": "Evidence not found."}, 404)
            data = file_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", row["mime_type"])
            self.send_header("Content-Disposition", "attachment; filename=\"evidence\"; filename*=UTF-8''" + urllib.parse.quote(row["evidence_name"]))
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            return self.wfile.write(data)
        followup_evidence = re.fullmatch(r"/api/reports/(\d+)/evidence/followup/(\d+)", path)
        if followup_evidence:
            report_id, followup_id = map(int, followup_evidence.groups())
            user = self.current_user()
            with db() as conn:
                row = conn.execute("SELECT r.user_id,r.guest_token_hash,f.evidence_path,f.evidence_name FROM reports r JOIN report_followups f ON f.report_id=r.id WHERE r.id=? AND f.id=?", (report_id, followup_id)).fetchone()
            guest_access = row and row["user_id"] is None and row["guest_token_hash"] in self.guest_token_hashes()
            if not row or not (guest_access or (user and (user["role"] == "admin" or row["user_id"] == user["id"]))):
                return self.send_json({"error": "Evidence not found."}, 404)
            file_path = (UPLOAD_DIR / row["evidence_path"]).resolve()
            if not row["evidence_path"] or not file_path.is_relative_to(UPLOAD_DIR.resolve()) or not file_path.is_file():
                return self.send_json({"error": "Evidence not found."}, 404)
            data = file_path.read_bytes()
            mime = next((kind for kind, ext in UPLOAD_MIMES.items() if file_path.suffix == ext), "application/octet-stream")
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Disposition", "attachment; filename=\"evidence\"; filename*=UTF-8''" + urllib.parse.quote(row["evidence_name"]))
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            return self.wfile.write(data)
        if path.startswith("/api/reports/") and path.endswith("/evidence"):
            try:
                report_id = int(path.split("/")[3])
            except (ValueError, IndexError):
                return self.send_json({"error": "Report not found."}, 404)
            user = self.current_user()
            with db() as conn:
                row = conn.execute("SELECT evidence_path,evidence_name,user_id,guest_token_hash FROM reports WHERE id=?", (report_id,)).fetchone()
            guest_access = row and row["user_id"] is None and row["guest_token_hash"] in self.guest_token_hashes()
            if not user and not guest_access:
                return self.send_json({"error": "Evidence not found."}, 404)
            if not row or ((not user or user["role"] != "admin") and (not user or row["user_id"] != user["id"]) and not guest_access):
                return self.send_json({"error": "Evidence not found."}, 404)
            path_on_disk = (UPLOAD_DIR / row["evidence_path"]).resolve()
            if not row["evidence_path"] or not path_on_disk.is_relative_to(UPLOAD_DIR.resolve()) or not path_on_disk.is_file():
                return self.send_json({"error": "Evidence not found."}, 404)
            data = path_on_disk.read_bytes()
            mime = next((kind for kind, ext in UPLOAD_MIMES.items() if path_on_disk.suffix == ext), "application/octet-stream")
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Disposition", "attachment; filename=\"evidence\"; filename*=UTF-8''" + urllib.parse.quote(row["evidence_name"]))
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            return self.wfile.write(data)
        if path == "/api/health":
            return self.send_json({"ok": True})
        relative = "index.html" if path == "/" else path.lstrip("/")
        target = (ROOT / "web" / relative).resolve()
        if not target.is_relative_to(ROOT / "web") or not target.is_file():
            self.send_error(404)
            return
        content_type = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml"}.get(target.suffix, "application/octet-stream")
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        try:
            payload = self.read_json()
            if self.handle_admin_post(path, payload):
                return
            report_ai = re.fullmatch(r"/api/reports/(\d+)/ai-analysis", path)
            if report_ai:
                if not self.rate_limit("ai_report", 5):
                    return
                report_id = int(report_ai.group(1))
                user = self.current_user()
                guest_hashes = self.guest_token_hashes()
                with db() as conn:
                    row = conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
                    if not row or not (actor_owns_report(row, user, guest_hashes) or (user and user["role"] == "admin")):
                        return self.send_json({"error": "Report not found."}, 404)
                    owner = actor_owns_report(row, user, guest_hashes)
                    if owner and payload.get("consent") is not True:
                        return self.send_json({"error": "Explicit consent is required before report text or extracted evidence is sent to the configured AI provider."}, 400)
                    if not owner and not row["ai_consent"]:
                        return self.send_json({"error": "The reporter has not consented to AI processing of private evidence."}, 403)
                    report = {key: row[key] for key in ("id", "url", "category", "details", "business", "incident_date", "domain", "links")}
                    report["evidence_checks"] = json.loads(row["evidence_analysis"] or "{}").get("checks", [])
                    candidates = [dict(item) for item in conn.execute("SELECT id,url,category,business,details,incident_date FROM reports WHERE id<>? ORDER BY id DESC LIMIT 300", (report_id,))]
                    followup_rows = conn.execute("SELECT details FROM report_followups WHERE report_id=? ORDER BY id", (report_id,)).fetchall()
                if followup_rows:
                    report["details"] = (report["details"] + "\nAdditional reporter updates: " + "\n".join(item["details"] for item in followup_rows))[:8_000]
                files = collect_report_evidence(report_id, row)
                intelligence = analyze_report_intelligence(report, files, candidates, consent=True)
                with db() as conn:
                    persist_ai_results(conn, "report", report_id, intelligence, user_consented=True)
                    conn.execute("UPDATE reports SET ai_analysis=?,ai_consent=1 WHERE id=?", (json.dumps(intelligence), report_id))
                return self.send_json({"ok": True, "ai_analysis": intelligence, "report_status_unchanged": True})
            if path == "/api/admin/ai/feedback":
                user = self.require_user("admin")
                if not user:
                    return
                try:
                    run_id = int(payload.get("run_id", 0))
                except (ValueError, TypeError):
                    run_id = 0
                finding_key = str(payload.get("finding_key", ""))[:100]
                decision = str(payload.get("decision", ""))
                note = str(payload.get("note", "")).strip()[:1000]
                if not run_id or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", finding_key) or decision not in {"accepted", "rejected"}:
                    return self.send_json({"error": "Choose a valid AI analysis finding and accept/reject decision."}, 400)
                with db() as conn:
                    run = conn.execute("SELECT id,resource_type,analysis_type,result_json FROM ai_runs WHERE id=?", (run_id,)).fetchone()
                    if not run or run["resource_type"] != "report":
                        return self.send_json({"error": "AI analysis not found."}, 404)
                    finding_match = re.fullmatch(r"risk_indicators:(\d+)", finding_key)
                    try:
                        run_result = json.loads(run["result_json"] or "{}")
                    except json.JSONDecodeError:
                        run_result = {}
                    if run["analysis_type"] != "complaint_intelligence" or not finding_match or int(finding_match.group(1)) >= len(run_result.get("risk_indicators", [])):
                        return self.send_json({"error": "That finding is not part of this complaint analysis."}, 400)
                    cursor = conn.execute("INSERT INTO ai_feedback(run_id,moderator_id,finding_key,decision,note,created_at) VALUES(?,?,?,?,?,?)", (run_id, user["id"], finding_key, decision, note, now()))
                    audit_admin_action(conn, user["id"], "ai.finding_feedback", "ai_run", run_id, new={"finding_key": finding_key, "decision": decision, "feedback_id": cursor.lastrowid})
                return self.send_json({"ok": True, "feedback_id": cursor.lastrowid})
            report_outcome = re.fullmatch(r"/api/admin/reports/(\d+)/ai-outcome", path)
            if report_outcome:
                user = self.require_user("admin")
                if not user:
                    return
                report_id = int(report_outcome.group(1))
                label = str(payload.get("label", "")).strip().lower()
                partition = str(payload.get("partition", "unassigned"))
                review_note = str(payload.get("note", "")).strip()[:1000]
                labels = {"confirmed malicious activity", "supported complaint", "insufficient evidence", "inaccurate complaint", "legitimate business", "disputed", "unresolved"}
                if label not in labels or partition not in {"training", "evaluation", "unassigned"} or len(review_note) < 12:
                    return self.send_json({"error": "Choose a supported human outcome label, dataset partition, and add a review note of at least 12 characters."}, 400)
                if label in {"insufficient evidence", "disputed", "unresolved"} and partition != "unassigned":
                    return self.send_json({"error": "Disputed, unresolved, or insufficient-evidence outcomes must remain outside training and evaluation sets."}, 400)
                with db() as conn:
                    report = conn.execute("SELECT category FROM reports WHERE id=?", (report_id,)).fetchone()
                    if not report:
                        return self.send_json({"error": "Report not found."}, 404)
                    prior = conn.execute("SELECT DISTINCT partition_name FROM ai_training_labels WHERE report_id=? AND partition_name<>'unassigned'", (report_id,)).fetchall()
                    if partition != "unassigned" and any(item["partition_name"] != partition for item in prior):
                        return self.send_json({"error": "A report cannot appear in both training and evaluation partitions."}, 409)
                    latest = conn.execute("SELECT id FROM ai_runs WHERE resource_type='report' AND resource_id=? AND analysis_type='complaint_intelligence' AND status='available' ORDER BY id DESC LIMIT 1", (report_id,)).fetchone()
                    cursor = conn.execute("INSERT INTO ai_training_labels(report_id,run_id,moderator_id,category,label,review_note,partition_name,created_at) VALUES(?,?,?,?,?,?,?,?)", (report_id, latest["id"] if latest else None, user["id"], report["category"], label, review_note, partition, now()))
                    audit_admin_action(conn, user["id"], "ai.human_outcome_recorded", "report", report_id, new={"label_id": cursor.lastrowid, "label": label, "partition": partition, "run_id": latest["id"] if latest else None})
                return self.send_json({"ok": True, "label_id": cursor.lastrowid, "partition": partition})
            notify_read = re.fullmatch(r"/api/notifications/(\d+)/read", path)
            if notify_read:
                user = self.current_user()
                guest_hashes = self.guest_token_hashes()
                notification_id = int(notify_read.group(1))
                with db() as conn:
                    if user:
                        if guest_hashes:
                            slots = ",".join("?" for _ in guest_hashes)
                            cursor = conn.execute(f"UPDATE notifications SET is_read=1 WHERE id=? AND (user_id=? OR guest_token_hash IN ({slots}))", (notification_id, user["id"], *guest_hashes))
                        else:
                            cursor = conn.execute("UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?", (notification_id, user["id"]))
                    elif guest_hashes:
                        slots = ",".join("?" for _ in guest_hashes)
                        cursor = conn.execute(f"UPDATE notifications SET is_read=1 WHERE id=? AND guest_token_hash IN ({slots})", (notification_id, *guest_hashes))
                    else:
                        cursor = None
                if not cursor or not cursor.rowcount:
                    return self.send_json({"error": "Notification not found."}, 404)
                return self.send_json({"ok": True})
            action_match = re.fullmatch(r"/api/reports/(\d+)/actions", path)
            if action_match:
                report_id = int(action_match.group(1))
                user = self.current_user()
                guest_hashes = self.guest_token_hashes()
                with db() as conn:
                    row = conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
                    if not row or not actor_owns_report(row, user, guest_hashes):
                        return self.send_json({"error": "Report not found."}, 404)
                    guidance = guidance_for(row["category"])
                    action_id = str(payload.get("action_id", ""))
                    if action_id not in {item["id"] for item in guidance["steps"]}:
                        return self.send_json({"error": "Choose a guidance step for this report."}, 400)
                    actor_user = user["id"] if user else None
                    actor_guest = row["guest_token_hash"] if not user else ""
                    conn.execute("DELETE FROM report_guidance_actions WHERE report_id=? AND action_id=? AND user_id IS ? AND guest_token_hash=?", (report_id, action_id, actor_user, actor_guest))
                    conn.execute("INSERT INTO report_guidance_actions(report_id,action_id,user_id,guest_token_hash,completed,updated_at) VALUES(?,?,?,?,?,?)", (report_id, action_id, actor_user, actor_guest, 1 if payload.get("completed") else 0, now()))
                return self.send_json({"ok": True, "action_id": action_id, "completed": bool(payload.get("completed"))})
            followup_match = re.fullmatch(r"/api/reports/(\d+)/followups", path)
            if followup_match:
                if not self.rate_limit("followup", 10): return
                report_id = int(followup_match.group(1))
                user = self.current_user()
                guest_hashes = self.guest_token_hashes()
                details = str(payload.get("details", "")).strip()[:4000]
                if len(details) < 8:
                    return self.send_json({"error": "Add at least a few details for the review team."}, 400)
                uploaded = stored_upload(payload.get("evidence_file"))
                with db() as conn:
                    row = conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
                    if not row or not actor_owns_report(row, user, guest_hashes):
                        return self.send_json({"error": "Report not found."}, 404)
                    if row["status"] != "More Information Required":
                        return self.send_json({"error": "This report is not currently waiting for more information."}, 409)
                    evidence_path = uploaded["path"] if uploaded else ""
                    cursor = conn.execute("INSERT INTO report_followups(report_id,user_id,guest_token_hash,details,evidence_name,evidence_path,created_at) VALUES(?,?,?,?,?,?,?)", (report_id, user["id"] if user else None, row["guest_token_hash"] if not user else "", details, uploaded["name"] if uploaded else "", evidence_path, now()))
                    if uploaded:
                        (UPLOAD_DIR / evidence_path).write_bytes(uploaded["content"])
                        conn.execute("INSERT INTO evidence_hashes(report_id,sha256,evidence_name,created_at) VALUES(?,?,?,?)", (report_id, uploaded["sha256"], uploaded["name"], now()))
                        current = json.loads(row["evidence_analysis"] or "{}")
                        hashes = {item[0] for item in conn.execute("SELECT sha256 FROM evidence_hashes WHERE report_id<>?", (report_id,))}
                        fresh = analyze_evidence({"url": row["url"], "category": row["category"], "details": details, "incident_date": row["incident_date"], "links": row["links"], "created_at": now()}, [uploaded], [], hashes)
                        current["checks"] = (current.get("checks", []) + fresh["checks"])
                        current["assessment"] = fresh["assessment"]
                        conn.execute("UPDATE reports SET evidence_analysis=? WHERE id=?", (json.dumps(current), report_id))
                    conn.execute("INSERT INTO moderation_events(report_id,moderator_id,old_status,new_status,note,created_at) VALUES(?,?,?,?,?,?)", (report_id, None, row["status"], row["status"], "Reporter supplied additional information.", now()))
                return self.send_json({"ok": True, "id": cursor.lastrowid, "message": "Your update was added to the report."}, 201)
            flag_match = re.fullmatch(r"/api/reports/(\d+)/(flags|disputes)", path)
            if flag_match:
                if not self.rate_limit("report_feedback", 10): return
                report_id = int(flag_match.group(1))
                flag_type = "dispute" if flag_match.group(2) == "disputes" else "inaccuracy"
                reason = str(payload.get("reason", "")).strip()[:2000]
                contact = str(payload.get("contact", "")).strip()[:160]
                if len(reason) < 12:
                    return self.send_json({"error": "Please explain the concern in at least 12 characters."}, 400)
                with db() as conn:
                    row = conn.execute("SELECT id,status FROM reports WHERE id=?", (report_id,)).fetchone()
                    if not row or row["status"] not in PUBLIC_STATUSES:
                        return self.send_json({"error": "Report not found."}, 404)
                    existing = conn.execute("SELECT id FROM report_flags WHERE report_id=? AND type=? AND lower(reason)=lower(?) AND status='Pending review'", (report_id, flag_type, reason)).fetchone()
                    if existing:
                        return self.send_json({"error": "A matching review request is already pending."}, 409)
                    cursor = conn.execute("INSERT INTO report_flags(report_id,user_id,type,reason,contact,created_at) VALUES(?,?,?,?,?,?)", (report_id, (self.current_user() or {}).get("id"), flag_type, reason, contact, now()))
                return self.send_json({"ok": True, "id": cursor.lastrowid, "message": "Your request was sent to the review team."}, 201)
            if path == "/api/scan":
                if not self.rate_limit("scan", 20):
                    return
                user = self.current_user()
                return self.send_json(scan_site(payload.get("url", ""), user["id"] if user else None))
            if path == "/api/reports":
                if not self.rate_limit("report", 5):
                    return
                url = normalize_url(payload.get("url", ""))
                category = str(payload.get("category", ""))[:80].strip()
                details = str(payload.get("details", ""))[:4000].strip()
                if category not in {
                    "Payment taken, but product or service not delivered.",
                    "Fake product or misleading advertisement.",
                    "Payment fraud or suspicious transaction.",
                    "Unauthorized financial transaction.",
                    "Website impersonating a trusted brand.",
                    "Fake customer support or contact details.",
                    "Refund or cancellation problem.",
                    "Phishing or suspicious links.",
                    "Account or personal information misuse.",
                    "Account compromise.",
                    "Something else.",
                    # Retain compatibility with reports created by earlier clients.
                    "Suspicious payment request", "Fake or impersonating store",
                    "Missing or misleading policy", "Non-delivery after payment", "Other concern",
                }:
                    return self.send_json({"error": "Choose a report category."}, 400)
                if len(details) < 12:
                    return self.send_json({"error": "Please describe what happened (at least 12 characters)."}, 400)
                if not payload.get("agree"):
                    return self.send_json({"error": "Please confirm the community report notice."}, 400)
                ai_consent = payload.get("ai_consent") is True
                incident_date = str(payload.get("incident_date", ""))[:10]
                try: timezone_offset_minutes = int(payload.get("timezone_offset_minutes", 0))
                except (ValueError, TypeError): timezone_offset_minutes = 0
                if not -840 <= timezone_offset_minutes <= 840:
                    timezone_offset_minutes = 0
                if incident_date:
                    try: parsed_incident_date = datetime.strptime(incident_date, "%Y-%m-%d").date()
                    except ValueError: parsed_incident_date = None
                    local_today = (datetime.now(timezone.utc) - timedelta(minutes=timezone_offset_minutes)).date()
                    if not parsed_incident_date or parsed_incident_date > local_today:
                        return self.send_json({"error": "Enter a valid incident date that is not in the future."}, 400)
                related = str(payload.get("links", ""))[:1000].strip()
                if related:
                    for candidate in related.splitlines()[:5]:
                        if candidate.strip():
                            normalize_url(candidate.strip())
                user = self.current_user()
                guest_token = "" if user else secrets.token_urlsafe(32)
                upload_payloads = payload.get("evidence_files")
                if upload_payloads is None:
                    upload_payloads = [payload.get("evidence_file")] if payload.get("evidence_file") else []
                if not isinstance(upload_payloads, list) or len(upload_payloads) > 3:
                    return self.send_json({"error": "Attach up to 3 files."}, 400)
                uploaded_files = [stored_upload(item) for item in upload_payloads]
                uploaded = uploaded_files[0] if uploaded_files else None
                evidence_name = uploaded["name"] if uploaded else ""
                evidence_path = uploaded["path"] if uploaded else ""
                created_at = now()
                candidate = {"url": url, "category": category, "details": details, "incident_date": incident_date,
                             "links": related, "created_at": created_at,
                             "timezone_offset_minutes": timezone_offset_minutes}
                with db() as conn:
                    duplicate = conn.execute("SELECT id FROM reports WHERE lower(url)=lower(?) AND lower(category)=lower(?) AND lower(details)=lower(?) LIMIT 1", (url, category, details)).fetchone()
                    if duplicate:
                        return self.send_json({"error": "A matching report is already on file. Add new information by contacting the review team."}, 409)
                    domain = report_domain(url)
                    pattern_candidates = [dict(item) for item in conn.execute("SELECT id,details,category,url,incident_date,business FROM reports ORDER BY id DESC LIMIT 300")]
                    related_reports = [item for item in pattern_candidates if item["category"] == category and report_domain(item["url"]) == domain]
                    duplicate_hashes = {item[0] for item in conn.execute("SELECT sha256 FROM evidence_hashes")}
                    analysis = analyze_evidence(candidate, uploaded_files, related_reports, duplicate_hashes)
                candidate.update({"domain": domain, "business": str(payload.get("business", ""))[:120].strip(),
                                 "amount": str(payload.get("amount", ""))[:60].strip()})
                # External inference stays outside the SQLite transaction so provider latency does not hold database locks.
                ai_intelligence = analyze_report_intelligence(candidate, uploaded_files, pattern_candidates, consent=ai_consent)
                with db() as conn:
                    duplicate = conn.execute("SELECT id FROM reports WHERE lower(url)=lower(?) AND lower(category)=lower(?) AND lower(details)=lower(?) LIMIT 1", (url, category, details)).fetchone()
                    if duplicate:
                        return self.send_json({"error": "A matching report is already on file. Add new information by contacting the review team."}, 409)
                    cur = conn.execute("INSERT INTO reports(url,category,details,evidence,created_at,business,incident_date,amount,reference,links,status,user_id,evidence_name,evidence_path,guest_token_hash,evidence_analysis,domain,public_summary,ai_analysis,ai_consent) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (url, category, details, "", created_at, str(payload.get("business", ""))[:120].strip(), incident_date, str(payload.get("amount", ""))[:60].strip(), str(payload.get("reference", ""))[:120].strip(), related, "Submitted", user["id"] if user else None, evidence_name, evidence_path, token_digest(guest_token) if guest_token else "", json.dumps(analysis), domain, safe_description(details)[:240], json.dumps(ai_intelligence), int(ai_consent)))
                    report_id = cur.lastrowid
                    persist_ai_results(conn, "report", report_id, ai_intelligence, user_consented=ai_consent)
                    conn.execute("UPDATE reports SET ai_analysis=? WHERE id=?", (json.dumps(ai_intelligence), report_id))
                    for index, item in enumerate(uploaded_files):
                        (UPLOAD_DIR / item["path"]).write_bytes(item["content"])
                        if index > 0:
                            conn.execute("INSERT INTO report_attachments(report_id,evidence_name,evidence_path,mime_type,sha256,size_bytes,created_at) VALUES(?,?,?,?,?,?,?)", (report_id, item["name"], item["path"], item["mime_type"], item["sha256"], item["size_bytes"], created_at))
                        conn.execute("INSERT INTO evidence_hashes(report_id,sha256,evidence_name,created_at) VALUES(?,?,?,?)", (report_id, item["sha256"], item["name"], created_at))
                    saved = conn.execute("SELECT id,user_id,guest_token_hash FROM reports WHERE id=?", (report_id,)).fetchone()
                    notify_report_owner(conn, saved, "submitted", "Report submitted", "Your report is saved as Submitted and has not been treated as verified.")
                response = {"id": report_id, "reference_code": f"TSH-{report_id:06d}", "message": "Your report was saved for review.", "created_at": created_at, "guidance": guidance_for(category), "evidence_analysis": analysis, "ai_analysis": ai_intelligence}
                if guest_token:
                    response["guest_token"] = guest_token
                return self.send_json(response, 201)
            if path == "/api/auth/register":
                if not self.rate_limit("register", 5):
                    return
                name = str(payload.get("name", "")).strip()[:100]
                email = str(payload.get("email", "")).strip().lower()[:254]
                password = str(payload.get("password", ""))
                if len(name) < 1 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
                    return self.send_json({"error": "Enter your name and a valid email address."}, 400)
                if len(password) < 10 or len(password) > 128:
                    return self.send_json({"error": "Use a password between 10 and 128 characters."}, 400)
                admin_email = os.environ.get("TRUSTSHIELD_ADMIN_EMAIL", "").strip().lower()
                admin_token = os.environ.get("TRUSTSHIELD_ADMIN_BOOTSTRAP_TOKEN", "")
                provided_token = str(payload.get("admin_token", ""))
                is_admin = admin_email and admin_token and hmac.compare_digest(email, admin_email) and hmac.compare_digest(provided_token, admin_token)
                role = "admin" if is_admin else "user"
                try:
                    with db() as conn:
                        cur = conn.execute("INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)", (name, email, password_hash(password), role, now()))
                        user_id = cur.lastrowid
                except sqlite3.IntegrityError:
                    return self.send_json({"error": "An account with that email already exists."}, 409)
                token = self.set_session(user_id)
                self.send_response(201)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Set-Cookie", self.session_cookie(token))
                body = json.dumps({"id": user_id, "name": name, "email": email, "role": role}).encode()
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                return self.wfile.write(body)
            if path == "/api/auth/login":
                if not self.rate_limit("login", 10):
                    return
                email = str(payload.get("email", "")).strip().lower()[:254]
                password = str(payload.get("password", ""))
                with db() as conn:
                    row = conn.execute("SELECT id,name,email,role,status,password_hash FROM users WHERE email=? COLLATE NOCASE", (email,)).fetchone()
                if not row or row["status"] != "active" or not verify_password(password, row["password_hash"]):
                    return self.send_json({"error": "Email or password is incorrect."}, 401)
                token = self.set_session(row["id"])
                body = json.dumps({key: row[key] for key in ("id", "name", "email", "role")}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Set-Cookie", self.session_cookie(token))
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                return self.wfile.write(body)
            if path == "/api/auth/logout":
                token = next((part.strip().split("=", 1)[1] for part in self.headers.get("Cookie", "").split(";") if part.strip().startswith("trustshield_session=")), "")
                if token:
                    with db() as conn:
                        conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_digest(token),))
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Set-Cookie", self.session_cookie("", 0))
                body = b'{"ok":true}'
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                return self.wfile.write(body)
            return self.send_json({"error": "Not found."}, 404)
        except (ValueError, json.JSONDecodeError) as exc:
            return self.send_json({"error": str(exc)}, 400)
        except Exception as exc:
            return self.send_json({"error": f"The request could not be completed: {str(exc)[:160]}"}, 500)

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {self.address_string()} {fmt % args}")

    def do_PATCH(self):
        path = urllib.parse.urlsplit(self.path).path
        new_admin_route = (path == "/api/admin/scanner/settings" or
                           re.fullmatch(r"/api/admin/users/\d+/(?:status|role)", path) or
                           re.fullmatch(r"/api/admin/reports/\d+", path) or
                           re.fullmatch(r"/api/admin/threats/\d+/status", path) or
                           re.fullmatch(r"/api/admin/incidents/\d+", path))
        if new_admin_route:
            try:
                if self.handle_admin_patch(path, self.read_json()):
                    return
                return self.send_json({"error": "Not found."}, 404)
            except (ValueError, json.JSONDecodeError) as exc:
                return self.send_json({"error": str(exc)}, 400)
        flag_match = re.fullmatch(r"/api/admin/reports/(\d+)/flags/(\d+)", path)
        status_match = re.fullmatch(r"/api/admin/reports/(\d+)/status", path)
        if not status_match and not flag_match:
            return self.send_json({"error": "Not found."}, 404)
        user = self.require_user("admin")
        if not user:
            return
        try:
            payload = self.read_json()
            if flag_match:
                report_id, flag_id = map(int, flag_match.groups())
                resolution = str(payload.get("status", ""))
                reason = str(payload.get("reason", "")).strip()[:1000]
                if resolution not in {"Actioned", "No change", "Needs follow-up"} or len(reason) < 10:
                    return self.send_json({"error": "Choose a resolution and add a reason of at least 10 characters."}, 400)
                with db() as conn:
                    flag = conn.execute("SELECT type FROM report_flags WHERE id=? AND report_id=?", (flag_id, report_id)).fetchone()
                    report = conn.execute("SELECT status FROM reports WHERE id=?", (report_id,)).fetchone()
                    if not flag or not report:
                        return self.send_json({"error": "Review request not found."}, 404)
                    conn.execute("UPDATE report_flags SET status=?,reviewed_by=?,reviewed_at=?,review_note=? WHERE id=?", (resolution, user["id"], now(), reason, flag_id))
                    conn.execute("INSERT INTO moderation_events(report_id,moderator_id,old_status,new_status,note,created_at) VALUES(?,?,?,?,?,?)", (report_id, user["id"], report["status"], report["status"], f"{flag['type']} review: {resolution}. {reason}", now()))
                    audit_admin_action(conn, user["id"], "report.flag_reviewed", "report", report_id, previous={"flag_id": flag_id}, new={"status": resolution, "reason": reason})
                return self.send_json({"ok": True, "status": resolution})
            report_id = int(status_match.group(1))
            status = str(payload.get("status", ""))
            status = {"Evidence Requested": "More Information Required", "Partially Verified": "Partially Supported", "Verified": "Verified Findings"}.get(status, status)
            note = str(payload.get("note", "")).strip()[:1000]
            public_message = safe_description(str(payload.get("public_message", "")).strip())[:1000]
            if status not in REPORT_STATUSES or len(note) < 10:
                return self.send_json({"error": "Choose a supported status and record a reason of at least 10 characters."}, 400)
            if status == "More Information Required" and len(public_message) < 8:
                return self.send_json({"error": "Add a clear message describing what information is needed."}, 400)
            with db() as conn:
                previous = conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
                if not previous:
                    return self.send_json({"error": "Report not found."}, 404)
                if status not in STATUS_TRANSITIONS.get(previous["status"], set()):
                    return self.send_json({"error": f"This report cannot move from {previous['status']} to {status}."}, 409)
                update_text = public_message if status == "More Information Required" else ""
                conn.execute("UPDATE reports SET status=?,moderated_by=?,moderated_at=?,moderation_note=?,public_update=? WHERE id=?", (status, user["id"], now(), note, update_text, report_id))
                conn.execute("INSERT INTO moderation_events(report_id,moderator_id,old_status,new_status,note,created_at) VALUES(?,?,?,?,?,?)", (report_id, user["id"], previous["status"], status, note, now()))
                audit_admin_action(conn, user["id"], "report.status_changed", "report", report_id, previous={"status": previous["status"]}, new={"status": status}, metadata={"moderation_note_recorded": True})
                notify_report_owner(conn, previous, "status_changed", f"Report status: {status}", update_text or f"Your report status changed to {status}. Review the report for the latest update.")
            return self.send_json({"ok": True, "status": status, "moderated_at": now(), "public_message": update_text})
        except (ValueError, json.JSONDecodeError) as exc:
            return self.send_json({"error": str(exc)}, 400)


if __name__ == "__main__":
    init_db()
    server = ThreadingHTTPServer(("127.0.0.1", 8000), Handler)
    print("TrustShield AI running at http://127.0.0.1:8000")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        server.server_close()
