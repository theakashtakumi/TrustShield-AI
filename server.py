"""TrustShield AI: evidence-based website checks and community reports."""

from __future__ import annotations

import ipaddress
import json
import base64
from contextlib import contextmanager
import hashlib
import hmac
import os
import re
import secrets
import socket
import sqlite3
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from trust_engine import classify

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "trustshield.db"
UPLOAD_DIR = ROOT / "uploads"
MAX_BODY = 1_500_000
TIMEOUT = 9
MAX_REDIRECTS = 5
RATE_BUCKETS = {}
RATE_LOCK = __import__("threading").Lock()
UPLOAD_MIMES = {"image/png": ".png", "image/jpeg": ".jpg", "image/webp": ".webp", "application/pdf": ".pdf", "text/plain": ".txt"}


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Validate each redirect before urllib makes the next network request."""
    def __init__(self):
        super().__init__()
        self.redirects = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.redirects += 1
        if self.redirects > MAX_REDIRECTS:
            raise ValueError("The website redirected too many times.")
        absolute = urllib.parse.urljoin(req.full_url, newurl)
        parts = urllib.parse.urlsplit(absolute)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
            raise ValueError("The website redirected to an invalid address.")
        safe_public_host(parts.hostname)
        return super().redirect_request(req, fp, code, msg, headers, absolute)


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
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
                user_id INTEGER REFERENCES users(id)
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
        """)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(reports)")}
        additions = {
            "business": "TEXT NOT NULL DEFAULT ''", "incident_date": "TEXT NOT NULL DEFAULT ''",
            "amount": "TEXT NOT NULL DEFAULT ''", "reference": "TEXT NOT NULL DEFAULT ''",
            "links": "TEXT NOT NULL DEFAULT ''", "status": "TEXT NOT NULL DEFAULT 'Submitted'",
            "user_id": "INTEGER REFERENCES users(id)", "evidence_name": "TEXT NOT NULL DEFAULT ''",
            "guest_token_hash": "TEXT NOT NULL DEFAULT ''",
            "evidence_path": "TEXT NOT NULL DEFAULT ''", "moderated_by": "INTEGER REFERENCES users(id)",
            "moderated_at": "TEXT NOT NULL DEFAULT ''", "moderation_note": "TEXT NOT NULL DEFAULT ''"
        }
        for name, spec in additions.items():
            if name not in columns:
                conn.execute(f"ALTER TABLE reports ADD COLUMN {name} {spec}")
        scan_columns = {row[1] for row in conn.execute("PRAGMA table_info(scans)")}
        if "user_id" not in scan_columns:
            conn.execute("ALTER TABLE scans ADD COLUMN user_id INTEGER REFERENCES users(id)")
        conn.execute("CREATE INDEX IF NOT EXISTS reports_url ON reports(url)")
        conn.execute("CREATE INDEX IF NOT EXISTS reports_created_at ON reports(created_at)")


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


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.links = []
        self.title = False
        self.title_text = []
        self.ignored_depth = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "title":
            self.title = True
        if tag in {"script", "style", "noscript", "svg"}:
            self.ignored_depth += 1
        if tag == "a" and attrs.get("href"):
            self.links.append((attrs["href"], attrs.get("aria-label", "")))

    def handle_endtag(self, tag):
        if tag == "title":
            self.title = False
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
    """Reject local/reserved targets before making an outbound request."""
    if not host or host.lower() in {"localhost", "localhost.localdomain"}:
        raise ValueError("Enter a public website address.")
    try:
        addresses = {ipaddress.ip_address(host.split("%", 1)[0])}
    except ValueError:
        try:
            addresses = {ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
        except (socket.gaierror, OSError):
            raise ValueError("The domain could not be resolved. Check the address and try again.")
    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError("This address points to a private or reserved network and cannot be scanned.")


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
    url = normalize_url(raw)
    initial = urllib.parse.urlsplit(url)
    domain = initial.hostname.encode("idna").decode("ascii").lower()
    checks = []
    points = 0

    def add(name, status, detail, impact=0, source="Website response"):
        nonlocal points
        points += impact
        checks.append({"name": name, "status": status, "detail": detail, "source": source, "impact": impact})

    request = urllib.request.Request(url, headers={"User-Agent": "TrustShield-Research/1.0 (+website safety scan)", "Accept": "text/html,application/xhtml+xml"})
    status_code = None
    headers = {}
    body = b""
    final_url = url
    fetch_error = None
    try:
        opener = urllib.request.build_opener(SafeRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        with opener.open(request, timeout=TIMEOUT) as response:
            final_url = response.geturl()
            # Validate redirect destination too; disable no safety checks on redirects.
            final_parts = urllib.parse.urlsplit(final_url)
            if final_parts.scheme not in {"http", "https"} or not final_parts.hostname:
                raise ValueError("The website redirected to an invalid address.")
            safe_public_host(final_parts.hostname)
            status_code = response.status
            headers = response.headers
            body = response.read(MAX_BODY)
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        headers = exc.headers or {}
        try:
            body = exc.read(MAX_BODY)
        except OSError:
            pass
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError, ValueError) as exc:
        fetch_error = str(getattr(exc, "reason", exc))[:180]

    if fetch_error:
        add("Encrypted connection", "unknown", "The final connection could not be established, so HTTPS and certificate validity could not be verified.", source="Live scan")
        add("Page retrieval", "unknown", f"The page could not be read: {fetch_error}. Content checks are unavailable.", source="Live scan")
        text = ""
        links = []
        title = ""
    else:
        final_parts = urllib.parse.urlsplit(final_url)
        if final_parts.scheme == "https":
            detail = "The retrieved page uses HTTPS and its certificate passed the browser-style TLS validation performed by this scan."
            if initial.scheme == "http":
                detail += " The submitted address began as HTTP before reaching this HTTPS page."
            add("Encrypted connection", "positive", detail)
        else:
            add("Encrypted connection", "warning", "The final page uses HTTP, so its connection is not encrypted.", 24)
        if final_parts.hostname.lower() != initial.hostname.lower():
            add("Redirect destination", "caution", f"The submitted domain redirected to {final_parts.hostname}. Confirm this destination is associated with the seller.", 5)
        elif final_parts.scheme != initial.scheme:
            add("Redirect behavior", "caution", f"The page changed from {initial.scheme.upper()} to {final_parts.scheme.upper()} during retrieval.", 2)
        add("Page retrieval", "positive" if status_code and status_code < 400 else "warning",
            f"The website responded with HTTP {status_code}." if status_code else "The website returned no HTTP status.",
            12 if status_code and status_code >= 400 else 0)
        parser = PageParser()
        content_type = headers.get("Content-Type", "")
        if "html" in content_type.lower() or not content_type:
            try:
                charset = headers.get_content_charset() or "utf-8"
                parser.feed(body.decode(charset, errors="replace"))
            except (LookupError, UnicodeError):
                parser.feed(body.decode("utf-8", errors="replace"))
        text = " ".join(parser.text).lower()
        links = [urllib.parse.urljoin(final_url, href).lower() + " " + label.lower() for href, label in parser.links]
        title = " ".join(parser.title_text)[:160]
        if final_parts.scheme == "https":
            missing = [h for h in ("Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options") if h not in headers]
            if missing:
                add("Security headers", "caution", f"Not observed: {', '.join(missing)}. These are defense-in-depth signals, not proof of fraud.", min(8, len(missing) * 2))
            else:
                add("Security headers", "positive", "Common browser security headers were present.")
        if any(word in domain for word in ("paypa1", "amaz0n", "app1e", "support-verify", "secure-login")):
            add("Domain wording", "warning", "The domain contains wording that can be used in impersonation attempts. Verify the business through its official channels.", 22)

        policy_terms = ("refund", "return", "money back", "cancellation")
        contact_terms = ("contact", "about us", "customer service", "support")
        policy_found = any(term in text or any(term in link for link in links) for term in policy_terms)
        contact_found = any(term in text or any(term in link for link in links) for term in contact_terms)
        if policy_found:
            add("Return and refund information", "positive", "Return or refund wording was found on the retrieved page. This does not confirm the policy is fair or honored.", source="Page text and links")
        else:
            add("Return and refund information", "unknown", "No clear return or refund wording was found in the retrieved page text and links.", source="Page text and links")
        if contact_found:
            add("Seller contact information", "positive", "Contact or support wording was found. The identity and reachability of the seller were not independently verified.", source="Page text and links")
        else:
            add("Seller contact information", "unknown", "No clear contact or support wording was found in the retrieved page text and links.", source="Page text and links")
        urgency_terms = ("act now", "limited time", "only today", "last chance", "guaranteed profit", "100% guaranteed")
        matches = [term for term in urgency_terms if term in text]
        if matches:
            add("High-pressure claims", "caution", f"The page includes promotional language: {', '.join(matches[:3])}. This is a context signal, not a fraud finding.", min(12, 4 * len(matches)), "Retrieved page text")
        else:
            add("High-pressure claims", "positive", "No selected high-pressure phrases were found in the retrieved page text.", source="Retrieved page text")

    add("Domain registration age", "unknown", "Registrar data is not connected in this MVP, so domain age could not be checked.", source="External data unavailable")
    add("Known malicious domain databases", "unknown", "No threat intelligence provider is configured, so no database match was performed.", source="External data unavailable")
    add("Business identity verification", "unknown", "The seller's legal identity and registration were not independently verified.", source="External data unavailable")

    assessment = classify(points, sufficient_data=not bool(fetch_error))
    score, label, summary = assessment["score"], assessment["label"], assessment["summary"]
    with db() as conn:
        cur = conn.execute("INSERT INTO scans(url,domain,score,label,summary,checks,created_at,user_id) VALUES(?,?,?,?,?,?,?,?)",
                           (url, domain, score, label, summary, json.dumps(checks), now(), user_id))
        scan_id = cur.lastrowid
    return {"id": scan_id, "url": url, "domain": domain, "title": title, "score": score,
            "label": label, "summary": summary, "checks": checks, "created_at": now(), "status_code": status_code}


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
        if size > 2_850_000:
            raise ValueError("Request is too large.")
        return json.loads(self.rfile.read(size) or b"{}")

    def current_user(self):
        cookie = self.headers.get("Cookie", "")
        token = next((part.strip().split("=", 1)[1] for part in cookie.split(";") if part.strip().startswith("trustshield_session=")), "")
        if not token:
            return None
        with db() as conn:
            row = conn.execute("SELECT u.id,u.name,u.email,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?", (token_digest(token), int(time.time()))).fetchone()
            return dict(row) if row else None

    def guest_token_hashes(self):
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

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/auth/me":
            user = self.current_user()
            return self.send_json(user or {"user": None}, 200 if user else 401)
        if path == "/api/history":
            user = self.current_user()
            guest_hashes = self.guest_token_hashes()
            with db() as conn:
                scans = [dict(row) for row in conn.execute("SELECT id,url,domain,score,label,summary,checks,created_at FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 20", (user["id"],))] if user else []
                reports = [dict(row) for row in conn.execute("SELECT id,url,category,details,business,incident_date,amount,evidence_name,status,created_at FROM reports WHERE status IN ('Under Review','Evidence Requested','Partially Verified','Verified','Disputed') ORDER BY id DESC LIMIT 100")]
                if user:
                    own = [dict(row) for row in conn.execute("SELECT id,url,category,business,status,created_at FROM reports WHERE user_id=? ORDER BY id DESC LIMIT 50", (user["id"],))]
                    if guest_hashes:
                        placeholders = ",".join("?" for _ in guest_hashes)
                        own.extend(dict(row) for row in conn.execute(f"SELECT id,url,category,business,status,created_at FROM reports WHERE user_id IS NULL AND guest_token_hash IN ({placeholders}) ORDER BY id DESC LIMIT 30", guest_hashes))
                elif guest_hashes:
                    placeholders = ",".join("?" for _ in guest_hashes)
                    own = [dict(row) for row in conn.execute(f"SELECT id,url,category,business,status,created_at FROM reports WHERE guest_token_hash IN ({placeholders}) ORDER BY id DESC LIMIT 30", guest_hashes)]
                else:
                    own = []
                if user and user["role"] == "admin":
                    reports = [dict(row) for row in conn.execute("SELECT id,url,category,details,business,incident_date,amount,evidence_name,status,created_at FROM reports ORDER BY id DESC LIMIT 100")]
                    stats_row = conn.execute("SELECT (SELECT COUNT(*) FROM users) AS users,(SELECT COUNT(*) FROM reports) AS reports,(SELECT COUNT(*) FROM scans) AS scans,(SELECT COUNT(*) FROM reports WHERE status IN ('Submitted','Under Review','Evidence Requested','Disputed')) AS review_queue,(SELECT COUNT(*) FROM reports WHERE status='Verified') AS verified").fetchone()
                    admin_stats = dict(stats_row)
                else:
                    admin_stats = None
            for scan in scans:
                scan["checks"] = json.loads(scan["checks"])
                scan["label"] = scan["label"]
            for report in reports:
                report["domain"] = urllib.parse.urlsplit(report["url"]).hostname or ""
                report.pop("email", None)
                report.pop("reference", None)
                report.pop("links", None)
                if not user or user["role"] != "admin":
                    report.pop("amount", None)
                    report.pop("evidence_name", None)
            return self.send_json({"scans": scans, "reports": reports, "my_reports": own, "admin_stats": admin_stats})
        if path.startswith("/api/reports/") and path.rsplit("/", 1)[-1].isdigit():
            report_id = int(path.rsplit("/", 1)[-1])
            user = self.current_user()
            with db() as conn:
                row = conn.execute("SELECT id,url,category,details,business,incident_date,amount,evidence_name,status,created_at,user_id,reference,links,guest_token_hash FROM reports WHERE id=?", (report_id,)).fetchone()
            restricted_status = row and row["status"] in {"Submitted", "Rejected"} and (not user or (user["role"] != "admin" and row["user_id"] != user["id"]))
            has_guest_access = row and row["user_id"] is None and row["guest_token_hash"] in self.guest_token_hashes()
            if restricted_status and has_guest_access:
                restricted_status = False
            private_owner_only = row and row["user_id"] and (not user or (row["user_id"] != user["id"] and user["role"] != "admin"))
            if not row or restricted_status or private_owner_only:
                return self.send_json({"error": "Report not found."}, 404)
            result = dict(row)
            result["domain"] = urllib.parse.urlsplit(result["url"]).hostname or ""
            result.pop("user_id", None)
            result.pop("guest_token_hash", None)
            if not user or user["role"] != "admin":
                result.pop("reference", None)
                result.pop("links", None)
                if not user or row["user_id"] != user["id"]:
                    result.pop("amount", None)
                    result.pop("evidence_name", None)
            with db() as conn:
                history = conn.execute("SELECT old_status,new_status,note,created_at FROM moderation_events WHERE report_id=? ORDER BY id", (report_id,)).fetchall()
            result["verification_history"] = [dict(item) for item in history]
            return self.send_json(result)
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
                if category not in {"Suspicious payment request", "Fake or impersonating store", "Missing or misleading policy", "Non-delivery after payment", "Other concern"}:
                    return self.send_json({"error": "Choose a report category."}, 400)
                if len(details) < 12:
                    return self.send_json({"error": "Please describe what happened (at least 12 characters)."}, 400)
                if not payload.get("agree"):
                    return self.send_json({"error": "Please confirm the community report notice."}, 400)
                incident_date = str(payload.get("incident_date", ""))[:10]
                if incident_date and (not re.fullmatch(r"\d{4}-\d{2}-\d{2}", incident_date) or incident_date > datetime.now(timezone.utc).date().isoformat()):
                    return self.send_json({"error": "Enter a valid incident date that is not in the future."}, 400)
                related = str(payload.get("links", ""))[:1000].strip()
                if related:
                    for candidate in related.splitlines()[:5]:
                        if candidate.strip():
                            normalize_url(candidate.strip())
                user = self.current_user()
                guest_token = "" if user else secrets.token_urlsafe(32)
                file = payload.get("evidence_file")
                evidence_name = ""
                evidence_path = ""
                if file:
                    mime = str(file.get("mime_type", ""))
                    encoded = str(file.get("data", ""))
                    if mime not in UPLOAD_MIMES:
                        return self.send_json({"error": "Use a PNG, JPG, WEBP, PDF or TXT attachment."}, 400)
                    try:
                        content = base64.b64decode(encoded, validate=True)
                    except (ValueError, base64.binascii.Error):
                        return self.send_json({"error": "The attachment could not be read."}, 400)
                    if not content or len(content) > 2 * 1024 * 1024:
                        return self.send_json({"error": "Choose a non-empty file smaller than 2 MB."}, 400)
                    signatures = {"image/png": b"\x89PNG\r\n\x1a\n", "image/jpeg": b"\xff\xd8\xff", "image/webp": b"RIFF", "application/pdf": b"%PDF", "text/plain": None}
                    signature = signatures[mime]
                    if signature and not content.startswith(signature):
                        return self.send_json({"error": "The attachment content does not match its file type."}, 400)
                    evidence_name = re.sub(r"[^A-Za-z0-9._ -]", "_", str(file.get("name", "evidence")))[:120]
                    evidence_path = secrets.token_hex(24) + UPLOAD_MIMES[mime]
                    (UPLOAD_DIR / evidence_path).write_bytes(content)
                with db() as conn:
                    duplicate = conn.execute("SELECT id FROM reports WHERE lower(url)=lower(?) AND lower(category)=lower(?) AND lower(details)=lower(?) LIMIT 1", (url, category, details)).fetchone()
                    if duplicate:
                        if evidence_path:
                            (UPLOAD_DIR / evidence_path).unlink(missing_ok=True)
                        return self.send_json({"error": "A matching report is already on file. Add new information by contacting the review team."}, 409)
                    cur = conn.execute("INSERT INTO reports(url,category,details,evidence,created_at,business,incident_date,amount,reference,links,status,user_id,evidence_name,evidence_path,guest_token_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (url, category, details, "", now(), str(payload.get("business", ""))[:120].strip(), incident_date, str(payload.get("amount", ""))[:60].strip(), str(payload.get("reference", ""))[:120].strip(), related, "Submitted", user["id"] if user else None, evidence_name, evidence_path, token_digest(guest_token) if guest_token else ""))
                    report_id = cur.lastrowid
                response = {"id": report_id, "message": "Your report was saved for review.", "created_at": now()}
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
                    row = conn.execute("SELECT id,name,email,role,password_hash FROM users WHERE email=? COLLATE NOCASE", (email,)).fetchone()
                if not row or not verify_password(password, row["password_hash"]):
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
        match = re.fullmatch(r"/api/admin/reports/(\d+)/status", path)
        if not match:
            return self.send_json({"error": "Not found."}, 404)
        user = self.require_user("admin")
        if not user:
            return
        try:
            payload = self.read_json()
            status = str(payload.get("status", ""))
            note = str(payload.get("note", ""))[:1000]
            if status not in {"Submitted", "Under Review", "Evidence Requested", "Partially Verified", "Verified", "Rejected", "Disputed"}:
                return self.send_json({"error": "Choose a supported verification status."}, 400)
            with db() as conn:
                previous = conn.execute("SELECT status FROM reports WHERE id=?", (int(match.group(1)),)).fetchone()
                if not previous:
                    return self.send_json({"error": "Report not found."}, 404)
                conn.execute("UPDATE reports SET status=?,moderated_by=?,moderated_at=?,moderation_note=? WHERE id=?", (status, user["id"], now(), note, int(match.group(1))))
                conn.execute("INSERT INTO moderation_events(report_id,moderator_id,old_status,new_status,note,created_at) VALUES(?,?,?,?,?,?)", (int(match.group(1)), user["id"], previous["status"], status, note, now()))
            return self.send_json({"ok": True, "status": status, "moderated_at": now()})
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
