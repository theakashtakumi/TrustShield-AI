"""TrustShield AI: evidence-based website checks and community reports."""

from __future__ import annotations

import html
import ipaddress
import json
import re
import socket
import sqlite3
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "trustshield.db"
MAX_BODY = 1_500_000
TIMEOUT = 9


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL,
                domain TEXT NOT NULL, score INTEGER NOT NULL, label TEXT NOT NULL,
                summary TEXT NOT NULL, checks TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL,
                category TEXT NOT NULL, details TEXT NOT NULL, evidence TEXT NOT NULL,
                email TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
            );
        """)


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.links = []
        self.title = False
        self.title_text = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "title":
            self.title = True
        if tag == "a" and attrs.get("href"):
            self.links.append((attrs["href"], attrs.get("aria-label", "")))

    def handle_endtag(self, tag):
        if tag == "title":
            self.title = False

    def handle_data(self, data):
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


def scan_site(raw):
    url = normalize_url(raw)
    initial = urllib.parse.urlsplit(url)
    domain = initial.hostname.encode("idna").decode("ascii").lower()
    checks = []
    points = 0

    def add(name, status, detail, impact=0, source="Website response"):
        nonlocal points
        points += impact
        checks.append({"name": name, "status": status, "detail": detail, "source": source, "impact": impact})

    if initial.scheme == "https":
        add("Encrypted connection", "positive", "The submitted address uses HTTPS. The connection certificate is checked during retrieval.")
    else:
        add("Encrypted connection", "warning", "The submitted address uses HTTP, so this connection is not encrypted.", 24)

    request = urllib.request.Request(url, headers={"User-Agent": "TrustShield-Research/1.0 (+website safety scan)", "Accept": "text/html,application/xhtml+xml"})
    status_code = None
    headers = {}
    body = b""
    final_url = url
    fetch_error = None
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT, context=ssl.create_default_context()) as response:
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
        add("Page retrieval", "unknown", f"The page could not be read: {fetch_error}. Content checks are unavailable.", source="Live scan")
        text = ""
        links = []
        title = ""
    else:
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

    score = min(100, points)
    if score >= 35:
        label, summary = "Elevated risk signals", "Several observable warning signs merit caution before you share payment or personal details."
    elif score >= 16:
        label, summary = "Some caution signals", "A few technical signals need context. Verify the seller and policies before making a purchase."
    elif fetch_error:
        label, summary = "Limited evidence", "We could not retrieve enough information to assess this site. A low signal count is not an endorsement."
    else:
        label, summary = "Limited concerns found", "The checks found few selected warning signs. This is not a guarantee that the seller is legitimate."
    with db() as conn:
        cur = conn.execute("INSERT INTO scans(url,domain,score,label,summary,checks,created_at) VALUES(?,?,?,?,?,?,?)",
                           (url, domain, score, label, summary, json.dumps(checks), now()))
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
        self.end_headers()
        self.wfile.write(data)

    def read_json(self):
        size = int(self.headers.get("Content-Length", "0"))
        if size > 20000:
            raise ValueError("Request is too large.")
        return json.loads(self.rfile.read(size) or b"{}")

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/history":
            with db() as conn:
                scans = [dict(row) for row in conn.execute("SELECT id,url,domain,score,label,summary,created_at FROM scans ORDER BY id DESC LIMIT 20")]
                reports = [dict(row) for row in conn.execute("SELECT id,url,category,details,evidence,created_at FROM reports ORDER BY id DESC LIMIT 20")]
            return self.send_json({"scans": scans, "reports": reports})
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
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        try:
            payload = self.read_json()
            if path == "/api/scan":
                return self.send_json(scan_site(payload.get("url", "")))
            if path == "/api/reports":
                url = normalize_url(payload.get("url", ""))
                category = str(payload.get("category", ""))[:80].strip()
                details = str(payload.get("details", ""))[:4000].strip()
                evidence = str(payload.get("evidence", ""))[:2000].strip()
                email = str(payload.get("email", ""))[:254].strip()
                if category not in {"Suspicious payment request", "Fake or impersonating store", "Missing or misleading policy", "Non-delivery after payment", "Other concern"}:
                    return self.send_json({"error": "Choose a report category."}, 400)
                if len(details) < 12:
                    return self.send_json({"error": "Please describe what happened (at least 12 characters)."}, 400)
                if email and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
                    return self.send_json({"error": "Enter a valid email address or leave it blank."}, 400)
                with db() as conn:
                    cur = conn.execute("INSERT INTO reports(url,category,details,evidence,email,created_at) VALUES(?,?,?,?,?,?)", (url, category, details, evidence, email, now()))
                    report_id = cur.lastrowid
                return self.send_json({"id": report_id, "message": "Your report was saved for review.", "created_at": now()}, 201)
            return self.send_json({"error": "Not found."}, 404)
        except (ValueError, json.JSONDecodeError) as exc:
            return self.send_json({"error": str(exc)}, 400)
        except Exception as exc:
            return self.send_json({"error": f"The request could not be completed: {str(exc)[:160]}"}, 500)

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {self.address_string()} {fmt % args}")


if __name__ == "__main__":
    init_db()
    server = ThreadingHTTPServer(("127.0.0.1", 8000), Handler)
    print("TrustShield AI running at http://127.0.0.1:8000")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        server.server_close()
