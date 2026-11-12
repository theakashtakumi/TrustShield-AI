# TrustShield AI

TrustShield AI is an evidence-first website assessment and community reporting MVP. It checks a public page using deterministic rules, explains the signals it could observe, accepts structured incident reports, and provides a small human moderation workflow.

## Run locally

Prerequisite: Python 3.11 or newer. The app uses only the Python standard library and has no package install step.

1. Copy `.env.example` values into your shell environment as needed. On PowerShell:

   ```powershell
   $env:TRUSTSHIELD_ADMIN_EMAIL = "admin@example.com"
   $env:TRUSTSHIELD_ADMIN_BOOTSTRAP_TOKEN = "replace-this-with-a-long-random-token"
   $env:TRUSTSHIELD_SECURE_COOKIE = "false"
   ```

2. Start the app:

   ```powershell
   python server.py
   ```

3. Open <http://127.0.0.1:8000>.

The first account registered with `TRUSTSHIELD_ADMIN_EMAIL` and the matching `TRUSTSHIELD_ADMIN_BOOTSTRAP_TOKEN` receives the administrator role. Enter the token in the optional administrator setup field during registration, then clear the token from the environment. The app creates `trustshield.db` and an `uploads/` directory on first start. Both are local data and excluded from Git.

## What works

- Read-only scan of a public HTTP/HTTPS page with DNS and redirect destination checks, short timeouts, response size limits, and a restrictive outbound target policy.
- Explainable 0–100 trust score and risk tier. The score is derived from weighted visible warning signals; it is neither a probability nor a safety guarantee.
- Findings for TLS/HTTPS, response status, selected browser security headers, return/contact wording, selected high-pressure phrases, and a small set of URL impersonation patterns.
- User-submitted community reports, basic duplicate suppression, search and status filtering, optional evidence files, registration/login, private account history, and administrator status changes with a verification event history.
- Evidence files are limited to PNG, JPG, WEBP, PDF, or TXT and 2 MB. They are stored outside the public web directory and are available only to the report owner or an administrator.

## Honest limitations

This MVP does not call domain registration/WHOIS, threat intelligence, antivirus, payment, review, or business registries. Domain age and known malicious-domain checks are shown as unavailable by omission from this initial rule set; no external verification is fabricated. Website content checks cover only a bounded text read of the requested page and may miss content on other pages, scripts, or behind login. The current implementation is deterministic and is not AI-powered.

Reports are allegations until reviewed by a human moderator. Moderation status does not establish legal wrongdoing. Admin bootstrap uses an environment variable and is suitable for a local MVP, not a production identity system. Use HTTPS, a production database, durable rate limiting, malware scanning, backups, and an operational moderation policy before public deployment.

## Project guides

- [Architecture](ARCHITECTURE.md)
- [API documentation](API_DOCUMENTATION.md)
- [Project status](PROJECT_STATUS.md)
- [Roadmap](PROJECT_ROADMAP.md)
- [Tests](tests/)

Run the backend unit tests with `python -m unittest discover -s tests -v`.
