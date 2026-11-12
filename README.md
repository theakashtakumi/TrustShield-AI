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

AI is disabled unless configured. Set `TRUSTSHIELD_AI_PROVIDER=ollama` for a local Ollama endpoint, or `TRUSTSHIELD_AI_PROVIDER=gemini` with a server-side `TRUSTSHIELD_GEMINI_API_KEY`. `TRUSTSHIELD_AI_MODEL` optionally selects the model and `TRUSTSHIELD_AI_TIMEOUT` sets a bounded request timeout. Keep credentials in the backend environment; never put them in `web/`. The Ollama default model is `llama3.2:3b`; Gemini defaults to `gemini-3.5-flash-lite`, which supports structured output in Gemini's current model list. Provider outages leave deterministic scan and reporting available. See [AI architecture](AI_ARCHITECTURE.md) before enabling a hosted provider.

Evidence extraction is local and optional: install PyMuPDF for PDFs, and Pillow, `pytesseract`, plus the Tesseract executable for image OCR. Without those dependencies, the app reports that extraction is unavailable and retains the existing file checks. These optional packages are not needed for normal application startup.

## Deploy the frontend to Vercel

The repository includes `vercel.json`, which tells Vercel to publish the static site from `web/` so the deployment root serves `web/index.html` instead of returning a 404. Keep the Vercel project Root Directory at the repository root and use the `Other` framework preset; no frontend build command is needed.

This configuration serves the frontend only. The current API is the Python `server.py` process and stores application data in local SQLite and `uploads/`; Vercel's static deployment does not run that process or provide persistent local storage. Scanner, account, complaint, and community API workflows therefore need a separately hosted backend with persistent database and file storage before they will work on a Vercel deployment.

## What works

- Read-only scan of a public HTTP/HTTPS page with DNS and redirect destination checks, short timeouts, response size limits, and a restrictive outbound target policy.
- Explainable 0–100 trust score and risk tier. The score is derived from weighted visible warning signals; it is neither a probability nor a safety guarantee.
- Categorized findings for DNS, TLS/HTTPS, HTTP behavior, all six requested security headers, cookie attributes, return/contact wording, selected high-pressure phrases, and URL patterns. Each finding includes a structured status, observed evidence, source, timestamp, scanner version, and score contribution.
- Complaint guidance tailored to the incident, with checkable and persisted steps, official India cybercrime/consumer links, and clear general-information disclaimers.
- Reports have stable references, a human review timeline, structured evidence checks, likely-duplicate hints, secure attachments, owner-only follow-up submissions, and accuracy/dispute requests.
- Moderation uses distinct states: Submitted, Under Review, More Information Required, Partially Supported, Verified Findings, Inconsistencies Found, Rejected, and Disputed. Status changes require an internal reason, are audit logged, and persist owner notifications; requests for more information also include a separate public message.
- Community search filters by website, domain, business, category, and status; sorts by latest or same-domain discussion count; and uses database-backed pagination. Website scan results include database-backed report counts and review statuses.
- User dashboards show actual scan/report totals, review queues, pending guidance, report history, and unread/read notifications. Admin views include queue metrics, evidence triage, related reports, dispute/accuracy review, and CSV export for the currently filtered report page.
- Users may attach up to 3 PNG, JPG, WEBP, PDF, or TXT files at 2 MB each. Files are stored outside the public web directory and downloads are restricted to the report owner or an administrator.
- Optional AI-assisted page-content findings, separate phishing/brand similarity heuristics, and private complaint assistance. AI observations do not affect deterministic trust scoring or report status.
- Local text extraction for TXT, optional PDF extraction and image OCR, consent-gated analysis of extracted text, and admin-only feedback/outcome curation with evaluation metrics.

The community feed is shared by design. The dashboard's **My reports**, scan history, and notifications are owner-scoped; anonymous guest reports are available only while signed out in the browser that holds their private tokens.

## Honest limitations

Evidence triage checks file structure/readability, category hints, duplicate hashes, date consistency, submitted URL relationships, and report completeness. Optional OCR/text extraction and AI analysis can organize evidence, but do not establish authenticity or prove an allegation. External analysis is only run after explicit consent, common personal-data patterns are redacted locally, and original files are never sent. Similar-report matches are moderator leads, not independent confirmation. Community numbers include unverified reports and must not be treated as proof of wrongdoing.

The app does not call domain registration/WHOIS, threat intelligence, antivirus, payment, review, or business registries. These checks are unavailable; no external verification is fabricated. Website content checks cover only a bounded text read of the requested page and may miss content on other pages, scripts, or behind login. The scanner and complaint triage are deterministic and are not AI-powered.

Reports remain allegations unless a moderator records a scoped review finding; even then, the status is not a legal determination. Evidence stays private until the report has entered a public review state. Guest report access depends on the browser’s locally stored token. Admin bootstrap uses an environment variable and is suitable for a local MVP, not a production identity system. Use HTTPS, a production database, durable rate limiting, malware scanning, retention controls, backups, and an operational moderation policy before public deployment.

## Project guides

- [Architecture](ARCHITECTURE.md)
- [API documentation](API_DOCUMENTATION.md)
- [AI architecture](AI_ARCHITECTURE.md)
- [Project status](PROJECT_STATUS.md)
- [Roadmap](PROJECT_ROADMAP.md)
- [Tests](tests/)

Run the backend unit tests with `python -m unittest discover -s tests -v`.
