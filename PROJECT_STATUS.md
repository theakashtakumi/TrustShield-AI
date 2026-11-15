# Project status

Last updated: 2026-11-12

## Completed in this MVP

- Responsive public landing/scanner experience with a midnight theme, accessible labels, loading feedback, error handling, report search/status filters, FAQs, and account/report modals.
- Stitch-inspired dark administrator console with responsive navigation, live overview metrics and selectable scan-history ranges, actual system health, and recent audit/moderation activity.
- Live read-only public page retrieval with public-IP validation and connection pinning, per-hop redirect validation, disabled proxies, and time/size limits.
- Six value-aware security-header validators, structured PASS/WARNING/FAIL/NOT DETECTED/UNKNOWN/NOT APPLICABLE findings, versioned evidence and transparent weighted scoring.
- Three-file evidence upload with removal/replacement before submission, strict MIME/size checks, private storage, owner/admin-only downloads, and secure follow-up evidence uploads.
- Structured evidence triage for basic file readability, category relevance hints, date consistency, URL/domain relationships, duplicate file hashes, report completeness, and similar report descriptions. Authenticity and claim support remain explicitly undetermined.
- Category-specific, owner-trackable guidance with official configurable India cybercrime/consumer resources; persisted completed actions and advice disclaimers.
- Distinct report lifecycle statuses, legal transition checks, mandatory internal reasons, separate public information requests, admin-only review notes, and immutable moderation event history.
- Database-backed community search, status/category filters, most-discussed/latest sorting, pagination, per-domain status counts, related report hints, and public-safe summaries.
- User dashboards with actual scan/report counts, pending guidance, in-app notifications, owner follow-ups, accuracy flags, and dispute submissions; admin dashboards with real queue stats and flag/dispute decisions.
- Admin APIs and views for searchable/paginated user profiles, user/admin role changes, account suspension/reactivation, all stored scans, report assignment/priority/private notes, local threat records, incident case timelines, scanner settings, AI run provenance/evaluation, and audit search/export.
- Scanner runtime configuration backed by SQLite for bounded timeout and redirects and optional phishing/AI checks. Existing network-safety checks are fixed and remain enabled. Verified local threat matches appear separately from technical scoring.
- Additive SQLite migrations for account status, report assignment/priority, private report notes, scanner settings, verified threat records, incident/report links, incident events, and admin audit events. Existing report and scan rows remain in place.
- Additive SQLite migrations preserve existing reports and migrate legacy verification labels to the more specific lifecycle statuses.
- Salted password hashing, cookie sessions, private per-account scans/reports, token-protected admin bootstrap, admin stats, status moderation, verification history, and protected evidence retrieval.
- Optional modular AI layer: structured Gemini/Ollama adapters, bounded retrieved-page content analysis, separate phishing/brand heuristics, local TXT/PDF/image text extraction, opt-in report analysis, similar-report leads, private moderator summaries, finding feedback, human outcome curation, and evaluation metrics.
- AI results are separated from scanner scoring and verified report status. External report analysis requires explicit consent; provider requests contain redacted text rather than original evidence files; provider/model/prompt/version/usage/hash provenance is retained without raw request text.
- SQLite schema, API/setup/architecture/roadmap documentation, and deterministic scanner/scoring tests.

## Partial / not connected

- Domain age, business registry, real threat feeds, and malicious-domain database checks require external providers; none are simulated.
- OCR requires optional PyMuPDF or Pillow/pytesseract plus a Tesseract executable. Extraction and AI interpretation can be incomplete or wrong, cannot determine authenticity or prove a complaint, and remain moderator leads. Similar reports are never merged or counted as independent confirmation.
- Hosted AI providers are optional and require server-side configuration; no provider is required for the existing product workflows. Common-pattern redaction cannot guarantee that all personal information is removed, and consented report text may still contain sensitive details.
- Vercel publishes the static frontend only. The Python API, AI calls, database, and private evidence storage need a separately deployed backend and persistent storage.
- Public reporting exposes aggregate counts for submitted claims while keeping report details and evidence private until review. Disputed reports remain visible with their status and full history.
- Rate limits are in-memory, and the platform still needs durable abuse prevention, retention controls, an operational moderator policy, and production security hardening.
- Reviewer assignment currently targets active administrators; separate analyst roles and fine-grained permissions are not implemented.
- External registry and threat feeds, deployment-level rate-limit controls, malware scanning, and automatic threat verification remain unavailable.
- Vercel serves only the static frontend. Sign in, scanning, admin APIs, persistent database, and private uploads require a separately deployed Python API and persistent storage.
- Authentication and rate limiting are MVP-level and need production hardening before public deployment.

## Verification performed

- `python -m unittest discover -s tests -v` — pending final rerun (baseline 41 tests passed; new admin-operation tests cover authorization, settings, account changes, threat gating, private notes, and incidents).
- `python -m py_compile server.py tests/test_admin_operations.py` — passed.
- `node --check web/admin.js` and `node --check web/app.js` — passed.
- `git diff --check` — passed with line-ending normalization warnings only.
- Browser visual QA was attempted, but the computer-use runtime stopped because it could not verify Chrome's current URL. No admin login or browser authentication was automated; visual viewport checks remain unverified.
