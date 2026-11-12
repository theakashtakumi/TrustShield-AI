# Project status

Last updated: 2026-11-12

## Completed in this MVP

- Light responsive landing and scanner experience with accessible labels, loading feedback, error handling, report search/status filters, FAQs, and account/report modals.
- Live read-only public page retrieval with public-IP validation and connection pinning, per-hop redirect validation, disabled proxies, and time/size limits.
- Six value-aware security-header validators, structured PASS/WARNING/FAIL/NOT DETECTED/UNKNOWN/NOT APPLICABLE findings, versioned evidence and transparent weighted scoring.
- Three-file evidence upload with removal/replacement before submission, strict MIME/size checks, private storage, owner/admin-only downloads, and secure follow-up evidence uploads.
- Structured evidence triage for basic file readability, category relevance hints, date consistency, URL/domain relationships, duplicate file hashes, report completeness, and similar report descriptions. Authenticity and claim support remain explicitly undetermined.
- Category-specific, owner-trackable guidance with official configurable India cybercrime/consumer resources; persisted completed actions and advice disclaimers.
- Distinct report lifecycle statuses, legal transition checks, mandatory internal reasons, separate public information requests, admin-only review notes, and immutable moderation event history.
- Database-backed community search, status/category filters, most-discussed/latest sorting, pagination, per-domain status counts, related report hints, and public-safe summaries.
- User dashboards with actual scan/report counts, pending guidance, in-app notifications, owner follow-ups, accuracy flags, and dispute submissions; admin dashboards with real queue stats and flag/dispute decisions.
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
- Admin user management is limited to user counts and registration role assignment.
- Authentication and rate limiting are MVP-level and need production hardening before public deployment.

## Verification performed

- `python -m unittest discover -s tests -v` — passed (41 tests; 1 skipped because optional PyMuPDF is not installed). Coverage includes AI providers/schemas, timeout/auth/malformed responses, consent and privacy, OCR limits, report moderation/evaluation, scanner score isolation, uploads, and existing workflows.
- `python -m compileall -q server.py ai_services tests` — passed.
- `node --check web/app.js` and `git diff --check` — passed.
- A browser-based end-to-end run was not performed in this environment.
