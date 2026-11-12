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
- SQLite schema, API/setup/architecture/roadmap documentation, and deterministic scanner/scoring tests.

## Partial / not connected

- Domain age, business registry, real threat feeds, and malicious-domain database checks require external providers; none are simulated.
- Evidence checks are deterministic heuristics and cannot determine authenticity or prove a complaint. No OCR or AI review is configured. Similar reports are leads only and are never merged or counted as independent confirmation.
- Public reporting exposes aggregate counts for submitted claims while keeping report details and evidence private until review. Disputed reports remain visible with their status and full history.
- Rate limits are in-memory, and the platform still needs durable abuse prevention, retention controls, an operational moderator policy, and production security hardening.
- Admin user management is limited to user counts and registration role assignment.
- Authentication and rate limiting are MVP-level and need production hardening before public deployment.

## Verification performed

- `python -m unittest discover -s tests -v` — passed (21 tests), covering scanner/header/scoring rules, guidance resources, evidence triage, domain relationships, report access, upload validation, review transitions, follow-ups, notifications, community search, and disputes.
- `python -m py_compile server.py trust_engine.py security_headers.py guidance_service.py evidence_service.py community_service.py` — passed.
- `node --check web/app.js` — passed.
- A browser-based end-to-end run was not performed in this environment.
