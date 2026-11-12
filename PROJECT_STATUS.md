# Project status

Last updated: 2026-11-12

## Completed in this MVP

- Light responsive landing and scanner experience with accessible labels, loading feedback, error handling, report search/status filters, FAQs, and account/report modals.
- Live read-only public page retrieval with URL validation, DNS/redirect checks, time and size limits, and observable HTTPS/status/header/content checks.
- Explainable score, five risk classifications, persisted scan findings, next-step guidance, and no unsupported AI labels.
- Community report submission with incident/business fields, optional URL evidence and file upload, duplicate check, searchable status-labelled reports, and public/private field separation. New reports stay private until a moderator starts review; guest access uses an unguessable browser-local token.
- Salted password hashing, cookie sessions, private per-account scans/reports, token-protected admin bootstrap, admin stats, status moderation, verification history, and protected evidence retrieval.
- SQLite schema, API/setup/architecture/roadmap documentation, and deterministic scanner/scoring tests.

## Partial / not connected

- Domain age, business registry, real threat feeds, and malicious-domain database checks require external providers; none are simulated.
- Verification uses human status updates and basic duplicate checks. There is no moderator assignment queue, decision rubric UI, appeal workflow, or robust spam prevention.
- Admin user management is limited to user counts and registration role assignment.
- Authentication and rate limiting are MVP-level and need production hardening before public deployment.

## Verification performed

- `python -m unittest discover -s tests -v` — passed (10 tests), covering scoring tiers, URL safety, scan storage, account password/session handling, admin bootstrap, guest report access, consent, file validation, report upload, and moderation history.
- `python -m py_compile server.py trust_engine.py` — passed.
- `node --check web/app.js` — passed.
- A local HTTP launch was attempted, but this execution environment denied socket access, so a browser/API end-to-end run could not be completed here.
