# Architecture

## Overview

The MVP runs as a same-origin Python standard-library HTTP server. This keeps local setup dependency-free while leaving the browser/API boundary and scoring service separable for a later FastAPI or framework migration.

```text
Browser (web/index.html, styles.css, app.js)
                │ same-origin JSON API
                ▼
server.py ──► trust_engine.py
    │
    ├── security_headers.py (individual security-header validators)
    ├── guidance_service.py (category-specific, country-aware guidance)
    ├── evidence_service.py (deterministic evidence triage and duplicate hints)
    ├── community_service.py (privacy-safe search, counts, and pagination)
    ├── SQLite (scans, accounts, sessions, reports, moderation events)
    └── uploads/ (private report and follow-up evidence)
```

## Main components

- `server.py`: static asset delivery, API routes, persistence, authentication, rate limits, safe file handling, and bounded website retrieval.
- `security_headers.py`: value-aware validators for HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and Permissions-Policy.
- `trust_engine.py`: deterministic, versioned finding format, configurable weighted scoring, and risk-tier labels, independent of HTTP and storage.
- `guidance_service.py`: incident-specific action steps and allowed official resources. Resource URLs are configurable but accepted only on the independently verified official host.
- `evidence_service.py`: file readability, category relevance hints, duplicate hashes, date/domain consistency, completeness, and possible-similarity checks. It deliberately does not authenticate files or decide claims.
- `community_service.py`: indexed domain/status/category query, safe public summaries, aggregate counts, and page-limited results.
- `web/`: responsive accessible interface. `app.js` owns API calls and renders escape-encoded user content.
- `trustshield.db`: SQLite file created at first startup. The database access helper commits/rolls back and always closes the connection.
- `uploads/`: random server-generated file names; never served as static assets. Private evidence is served only after checking ownership or admin role.

## Scan flow

1. Normalize the submitted URL and allow only HTTP or HTTPS; reject credentials, malformed ports, local names, and any DNS answer that is not a globally routable IP.
2. Resolve hostnames, reject private or reserved addresses, and connect to a validated public IP while preserving the original HTTP host and TLS name. Revalidate each redirect destination. Disable proxy use; cap redirects, request duration, and response bytes.
3. Parse page title, visible text, links, all six security headers, cookie attributes, and a small set of deterministic wording/domain patterns.
4. Store each finding with status, evidence, source, timestamp, scanner version, and score contribution. `trust_engine.score_findings` applies bounded, explicit weights and keeps unknown checks at zero impact.
5. Return the evidence, source, status, and next steps. Missing values are unknown and do not add risk points.

The scan is a read-only fetch; it does not submit forms, authenticate, or purchase anything. Domain registration and threat intelligence providers are not configured, so those results remain unknown. Before public deployment, add egress firewall rules, worker isolation, durable rate limits, and abuse controls.

## Identity and moderation

Passwords use salted scrypt hashes. Sessions use random bearer tokens stored by SHA-256 digest, with HttpOnly and SameSite=Strict cookies; enable the Secure cookie flag behind HTTPS. Admin bootstrap requires both the configured email and a server-side one-time token, so merely claiming the configured address cannot grant admin. Admin-only status updates are recorded as immutable event rows while the report stores its current status.

Guest reports are allowed. Signed-in users can view their own report evidence and scan history. Public community views omit email, transaction reference, and related links. Evidence file names are sanitized for display, storage paths are random, MIME type and file signatures are checked, and content is bounded to 2 MB.

## Complaint lifecycle

Reports start at `Submitted` and remain private until a moderator moves them into review. Supported states are `Submitted`, `Under Review`, `More Information Required`, `Partially Supported`, `Verified Findings`, `Inconsistencies Found`, `Rejected`, and `Disputed`. `STATUS_TRANSITIONS` in `server.py` defines permitted transitions. Every moderator decision requires an internal reason and creates an append-only `moderation_events` record with moderator ID and time. A separate public update is used for information requests, so internal notes never appear in user or community views. Legacy states are mapped additively during startup migration.

The evidence service stores its versioned checks with each report. It can note unreadable files, category hints, duplicate hashes, incident date conflicts, unrelated links, incomplete narratives, and similar domain/category reports. Similarity is based on a text heuristic and relevant dates; candidates are shown to moderators and never merged automatically. File structure cannot prove authenticity, and a genuine receipt cannot by itself prove intentional fraud. The analyzer boundary is ready for later OCR/document adapters, but none are configured and the app makes no AI claim.

User guidance is selected by category and currently targets India. Completed steps are scoped to the report owner (account or guest token). In-app notifications are persisted in SQLite with read state. More-information requests keep the current verification status until an administrator reviews the reporter's follow-up. Accuracy flags and business/affected-party disputes are stored privately for moderator review; they do not automatically change a public report's verification status.

Community search uses indexed status, category, and normalized domain columns and returns at most 20 rows per page. Public cards use a redacted short description and omit private evidence, transaction references, related links, contact details, and internal notes. Per-domain totals may include submitted but unpublished allegations; the interface labels these as unverified and warns that counts are not proof.

## Future service boundaries

`trust_engine.py` is the scan scoring boundary; later domain-age and threat-intelligence adapters should return typed findings with source, timestamp, availability, and rule IDs. An optional evidence-extraction interface can be added beside `evidence_service.py`, but outputs must remain review suggestions and cannot silently change report status. Database access can move behind repositories before replacing SQLite with PostgreSQL.
