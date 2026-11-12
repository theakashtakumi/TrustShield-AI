# Architecture

## Overview

The MVP runs as a same-origin Python standard-library HTTP server. This keeps local setup dependency-free while leaving the browser/API boundary and scoring service separable for a later FastAPI or framework migration.

```text
Browser (web/index.html, styles.css, app.js)
                │ same-origin JSON API
                ▼
server.py ──► trust_engine.py
    │
    ├── SQLite (scans, accounts, sessions, reports, moderation events)
    └── uploads/ (private evidence files)
```

## Main components

- `server.py`: static asset delivery, API routes, persistence, authentication, rate limits, safe file handling, and bounded website retrieval.
- `trust_engine.py`: deterministic rule-weight mapping and risk-tier labels, independent of HTTP and storage.
- `web/`: responsive accessible interface. `app.js` owns API calls and renders escape-encoded user content.
- `trustshield.db`: SQLite file created at first startup. The database access helper commits/rolls back and always closes the connection.
- `uploads/`: random server-generated file names; never served as static assets. Private evidence is served only after checking ownership or admin role.

## Scan flow

1. Normalize the submitted URL and allow only HTTP or HTTPS; reject credentials, malformed ports, local names, and any DNS answer that is not a globally routable IP.
2. Before following redirects, validate each redirect's scheme and resolved destination. Cap redirects, request duration, and response bytes.
3. Parse page title, visible text, links, selected headers, and a small set of deterministic wording/domain patterns.
4. Store each finding and calculate a bounded trust score from warning points using `trust_engine.classify`.
5. Return the evidence, source, status, and next steps. Missing values are unknown and do not add risk points.

The scan is a read-only fetch; it does not submit forms, authenticate, or purchase anything. DNS validation is performed before requests and redirects. As with many URL fetchers, this local MVP is not a hardened, isolated scanning service and should not be exposed to arbitrary users on the public internet without stronger DNS pinning, egress firewall rules, worker isolation, and abuse controls.

## Identity and moderation

Passwords use salted scrypt hashes. Sessions use random bearer tokens stored by SHA-256 digest, with HttpOnly and SameSite=Strict cookies; enable the Secure cookie flag behind HTTPS. Admin bootstrap requires both the configured email and a server-side one-time token, so merely claiming the configured address cannot grant admin. Admin-only status updates are recorded as immutable event rows while the report stores its current status.

Guest reports are allowed. Signed-in users can view their own report evidence and scan history. Public community views omit email, transaction reference, and related links. Evidence file names are sanitized for display, storage paths are random, MIME type and file signatures are checked, and content is bounded to 2 MB.

## Future service boundaries

`trust_engine.py` is the scoring boundary; later domain-age, threat-intelligence, and AI analyzers should return typed findings with source, timestamp, confidence/availability, and rule IDs. The scoring layer should remain transparent and separate from any AI model output. Database access can move behind repositories before replacing SQLite with PostgreSQL.
