# API documentation

All endpoints are same-origin and JSON unless noted. API errors use `{"error":"..."}`. Sessions use an HttpOnly cookie.

## Website checks

### `POST /api/scan`

Request: `{"url":"https://shop.example"}`. Scheme is optional; HTTPS is assumed. The result includes `id`, canonical `url`, `domain`, `score`, `label`, `summary`, `findings[]` (also returned as `checks[]`), `calculation`, `scanner_version`, `created_at`, and `status_code`. The score is a bounded presentation aid, not a safety probability. Each finding includes `rule_id`, `name`, `category`, `status`, `explanation`, `source`, `evidence`, `observed_at`, `score_contribution`, and `scanner_version`. Status is `PASS`, `WARNING`, `FAIL`, `NOT DETECTED`, `UNKNOWN`, or `NOT APPLICABLE`. Unknown and unavailable checks contribute no points. The calculation contains the formula and weighted warning points.

The scanner checks public DNS addresses, HTTPS/TLS where available, HTTP behavior, six security headers, cookie attributes, and selected page text and URL patterns. Domain registration, nameserver and external threat-feed lookups are explicitly `UNKNOWN` until providers are configured. Scanner requests are size- and time-bounded, resolve and validate destinations, pin the connection to a validated public IP, disable proxies, and validate every redirect. When configured, `ai_analysis` contains a separately labeled analysis of retrieved visible text and `phishing_analysis` contains deterministic URL/brand/login heuristics. These fields never change the deterministic score. AI service errors preserve the non-AI result. `verified_threat_match` is returned separately when the hostname matches a moderator-created local record whose source report is `Verified Findings`; this annotation does not affect the score.

### `GET /api/ai/status`

Returns provider configuration and supported capabilities. `configured: true` means credentials/endpoint settings are present; it is not a live health check. AI is optional and disabled by default.

### `GET /api/history`

Returns signed-in scans, public-safe community reports, owner report history, and database-backed overview counts. New `Submitted` reports stay private from community details until a moderator enters them into review. Guest submissions are included when a valid `X-TrustShield-Guest-Tokens` header is supplied. Admin responses also include actual queue, verified, disputed, and accuracy-request counts.

### `GET /api/community`

Supports `q`, `status`, `category`, `sort=latest|most_discussed`, and `page`. Returns up to 20 public-safe report cards per page. Search covers URL, normalized domain, business, category, and redacted summary. Admins can additionally see Submitted and Rejected reports for review. Similar reports are counted by normalized domain and are not treated as independent confirmation.

### `GET /api/community/domain/{domain}`

Returns database-backed totals and review-status/category counts for the domain, with at most 20 public report summaries. Aggregate totals include Submitted reports that are not individually public; the caller must keep the unverified distinction visible.

## Community reports

### `POST /api/reports`

Required body fields: `url`, `category`, `details` (12–4,000 characters), and `agree: true`. Optional fields: `business`, `incident_date` (`YYYY-MM-DD`, not future), `amount` (free text, such as `INR 1200`), `reference`, `links` (up to five URLs on separate lines), `ai_consent` (boolean, defaults false), and `evidence_files` (up to 3 `{name,mime_type,data}` objects, base64 data). Legacy clients may use one `evidence_file`. Each file must be PNG/JPEG/WEBP/PDF/TXT and no larger than 2 MB. Reports begin at `Submitted`; the response contains a stable reference, personalized guidance, deterministic evidence triage, and private AI analysis metadata/results when available. `ai_consent: true` permits the configured provider to process report text and locally extracted evidence text after common-pattern redaction; the raw file is never sent. Other sensitive details can remain in text, so the user must review before opting in. The form presents fields as a three-step flow and defaults the amount currency to INR.

Duplicate URL/category/details combinations are rejected. This is basic duplicate suppression, not an anti-abuse system. Guests can submit; signed-in reports attach to the account.
Guest submissions receive an unguessable access token once in the response. The browser stores it locally and sends it in `X-TrustShield-Guest-Tokens` to show report status and access private submission details. Clearing browser storage loses guest access; sign-in provides account-based tracking instead.

### `GET /api/reports/{id}`

Returns the report reference, status timeline, safe public description (or full description to its owner/admin), category guidance, related reports, and basic evidence summary. Only the owner/admin receives transaction references, related URLs, original evidence names, private follow-ups, structured evidence analysis, and internal moderation reasons. Moderation history notes are only returned to admins. Public users cannot retrieve Submitted or Rejected reports.

Owner/admin details may also include `ai_analysis`: local completeness and extraction results, AI summaries/observations, possible inconsistencies, suggested questions, and similar-report leads. It is private and explicitly not independent verification. Administrators also receive recorded `ai_feedback` decisions for the report. Public report details omit AI analysis, consent, and moderator feedback.

### `POST /api/reports/{id}/ai-analysis`

Owner may request a new analysis with `{ "consent": true }`; explicit consent is required on every owner-triggered retry. An administrator may retry only if the reporter previously consented. Returns the updated private analysis and `report_status_unchanged: true`. This endpoint cannot alter report status. Analysis may be unavailable when the provider or optional extraction tools are not configured.

### `POST /api/reports/{id}/actions`

Owner only. Body `{action_id,completed}` persists completion of a guidance step generated for that report's category.

### `POST /api/reports/{id}/followups`

Owner only, and only while status is `More Information Required`. Body includes `details` (8–4,000 characters) and optional one `evidence_file`. Follow-ups append to the report; they do not alter verification status.

### `POST /api/reports/{id}/flags` and `POST /api/reports/{id}/disputes`

Publicly visible report only. Body `{reason,contact?}`. Creates a private accuracy/dispute request for admin review. It does not change report status or delete the report.

### `GET /api/reports/{id}/evidence`

Returns the original attachment only for its owner or an administrator. Additional initial attachments use `/api/reports/{id}/evidence/attachment/{attachment_id}`; follow-up attachments use `/api/reports/{id}/evidence/followup/{followup_id}`. Downloads are private, returned as attachments with `nosniff`, and never served from the static web directory.

### `GET /api/notifications` and `POST /api/notifications/{id}/read`

Lists persisted in-app notifications for a signed-in owner or guest-token owner and marks an owned item read. Status changes and report submission notifications persist in SQLite; no email is sent.

## Accounts and moderation

- `POST /api/auth/register`: `{name,email,password,admin_token?}`. Password must be 10–128 characters. Admin bootstrap requires a match to both `TRUSTSHIELD_ADMIN_EMAIL` and the server's `TRUSTSHIELD_ADMIN_BOOTSTRAP_TOKEN`. Returns the user and sets a session cookie.
- `POST /api/auth/login`: `{email,password}`. Returns the user and sets a session cookie.
- `POST /api/auth/logout`: clears the current session.
- `GET /api/auth/me`: returns the current user, or HTTP 401 when signed out.
- `PATCH /api/admin/reports/{id}/status`: admin only; `{status,note,public_message?}`. Status must follow the allowed lifecycle transition: Submitted, Under Review, More Information Required, Partially Supported, Verified Findings, Inconsistencies Found, Rejected, or Disputed. An internal reason is required; `More Information Required` also requires a separate message visible to the owner. Each change is logged with moderator ID, prior/new status, reason, and time; the owner receives an in-app notification.
- `PATCH /api/admin/reports/{id}/flags/{flag_id}`: admin only; `{status,reason}` resolves an accuracy/dispute request as `Actioned`, `No change`, or `Needs follow-up`. The decision is recorded in the moderation audit trail.
- `POST /api/admin/ai/feedback`: admin only; `{run_id,finding_key,decision,note?}` accepts/rejects an existing complaint finding (for example `risk_indicators:0`). Decisions are audit data and do not update the complaint's official status.
- `POST /api/admin/reports/{id}/ai-outcome`: admin only; `{label,partition,note}` records a human-reviewed outcome. Partitions are `training`, `evaluation`, and `unassigned`. A required review note explains the label; insufficient-evidence, disputed, and unresolved labels must be unassigned. A report cannot be placed in both training and evaluation partitions.
- `GET /api/admin/ai/evaluation`: admin only; returns precision, recall, false-positive/negative rates, accuracy, category slices, eligible and excluded counts for the latest evaluation label per report. Only confirmed-malicious and legitimate-business labels qualify for binary metrics; no model training occurs.
- `GET /api/admin/overview?days=7|30|90`: admin only; returns database-backed account, scan, complaint, local verified-threat, and incident counts; daily scan counts; recent audit/moderation activity; and API/database/provider status.
- `GET /api/admin/users?q=&status=&page=&limit=`: admin only; searchable account list with role, active/suspended state, scan/report counts, and pagination. `GET /api/admin/users/{id}` returns a profile with recent scans and submitted reports. `PATCH /api/admin/users/{id}/status` accepts `{status:"active"|"suspended"}` and revokes sessions on suspension. `PATCH /api/admin/users/{id}/role` accepts `{role:"user"|"admin"}`. Self changes and removal/suspension of the last active admin are rejected. Each change is audit logged.
- `GET /api/admin/scans?q=&status=&page=&limit=`: admin only; paginated stored scans and observed checks.
- `GET /api/admin/reports?q=&status=&priority=&page=&limit=`: admin only; searchable report queue. `GET /api/admin/reports/{id}` returns private report details, assigned reviewer, priority, evidence metadata, review history, and administrator-only notes. `PATCH /api/admin/reports/{id}` accepts `assigned_to` (active admin ID or null) and/or `priority` (`low`, `normal`, `high`, `urgent`). `POST /api/admin/reports/{id}/notes` accepts `{note}` and saves a private investigation note. Assignment, priority, and notes are audit logged; they are not shown in public report details.
- `GET /api/admin/threats?q=&status=&page=&limit=`: admin only; human-reviewed local threat records, source report, domain, category, and first/last seen. `POST /api/admin/threats` accepts `{report_id,verification_note}` and requires the source report to already be `Verified Findings`. `PATCH /api/admin/threats/{id}/status` accepts `{status:"verified"|"false_positive",note}` and records reviewer/time. No external threat feed is queried.
- `GET /api/admin/scanner/settings`: admin only; returns supported runtime settings and fixed/unavailable modules. `PATCH /api/admin/scanner/settings` accepts any subset of `request_timeout_seconds` (3–20), `max_redirects` (0–10), `phishing_heuristics_enabled` (boolean), and `ai_content_analysis_enabled` (boolean). Saved settings affect subsequent scans and are audit logged. Core DNS/IP, TLS, security-header, and redirect-destination safeguards remain enabled.
- `GET /api/admin/incidents?q=&status=&page=&limit=` and `GET /api/admin/incidents/{id}`: admin only; case records with assigned admin, linked reports, resolution and event history. `POST /api/admin/incidents` accepts `{title,severity,assigned_to?,report_ids?,note?}` where severity is `low|medium|high|critical`. `PATCH /api/admin/incidents/{id}` accepts status (`new|investigating|contained|resolved|closed`), severity, active-admin assignee/null, resolution note, and optional event note; resolving/closing requires a resolution note. `POST /api/admin/incidents/{id}/events` accepts `{note}`. Case changes and notes are appended to the timeline and audit feed.
- `GET /api/admin/audit?q=&page=&limit=`: admin only; searchable, read-only event feed combining administrator actions, moderation, incident changes, and AI feedback. No API operation edits or deletes audit entries. `GET /api/admin/ai` returns provider status, stored run counts/provenance, feedback counts, human-label counts, and recent AI runs; it does not claim model accuracy.
- `GET /api/health`: `{ok:true}`.

The app enforces in-memory per-IP rate limits on scans, reports, registration, and login. Limits reset when the process restarts and are not shared across multiple server workers.

## Evidence review methodology and limits

Evidence triage checks basic readability, filename/category hints, matching SHA-256 hashes, incident/submission dates, whether submitted URLs share the reported domain or a related subdomain, and whether the description gives enough context. It can suggest similar reports based on domain, category, description similarity, and dates within 30 days. These are moderator leads only. Optional local extraction supports TXT, optional PyMuPDF PDFs, and optional Pillow/pytesseract/Tesseract images. Extraction may be unavailable or wrong and does not authenticate the file. The configured AI service receives only consented redacted text, not original binaries. A receipt does not prove seller intent. See `AI_ARCHITECTURE.md` for limits and privacy behavior. `guidance_service.py` contains category/country adapters; India resource URLs may be overridden only while retaining the verified official host. Guidance is general information, not legal or financial advice.

Public views omit contact details, amount, transaction reference, related URLs, private attachments, follow-up details, and internal moderation notes. Public summaries redact common email, phone/long-number, and credential patterns. This heuristic may miss sensitive information, so reports must be moderated before publication and public output should never be used as secure evidence storage.
