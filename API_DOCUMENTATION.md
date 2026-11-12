# API documentation

All endpoints are same-origin and JSON unless noted. API errors use `{"error":"..."}`. Sessions use an HttpOnly cookie.

## Website checks

### `POST /api/scan`

Request: `{"url":"https://shop.example"}`. Scheme is optional; HTTPS is assumed. The result includes `id`, canonical `url`, `domain`, `score`, `label`, `summary`, `checks[]`, `created_at`, and `status_code`. `score` is a trust score from 0–100 (higher means fewer selected warning signals), not a safety probability. Each check includes `name`, `status`, `detail`, `source`, and `impact`.

### `GET /api/history`

Returns the signed-in user's scans, reports that have entered review, and their own report statuses. New `Submitted` reports stay private to the submitter and moderators until reviewed. Anonymous users get reviewed community reports and empty personal histories. Admin responses also include aggregate moderation counts.

## Community reports

### `POST /api/reports`

Required body fields: `url`, `category`, `details` (12–4,000 characters), and `agree: true`. Optional fields: `business`, `incident_date` (`YYYY-MM-DD`, not future), `amount`, `reference`, `links` (up to five URLs on separate lines), and `evidence_file` `{name,mime_type,data}` where `data` is base64. Files must be PNG/JPEG/WEBP/PDF/TXT and at most 2 MB. Reports begin at `Submitted`.

Duplicate URL/category/details combinations are rejected. This is basic duplicate suppression, not an anti-abuse system. Guests can submit; signed-in reports attach to the account.
Guest submissions receive an unguessable access token once in the response. The browser stores it locally and sends it in `X-TrustShield-Guest-Tokens` to show report status and access private submission details. Clearing browser storage loses guest access; sign-in provides account-based tracking instead.

### `GET /api/reports/{id}`

Returns the report and verification history. New and rejected reports are private to the submitter and moderators. Transaction references and related URLs are only returned to the report owner or admin.

### `GET /api/reports/{id}/evidence`

Returns the submitted attachment only for its owner or an administrator.

## Accounts and moderation

- `POST /api/auth/register`: `{name,email,password,admin_token?}`. Password must be 10–128 characters. Admin bootstrap requires a match to both `TRUSTSHIELD_ADMIN_EMAIL` and the server's `TRUSTSHIELD_ADMIN_BOOTSTRAP_TOKEN`. Returns the user and sets a session cookie.
- `POST /api/auth/login`: `{email,password}`. Returns the user and sets a session cookie.
- `POST /api/auth/logout`: clears the current session.
- `GET /api/auth/me`: returns the current user, or HTTP 401 when signed out.
- `PATCH /api/admin/reports/{id}/status`: admin only; `{status,note?}`. Status must be one of Submitted, Under Review, Evidence Requested, Partially Verified, Verified, Rejected, or Disputed. The prior status and decision time are recorded.
- `GET /api/health`: `{ok:true}`.

The app enforces in-memory per-IP rate limits on scans, reports, registration, and login. Limits reset when the process restarts and are not shared across multiple server workers.
