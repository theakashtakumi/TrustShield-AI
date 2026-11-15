# Project roadmap

## Next: safer scanner operations

- Move scans into isolated workers with DNS pinning and network egress allow/deny controls.
- Add verified domain-age and threat-intelligence providers behind independent adapters; expose source/time/availability in every finding.
- Expand page sampling safely to policy/contact pages while retaining response caps and clear source URLs.
- Add administrator-owned, versioned scoring configurations and regression tests before allowing live score-weight changes.

## Next: production evidence and review operations

- Add analyst-specific roles, queue ownership, review service targets, escalation, and an appeal workflow. The MVP supports assignment to active administrators, internal notes, and incident timelines.
- Add malware scanning, retention/deletion policies, upload quotas, content safety checks, evidence access audit logs, and storage encryption/key rotation.
- Improve duplicate and coordinated-report detection with better similarity explanations while avoiding counting repeated allegations as independent confirmation.
- Add user email verification and secure identity recovery; retain in-app notifications as the core auditable record.

## Next: user and platform operations

- Add CSRF protection, PostgreSQL migrations, durable distributed rate limiting, backups, and service monitoring.
- Add saved sites, domain trust profiles with scan timelines, report retention/privacy settings, and business response channels.
- Add CSRF protection, production identity recovery, and fine-grained administrator permissions; the MVP currently has audited user/admin roles and account suspension controls.

## Future analysis integrations

- Add domain registration and reputable threat intelligence providers behind explicit availability/source adapters; do not simulate results where credentials or coverage are absent.
- Evaluate privacy-preserving multilingual OCR, calibrated confidence, and better similarity methods against curated, independently reviewed datasets before production use.
- Add deletion/retention controls for OCR output and consent records, plus provider-specific data-processing controls for deployments that enable hosted models.
- Keep training and evaluation datasets partitioned by report and governed by human label review; any future training job needs a separately documented approval and reproducibility process.

## AI MVP follow-up

- Deploy the Python API, database, and private file storage as a persistent service alongside the static Vercel frontend; configure provider credentials only in the backend environment.
- Add egress policies and deployment health/usage monitoring for configured hosted or local model endpoints.
- Expand API integration coverage for provider failures and run an end-to-end browser pass on the deployed frontend/backend pairing.
