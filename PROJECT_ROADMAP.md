# Project roadmap

## Next: safer scanner operations

- Move scans into isolated workers with DNS pinning and network egress allow/deny controls.
- Add verified domain-age and threat-intelligence providers behind independent adapters; expose source/time/availability in every finding.
- Expand page sampling safely to policy/contact pages while retaining response caps and clear source URLs.
- Add configurable scoring rules with versioned calculation records and regression tests.

## Next: review quality and evidence

- Add a moderator queue, decision notes, evidence-request workflow, disputes/appeals, and report-change history UI.
- Add malware scanning, file retention/deletion controls, upload quotas, content safety checks, and evidence access audit logs.
- Improve duplicate and coordinated-report detection while avoiding treating repeated allegations as verified facts.

## Next: user and platform operations

- Add account recovery, email verification, CSRF strategy, PostgreSQL migrations, durable rate limiting, audit logs, backups, and service monitoring.
- Add saved sites, domain trust profiles with scan timelines, and privacy settings for reports.
- Add admin user management and role assignment with explicit audit events.

## Future analysis integrations

- Add optional AI adapters for page similarity and language triage. AI output should be presented as a non-verified signal, keep provenance, and never replace evidence review or silently change rule weights.
