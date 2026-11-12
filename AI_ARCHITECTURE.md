# AI architecture

TrustShield AI's intelligence layer is optional, bounded, and separated from scoring and moderation. It provides leads for a person to review. It does not decide whether a seller committed fraud, authenticate evidence, or change a report status.

## Service boundaries

- `ai_services/provider.py` defines JSON-only adapters for Gemini and Ollama. The interface can be extended for another hosted or local model without changing report/scanner workflows.
- `ai_services/website_content.py` sends only the safe scanner's retrieved title and visible text (maximum 12,000 characters) for website-content analysis. Empty pages are skipped.
- `ai_services/phishing.py` performs deterministic URL, IDN/punycode, configured brand similarity, password-form action, HTTP credential, and cross-host redirect checks. `brand_domains.json` is editable reference data. These heuristics do not represent a threat-feed match.
- `ai_services/evidence_analysis.py` extracts bounded text locally from TXT, optional PDF, or optional image OCR, then derives dates, amounts, domains, and masked reference hints. The original upload bytes are never passed to an AI provider.
- `ai_services/complaint_intelligence.py` computes deterministic completeness hints and, only with consent, requests a neutral summary, category fit, follow-up questions, and risk leads.
- `ai_services/fraud_patterns.py` compares a report with bounded recent candidates using domain/category/text similarity and dates. These are candidate links, not independent confirmations.
- `ai_services/moderation_assistant.py` assembles a private moderator brief and explicitly cannot alter status.
- `ai_services/learning.py` reports metrics only for explicitly curated, partitioned labels. It does not train or auto-label data.

`server.py` coordinates these services and persists results. Existing deterministic scan findings and `trust_engine.py` scoring remain independent of model output. Phishing heuristics are displayed separately and do not add score points. When a provider is missing, unavailable, times out, or returns an invalid response, safe status metadata is returned and the rule-based workflow continues.

## Provider setup

AI is off by default. Configure the backend process environment:

| Variable | Purpose |
| --- | --- |
| `TRUSTSHIELD_AI_PROVIDER` | `gemini`, `ollama`, or blank to disable |
| `TRUSTSHIELD_AI_MODEL` | Optional model override; defaults are `gemini-3.5-flash-lite` or `llama3.2:3b` |
| `TRUSTSHIELD_AI_MODEL_VERSION` | Optional version label stored with each run; otherwise `unknown` |
| `TRUSTSHIELD_AI_TIMEOUT` | Request timeout in seconds, clamped to 1–20 |
| `TRUSTSHIELD_GEMINI_API_KEY` | Server-only credential when using Gemini |
| `TRUSTSHIELD_OLLAMA_URL` | Local Ollama endpoint; defaults to `http://127.0.0.1:11434` |

Provider calls use structured JSON output, temperature zero, bounded response sizes, no model tools, and at most one retry for transient transport/server failures. The default Gemini model supports structured outputs per [Google's model reference](https://ai.google.dev/gemini-api/docs/models/gemini-3.5-flash-lite); API availability and model catalog can change. AI request status is shown by `GET /api/ai/status`; "configured" means configured, not that the remote service has just passed a health check. Hosted API pricing and data handling are controlled by the provider and account. Ollama can run locally without an external model API, subject to its own resource requirements.

The Vercel configuration publishes only `web/`. The Python API, database, private uploads, and provider credentials require a separately hosted backend with persistent storage; a static Vercel deployment alone cannot run this AI service.

## Data flow and privacy

1. A scan uses the existing public-host validation, redirect checks, pinned connection, time cap, and response-size limit before extracting visible text. Scripts are not executed. Retrieved page text is untrusted input.
2. A report can be submitted without AI. The separate, unchecked-by-default consent box allows complaint details and extracted evidence text to be sent to the configured provider for that analysis. The owner must consent again for an owner-triggered retry. An administrator can retry only where the reporter previously consented.
3. Evidence files stay in private storage and are decoded locally. At most four bounded attachments are read per analysis; PDF extraction covers at most ten pages and 12,000 characters; image OCR rejects images above 20 million pixels and uses a short Tesseract timeout.
4. Before provider calls, common email addresses, credential/OTP patterns, long numbers, card-like numbers, and filenames are redacted. This pattern-based redaction is incomplete: names, addresses, or other sensitive details may remain. The UI asks users to review their text before opting in. A provider receives text, never the raw uploaded binary.
5. The database stores validated output, provider/model/prompt version, timestamp, resource domain, consent flag, usage metadata, and a SHA-256 hash of serialized input. It does not store the provider request text in `ai_runs`. Private report analysis remains visible only to the report owner and administrators.

Do not enable external processing without reviewing the provider's current data-handling terms. Use a local Ollama deployment where policy requires the model call to stay in the deployment environment.

## Prompt injection and output validation

Website, complaint, and OCR text are embedded as data in a JSON input. The system instruction says to ignore instructions found in that data, use no tools, and analyze only supplied information. The model has no database, browser, or action tools. Provider output is parsed and validated against strict service schemas. Model evidence excerpts and extracted entities are retained only when they match text supplied to the model. Displayed text is HTML-escaped by the frontend.

Schema validation bounds list lengths and text fields, validates enumerated values, redacts common identifiers in returned text, and drops unsupported quoted evidence. Provider errors do not create trusted findings. All model confidence values are ordinal model-reported bands, not calibrated probabilities.

## Evidence analysis limits

OCR and PDF parsing may be incomplete, inaccurate, or unavailable when optional dependencies are missing. Entity extraction is heuristic. Extracted dates can use ambiguous formats, amounts do not prove payment, a domain mention does not identify who controlled it, and masked transaction references do not establish an event. Similarity between the submitted URL and document domains is only a review lead. Neither consistent documents nor an AI summary proves authenticity or a user's account. The UI labels these results **AI-assisted evidence analysis — not independent verification** and reserves conclusions for authorized human moderators.

## Moderator feedback and data curation

Administrators can accept or reject specific model risk indicators and add an optional note. Feedback records reference an existing validated run and finding index. Separately, administrators can record human-reviewed report outcomes with a required review note and assign a report to `training`, `evaluation`, or `unassigned`. A report cannot appear in both partitions. Disputed, unresolved, and insufficient-evidence labels must remain unassigned. Nothing is automatically treated as a training label and no model training occurs in this phase.

Evaluation currently compares complaint triage with only the explicit labels `confirmed malicious activity` and `legitimate business`. It reports precision, recall, false-positive rate, false-negative rate, accuracy, counts, and category slices. Supported-but-not-confirmed, inaccurate, disputed, unresolved, and insufficient-evidence cases are excluded from binary metrics. Duplicate report IDs are counted once. Small or biased curated sets are not evidence of production performance; results need independent review and larger, representative, leakage-controlled data before model comparisons are meaningful.

## Future work

Possible next steps include verified threat-intelligence providers, calibrated evaluation sets with documented labeling policy, more robust multilingual OCR and domain normalization, privacy/retention controls for extracted text, moderator review analytics, and a separately governed training pipeline. Any new model must preserve source attribution, consent, human control, and deterministic fallback.
