const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const state = { user: null, view: 'overview', page: 1, limit: 25, q: '', status: '', priority: '', role: '', severity: '', admins: [], toastTimer: null, currentRows: [], evaluation: null, overviewDays: 30 };
const titles = { overview: 'Overview', reports: 'Complaint operations', scans: 'Website scans', users: 'User management', threats: 'Threat intelligence', incidents: 'Incident response', scanner: 'Scanner settings', ai: 'AI & evaluation', audit: 'Audit trail' };
const h = (value = '') => String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const n = (value) => Number.isFinite(Number(value)) ? new Intl.NumberFormat().format(Number(value)) : '0';
const date = (value) => { const parsed = new Date(value); return Number.isNaN(parsed.getTime()) ? 'Date unavailable' : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(parsed); };
const shortDate = (value) => { const parsed = new Date(value); return Number.isNaN(parsed.getTime()) ? '' : new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' }).format(parsed); };
const queryString = (extra = {}) => new URLSearchParams({ page: String(state.page), limit: String(state.limit), ...(state.q ? { q: state.q } : {}), ...(state.status ? { status: state.status } : {}), ...(state.priority ? { priority: state.priority } : {}), ...(state.role ? { role: state.role } : {}), ...(state.severity ? { severity: state.severity } : {}), ...extra }).toString();

async function api(path, options = {}) {
  const response = await fetch(path, { credentials: 'same-origin', ...options, headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) } });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || (response.status === 404 ? 'This service is not available on the current deployment. Check the backend API configuration.' : `Request failed (${response.status}).`));
  return body;
}
function notify(message) { const el = $('#toast'); el.textContent = message; el.classList.add('visible'); clearTimeout(state.toastTimer); state.toastTimer = setTimeout(() => el.classList.remove('visible'), 3400); }
function setBusy(button, busy, label = 'Saving…') { if (!button) return; if (busy) { button.dataset.oldText = button.textContent; button.textContent = label; button.disabled = true; } else { button.textContent = button.dataset.oldText || button.textContent; button.disabled = false; } }
function setViewFromHash() { const match = location.hash.match(/^#admin\/([a-z-]+)/); return titles[match?.[1]] ? match[1] : 'overview'; }
function go(view, query = {}) { state.page = 1; state.q = query.q || ''; state.status = query.status || ''; state.priority = query.priority || ''; state.role = query.role || ''; state.severity = query.severity || ''; location.hash = `#admin/${view}`; if (state.view === view) loadView(); }
function pageHeading(kicker, title, description, action = '') { return `<div class="page-heading"><div><span class="eyebrow">${h(kicker)}</span><h1>${h(title)}</h1><p class="subheading">${h(description)}</p></div>${action ? `<div class="toolbar">${action}</div>` : ''}</div>`; }
function tableShell(rows, empty, headers) { return `<div class="table-wrap"><table><thead><tr>${headers.map((x) => `<th>${h(x)}</th>`).join('')}</tr></thead><tbody>${rows || `<tr><td colspan="${headers.length}"><div class="empty-state"><div><strong>${h(empty)}</strong>Try changing your search or filters.</div></div></td></tr>`}</tbody></table></div>`; }
function pager(total, page = state.page, limit = state.limit) { const pages = Math.max(1, Math.ceil(Number(total || 0) / limit)); return `<div class="pagination"><span>${n(total)} record${Number(total) === 1 ? '' : 's'} · page ${page} of ${pages}</span><div class="toolbar"><button class="button small" data-action="page" data-page="${page - 1}" ${page <= 1 ? 'disabled' : ''}>← Previous</button><button class="button small" data-action="page" data-page="${page + 1}" ${page >= pages ? 'disabled' : ''}>Next →</button></div></div>`; }
function statusClass(value) { const text = String(value || '').toLowerCase(); if (['verified findings', 'verified', 'active', 'resolved', 'contained', 'low risk'].includes(text)) return 'good'; if (['under review', 'submitted', 'new', 'investigating', 'moderate risk', 'partially supported', 'normal'].includes(text)) return 'warn'; if (/critical|high risk|rejected|suspended|false_positive|closed/.test(text)) return 'bad'; return ''; }
function statusPill(value) { return `<span class="status-pill ${statusClass(value)}">${h(value || 'Unknown')}</span>`; }
function filterBar(statusOptions = [], extras = '') { return `<form class="table-toolbar filter-form"><input class="input search-input" name="q" value="${h(state.q)}" placeholder="Search this workspace…" aria-label="Search records" /><div class="toolbar">${statusOptions.length ? `<select class="select" name="status" aria-label="Filter by status"><option value="">All statuses</option>${statusOptions.map((s) => `<option value="${h(s)}" ${s === state.status ? 'selected' : ''}>${h(s)}</option>`).join('')}</select>` : ''}${extras}<button class="button primary" type="submit">Search</button></div></form>`; }
function bars(items) { const max = Math.max(1, ...items.map((x) => Number(x.count || 0))); return `<div class="chart" role="img" aria-label="Actual scans per day for the last 30 days">${items.map((item) => { const height = Math.max(2, Math.round((Number(item.count || 0) / max) * 100)); return `<span class="chart-bar" style="--height:${height}%" data-date="${h(shortDate(item.date))}" title="${h(item.date)} · ${n(item.count)} scans"></span>`; }).join('')}</div><div class="chart-axis"><span>${h(shortDate(items[0]?.date))}</span><span>Scans recorded per day · UTC</span><span>${h(shortDate(items.at(-1)?.date))}</span></div>`; }
function metric(label, value, note, icon, view, filters = {}, tone = '') { const encoded = h(JSON.stringify(filters)); return `<button class="metric-card ${tone}" data-action="metric" data-go="${view}" data-filters="${encoded}"><span class="metric-top">${h(label)}<i class="metric-icon">${h(icon)}</i></span><strong class="metric-value">${n(value)}</strong><small class="metric-note">${h(note)}</small></button>`; }
function activityRows(events) { return events.length ? events.map((item) => `<div class="activity-row"><span class="activity-icon">${item.resource_type === 'incident' ? '⚑' : item.resource_type === 'report' ? '▤' : '⌑'}</span><span class="activity-copy"><b>${h((item.action || item.event_type || 'Activity').replaceAll('.', ' '))} · ${h(item.resource_type || 'record')} ${h(item.resource_id || '')}</b><small>${h(item.actor_name || 'System')} · ${date(item.created_at)}</small></span><time>${h(item.actor_name || 'system')}</time></div>`).join('') : '<div class="empty-state"><div><strong>No recorded activity yet</strong>Administrator actions and moderation events will appear here.</div></div>'; }

async function loadView() {
  state.view = setViewFromHash();
  $('#page-title').textContent = titles[state.view];
  $$('.side-nav [data-view]').forEach((link) => link.classList.toggle('active', link.dataset.view === state.view));
  $('#page-content').innerHTML = '<div class="loading-state"><span class="spinner"></span><p>Loading live data…</p></div>';
  try {
    const routes = { overview: loadOverview, reports: loadReports, scans: loadScans, users: loadUsers, threats: loadThreats, incidents: loadIncidents, scanner: loadScanner, ai: loadAi, audit: loadAudit };
    await routes[state.view]();
  } catch (error) {
    $('#page-content').innerHTML = `<div class="error-state"><div><strong>Could not load ${h(titles[state.view])}</strong>${h(error.message)}<p><button class="button" data-action="reload">Try again</button></p></div></div>`;
  }
}

async function loadOverview() {
  const data = await api(`/api/admin/overview?days=${state.overviewDays}`);
  const m = data.metrics || {};
  $('#system-state').textContent = `API ${data.health?.api || 'unknown'} · DB ${data.health?.database || 'unknown'}`;
  const pending = Number(m.pending_complaints || 0); const badge = $('#pending-count'); badge.hidden = pending === 0; badge.textContent = n(pending);
  $('#page-content').innerHTML = `${pageHeading('SECURITY OPERATIONS', 'Command center', 'A live view of TrustShield activity, based on records in this deployment.', '<button class="button" data-action="reload">↻ Refresh</button>')}
    <div class="grid metric-grid">${metric('TOTAL USERS',m.total_users,'Registered accounts','♙','users')}${metric('ACTIVE USERS',m.active_users,'Accounts currently enabled','●','users',{status:'active'},'good')}${metric('TOTAL SCANS',m.total_scans,`${n(m.scans_today)} recorded today`,'⌕','scans')}${metric('MODERATE RISK DOMAINS',m.suspicious_websites,'Distinct domains with a Moderate Risk scan label','⌑','scans',{status:'Moderate Risk'},'warning')}${metric('HIGH RISK DOMAINS',m.high_risk_websites,'Distinct domains with a High Risk scan label','⚠','scans',{status:'High Risk'},'critical')}${metric('CRITICAL RISK SCANS',m.critical_risk_scans,'Scan records labelled Critical Risk','⛨','scans',{status:'Critical Risk'},'critical')}${metric('PENDING COMPLAINTS',m.pending_complaints,'Open review queue; click to review all statuses','▤','reports',{},'warning')}${metric('VERIFIED THREATS',m.verified_threats,'Human-reviewed threat records','⌑','threats',{},'good')}${metric('INCOMPLETE SCANS',m.failed_scans,'Insufficient data; not necessarily a site failure','◷','scans',{status:'Insufficient Data'},'warning')}${metric('OPEN INCIDENTS',m.open_incidents,'Cases not resolved or closed','⚑','incidents',{},'critical')}</div>
    <div class="grid overview-grid"><section class="panel"><div class="panel-heading"><div><h2>Website scans</h2><p>Stored scan records, grouped by UTC day</p></div><div class="toolbar"><select class="select" id="overview-days" aria-label="Scan chart date range"><option value="7" ${state.overviewDays===7?'selected':''}>7 days</option><option value="30" ${state.overviewDays===30?'selected':''}>30 days</option><option value="90" ${state.overviewDays===90?'selected':''}>90 days</option></select><span class="chart-legend"><i></i> Scans</span></div></div>${bars(data.scans_by_day || [])}</section><section class="panel"><div class="panel-heading"><div><h2>System health</h2><p>Observed by the backend at request time</p></div></div>${Object.entries(data.health || {}).map(([key,value]) => `<div class="health-row"><span>${h(key.replaceAll('_',' '))}</span><b class="${['available','configured'].includes(String(value).toLowerCase()) ? 'health-ok' : 'health-muted'}">${h(value)}</b></div>`).join('')}<div class="notice info" style="margin-top:12px">External registration and threat feeds are not connected. Verified threat records come only from moderator actions.</div></section></div>
    <section class="panel"><div class="panel-heading"><div><h2>Recent activity</h2><p>Admin audit events and complaint review changes</p></div><a class="icon-link" href="#admin/audit">Open audit trail →</a></div><div class="activity-list">${activityRows(data.activity || [])}</div></section>`;
}

async function loadReports() {
  state.limit = 25; const data = await api(`/api/admin/reports?${queryString()}`); state.currentRows = data.reports || [];
  const statuses = ['Submitted','Under Review','More Information Required','Partially Supported','Verified Findings','Inconsistencies Found','Rejected','Disputed'];
  const rows = state.currentRows.map((r) => `<tr><td data-label="Report"><button class="icon-link cell-primary" data-action="open-report" data-id="${Number(r.id)}">TSH-${String(r.id).padStart(6,'0')} · ${h(r.business || r.domain || r.url)}</button><span class="cell-secondary">${h(r.domain || r.url)}</span></td><td data-label="Category">${h(r.category)}</td><td data-label="Status">${statusPill(r.status)}</td><td data-label="Priority"><span class="priority ${h(r.priority)}">${h(r.priority)}</span></td><td data-label="Assigned">${h(r.assigned_name || 'Unassigned')}</td><td data-label="Evidence">${n(r.evidence_count)}</td><td data-label="AI">${r.has_ai ? '<span class="status-pill good" title="AI analysis available">AI ✓</span>' : '<span class="status-pill" style="opacity:.45" title="No AI analysis yet">—</span>'}</td><td data-label="Updated">${h(shortDate(r.created_at))}</td><td data-label="Action"><button class="button small" data-action="open-report" data-id="${Number(r.id)}">Review</button></td></tr>`).join('');
  const statusSelect = filterBar(statuses, `<select class="select" name="priority" aria-label="Filter by priority"><option value="">All priorities</option>${['urgent','high','normal','low'].map((p) => `<option value="${p}" ${p === state.priority ? 'selected' : ''}>${p}</option>`).join('')}</select>`);
  $('#page-content').innerHTML = `${pageHeading('REPORT OPERATIONS','Complaints & reports','Triage user-submitted claims. Verified Findings reflects a moderator decision, not a legal determination.','<button class="button" data-action="export">⇩ Export current page</button>')}
    <div class="table-panel">${statusSelect}${tableShell(rows,'No reports match these filters.', ['Report','Category','Review status','Priority','Assigned reviewer','Evidence files','AI','Submitted',''])}${pager(data.total)}</div>`;
}

async function loadScans() {
  state.limit = 25; const data = await api(`/api/admin/scans?${queryString()}`); state.currentRows = data.scans || [];
  const labels = ['Low Risk','Moderate Risk','High Risk','Critical Risk','Insufficient Data'];
  const rows = state.currentRows.map((s) => `<tr><td data-label="Website"><span class="cell-primary">${h(s.domain)}</span><span class="cell-secondary">#${Number(s.id)} · ${h(s.url)}</span></td><td data-label="Assessment">${statusPill(s.label)}</td><td data-label="Score"><span class="mono">${s.label === 'Insufficient Data' ? '—' : n(s.score)}</span></td><td data-label="Checks">${n(s.checks?.length)}</td><td data-label="Account">${h(s.user_name || 'Guest')}</td><td data-label="Scanned">${h(date(s.created_at))}</td><td data-label="Action"><button class="button small" data-action="open-scan" data-id="${Number(s.id)}">View checks</button></td></tr>`).join('');
  $('#page-content').innerHTML = `${pageHeading('SCANNER ACTIVITY','Website scans','Stored scan records and their actual backend findings. A risk label is not a fraud determination.')}
    <div class="table-panel">${filterBar(labels)}${tableShell(rows,'No scans match these filters.',['Website','Assessment','Score','Checks','Account','Scanned',''])}${pager(data.total)}</div>`;
}

async function loadUsers() {
  state.limit = 25; const data = await api(`/api/admin/users?${queryString()}`); state.currentRows = data.users || [];
  const rows = state.currentRows.map((u) => `<tr><td data-label="Account"><span class="cell-primary">${h(u.name)}</span><span class="cell-secondary">${h(u.email)} · #${Number(u.id)}</span></td><td data-label="Role">${statusPill(u.role)}</td><td data-label="Status">${statusPill(u.status)}</td><td data-label="Scans">${n(u.scan_count)}</td><td data-label="Reports">${n(u.report_count)}</td><td data-label="Joined">${h(shortDate(u.created_at))}</td><td data-label="Action"><button class="button small" data-action="open-user" data-id="${Number(u.id)}">Profile</button></td></tr>`).join('');
  $('#page-content').innerHTML = `${pageHeading('IDENTITY & ACCESS','User management','Review account activity and manage account status or administrator roles.')}
    <div class="table-panel">${filterBar([],`<select class="select" name="status" aria-label="Filter account status"><option value="">All account states</option><option value="active" ${state.status==='active'?'selected':''}>Active</option><option value="suspended" ${state.status==='suspended'?'selected':''}>Suspended</option></select><select class="select" name="role" aria-label="Filter account role"><option value="">All roles</option><option value="user" ${state.role==='user'?'selected':''}>User</option><option value="admin" ${state.role==='admin'?'selected':''}>Administrator</option></select>`)}${tableShell(rows,'No accounts match these filters.',['Account','Role','Account status','Scans','Reports','Created',''])}${pager(data.total)}</div>`;
}

async function loadThreats() {
  state.limit = 25; const data = await api(`/api/admin/threats?${queryString()}`); state.currentRows = data.threats || [];
  const rows = state.currentRows.map((t) => `<tr><td data-label="Domain"><span class="cell-primary mono">${h(t.domain)}</span><span class="cell-secondary">Source report #${Number(t.source_report_id)}</span></td><td data-label="Category">${h(t.category)}<span class="cell-secondary">${n(t.related_report_count)} report${Number(t.related_report_count)===1?'':'s'} for exact domain</span></td><td data-label="Status">${statusPill(t.status)}</td><td data-label="First seen">${h(shortDate(t.first_seen))}</td><td data-label="Last reviewed">${h(shortDate(t.last_seen))}</td><td data-label="Reviewer">${h(t.reviewer_name || '—')}</td><td data-label="Action"><button class="button small" data-action="review-threat" data-id="${Number(t.id)}" data-status="${h(t.status)}">Review</button></td></tr>`).join('');
  $('#page-content').innerHTML = `${pageHeading('HUMAN-REVIEWED SIGNALS','Threat intelligence','Only moderator-created records backed by a Verified Findings report appear here. No external feed is connected.')}
    <div class="notice info" style="margin-bottom:12px">Community reports stay separate from verified threat records. A threat match annotates later scans and does not change their technical score.</div><div class="table-panel">${filterBar(['verified','false_positive'])}${tableShell(rows,'No threat records match these filters. Add a record from a Verified Findings report.',['Domain','Category / related reports','Record status','First seen','Last reviewed','Reviewer',''])}${pager(data.total)}</div>`;
}

async function loadIncidents() {
  state.limit = 25; const data = await api(`/api/admin/incidents?${queryString()}`); state.currentRows = data.incidents || [];
  const rows = state.currentRows.map((i) => `<tr><td data-label="Incident"><button class="icon-link cell-primary" data-action="open-incident" data-id="${Number(i.id)}">INC-${String(i.id).padStart(5,'0')} · ${h(i.title)}</button><span class="cell-secondary">Created ${h(shortDate(i.created_at))}</span></td><td data-label="Severity">${statusPill(i.severity)}</td><td data-label="Status">${statusPill(i.status)}</td><td data-label="Assigned">${h(i.assigned_name || 'Unassigned')}</td><td data-label="Linked reports">${n(i.report_count)}</td><td data-label="Updated">${h(shortDate(i.updated_at))}</td><td data-label="Action"><button class="button small" data-action="open-incident" data-id="${Number(i.id)}">Open case</button></td></tr>`).join('');
  $('#page-content').innerHTML = `${pageHeading('INCIDENT RESPONSE','Incident management','Coordinate investigations with a timeline, linked complaints, assignees, and resolution records.','<button class="button primary" data-action="create-incident">＋ New incident</button>')}
    <div class="table-panel">${filterBar(['new','investigating','contained','resolved','closed'],`<select class="select" name="severity" aria-label="Filter incident severity"><option value="">All severities</option>${['critical','high','medium','low'].map((s)=>`<option value="${s}" ${state.severity===s?'selected':''}>${s}</option>`).join('')}</select>`)}${tableShell(rows,'No incident cases yet. Create a case and link relevant complaints.',['Incident','Severity','Status','Assignee','Reports','Updated',''])}${pager(data.total)}</div>`;
}

async function loadScanner() {
  const data = await api('/api/admin/scanner/settings'); const s = data.settings;
  $('#page-content').innerHTML = `${pageHeading('ENGINE CONTROLS','Scanner settings','Runtime-supported controls are saved in the database and apply to subsequent scans.')}
    <form id="scanner-settings" class="grid two-col"><section class="config-card"><h2>Request and analysis limits</h2><p>Keep public scans bounded. Core DNS, TLS, response-header, and redirect destination safety checks are always enabled.</p>
      <label class="field"><span>Request timeout · seconds (3–20)</span><input class="input" name="request_timeout_seconds" type="number" min="3" max="20" value="${Number(s.request_timeout_seconds)}" required /></label>
      <label class="field"><span>Maximum validated redirects (0–10)</span><input class="input" name="max_redirects" type="number" min="0" max="10" value="${Number(s.max_redirects)}" required /></label>
      <label class="config-row"><span><b>Phishing and brand heuristics</b><small>Selected URL, credential form, and redirect heuristics. This is a weak signal and does not determine the score.</small></span><input class="switch" name="phishing_heuristics_enabled" type="checkbox" ${s.phishing_heuristics_enabled?'checked':''} /></label>
      <label class="config-row"><span><b>Optional AI page analysis</b><small>Uses the configured AI provider when available. AI observations do not change the trust score.</small></span><input class="switch" name="ai_content_analysis_enabled" type="checkbox" ${s.ai_content_analysis_enabled?'checked':''} /></label>
      <div class="dialog-footer"><button class="button primary" type="submit">Save runtime configuration</button></div></section>
      <section class="config-card"><h2>Fixed and unavailable checks</h2><p>These values describe actual deployment capabilities. Settings unavailable at runtime are not presented as active switches.</p>${data.fixed_checks.map((item) => `<div class="config-row"><span><b>${h(item)}</b><small>Enabled and enforced by the scanner implementation</small></span>${statusPill('Enabled')}</div>`).join('')}${data.unavailable.map((item) => `<div class="config-row"><span><b>${h(item.split(' (')[0])}</b><small>${h(item.includes('(')?item.slice(item.indexOf('(')+1,-1):'Provider not configured')}</small></span>${statusPill('Unavailable')}</div>`).join('')}<div class="notice warning">Changing deployment rate limits requires backend hosting configuration. WHOIS and external threat feeds are not configured; those values cannot be verified.</div></section></form>`;
}

async function loadAi() {
  const [data, evaluation] = await Promise.all([api('/api/admin/ai'), api('/api/admin/ai/evaluation').catch(() => null)]); state.evaluation = evaluation;
  const counts = data.counts || {}; const feedback = data.feedback || {}; const labels = data.human_labels || {};
  const provider = data.provider || {}; const runs = data.recent_runs || [];
  const rows = runs.map((r) => `<tr><td data-label="Analysis"><strong>${h(r.analysis_type.replaceAll('_',' '))}</strong><span class="cell-secondary">${h(r.resource_type)} #${Number(r.resource_id)} · ${h(r.domain)}</span></td><td data-label="Provider">${h(r.provider || 'none')}</td><td data-label="Model">${h(r.model || 'Not recorded')}<span class="cell-secondary">${h(r.model_version || 'unknown')}</span></td><td data-label="Status">${statusPill(r.status)}</td><td data-label="Consent">${r.user_consented ? 'Granted' : 'Not applicable'}</td><td data-label="Date">${h(date(r.created_at))}</td></tr>`).join('');
  const evalValues = evaluation && typeof evaluation === 'object' ? Object.entries(evaluation).filter(([,v]) => typeof v !== 'object').slice(0,8).map(([key,value]) => `<div class="kv"><span>${h(key.replaceAll('_',' '))}</span><b>${h(value)}</b></div>`).join('') : '<div class="notice">No evaluation metrics are available. Add human-reviewed evaluation labels and available model predictions to calculate metrics.</div>';
  $('#page-content').innerHTML = `${pageHeading('AI GOVERNANCE','AI & model evaluation','Provider provenance, human feedback, and available evaluation results. AI predictions stay separate from moderator decisions.')}
    <div class="grid metric-grid">${metric('AI ANALYSIS RUNS',counts.total_runs,'Recorded model analysis runs','✳','ai')}${metric('PROVIDERS USED',counts.providers,'Distinct stored provider names','◇','ai')}${metric('HUMAN FEEDBACK',feedback.total || 0,'Accept/reject decisions recorded','✓','ai')}${metric('ACCEPTED FEEDBACK',feedback.accepted || 0,'Moderator-accepted findings','＋','ai',{},'good')}${metric('HUMAN LABELS',labels.total || 0,'Curated report outcomes','▤','ai')}</div>
    <div class="grid two-col" style="margin-bottom:14px"><section class="config-card"><h2>Configured provider</h2><p>Live provider status from the backend. No model accuracy is inferred from run counts.</p><div class="kv-grid"><div class="kv"><span>Status</span><b>${h(provider.status || 'unknown')}</b></div><div class="kv"><span>Provider</span><b>${h(provider.provider || 'Not configured')}</b></div><div class="kv"><span>Model</span><b>${h(provider.model || 'Not configured')}</b></div><div class="kv"><span>Latest recorded analysis</span><b>${h(counts.latest_run ? date(counts.latest_run) : 'None')}</b></div></div><div class="notice info" style="margin-top:12px">AI output is an unverified observation. Human review status and AI output are stored separately.</div></section><section class="config-card"><div class="panel-heading"><div><h2>Held-out evaluation</h2><p>Computed from human labels in the evaluation partition</p></div></div><div class="kv-grid">${evalValues}</div></section></div>
    <section class="table-panel"><div class="table-toolbar"><div><strong>Recent model runs</strong><div class="field-help">Stored provider and model provenance; inputs are not shown.</div></div></div>${tableShell(rows,'No AI runs have been recorded.',['Analysis','Provider','Model / version','Run status','Consent','Created'])}</section>`;
}

async function loadAudit() {
  state.limit = 50; const data = await api(`/api/admin/audit?${queryString()}`); state.currentRows = data.events || [];
  const rows = state.currentRows.map((e) => `<tr><td data-label="Time"><span class="cell-primary">${h(date(e.created_at))}</span></td><td data-label="Administrator">${h(e.actor_name || 'System')}</td><td data-label="Action">${h(e.action || e.event_type)}</td><td data-label="Resource">${h(e.resource_type)} <span class="mono">${h(e.resource_id)}</span></td><td data-label="Previous / new"><details><summary class="icon-link">Inspect values</summary><div class="kv-grid" style="margin-top:8px"><div class="kv"><span>Previous</span><b>${h(e.previous_json || '{}')}</b></div><div class="kv"><span>New</span><b>${h(e.new_json || '{}')}</b></div></div>${e.metadata_json && e.metadata_json !== '{}' ? `<div class="kv" style="margin-top:7px"><span>Metadata</span><b>${h(e.metadata_json)}</b></div>` : ''}</details></td></tr>`).join('');
  $('#page-content').innerHTML = `${pageHeading('COMPLIANCE','Audit trail','Append-only administrator actions, moderation decisions, incident events, and AI feedback.')}
    <div class="table-panel">${filterBar()}${tableShell(rows,'No audit events match this search.',['Timestamp','Actor','Action','Resource','Recorded changes'])}${pager(data.total)}</div>`;
}

async function ensureAdmins() { if (!state.admins.length) { const result = await api('/api/admin/users?status=active&limit=100'); state.admins = (result.users || []).filter((u) => u.role === 'admin'); } return state.admins; }
function adminOptions(current = '') { return `<option value="">Unassigned</option>${state.admins.map((u) => `<option value="${Number(u.id)}" ${String(u.id) === String(current) ? 'selected' : ''}>${h(u.name)} · ${h(u.email)}</option>`).join('')}`; }
function showDialog(html) { const dialog = $('#admin-dialog'); dialog.innerHTML = html; if (!dialog.open) dialog.showModal(); }
function closeDialog() { const dialog = $('#admin-dialog'); if (dialog.open) dialog.close(); }
function dialogHead(kicker, title) { return `<div class="dialog-head"><div><span class="eyebrow">${h(kicker)}</span><h2>${h(title)}</h2></div><button class="dialog-close" data-action="close-dialog" aria-label="Close dialog">×</button></div>`; }

function renderAiPanel(details, reportId) {
  const ai = details && details.ai_analysis;
  const rid = Number(reportId);
  if (!ai || typeof ai !== 'object') {
    return `<section class="dialog-section"><details><summary style="cursor:pointer"><h3 style="display:inline">AI Investigation Assistance</h3></summary>
      <p class="field-help" style="margin-bottom:10px">No AI analysis has been run yet for this report. If the reporter consented to AI analysis, you can request it below.</p>
      <button class="button primary" data-action="run-ai-analysis" data-id="${rid}" data-busy="false">Request AI Analysis</button>
    </details></section>`;
  }

  // 1. Triage assessment
  const triage = ai.triage || {};
  const triageHtml = triage.label
    ? `<div class="kv-grid" style="margin-bottom:10px"><div class="kv"><span>Triage category</span><b>${h(triage.label)}</b></div><div class="kv"><span>Confidence</span><b>${triage.confidence != null ? Math.round(triage.confidence * 100) + '%' : 'N/A'}</b></div><div class="kv"><span>Category alignment</span><b>${h(triage.category_alignment || 'Not assessed')}</b></div></div>`
    : '<p class="field-help">No triage assessment recorded.</p>';

  // 2. Risk indicators
  const indicators = Array.isArray(ai.risk_indicators) ? ai.risk_indicators : [];
  const indicatorsHtml = indicators.length
    ? indicators.map((ind, i) => `<div class="config-row" style="flex-direction:column;align-items:flex-start;gap:6px" data-indicator-idx="${i}">
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap"><b>${h(ind.description || ind.name || 'Indicator')}</b>${severityBadge(ind.severity)}${confidenceBar(ind.confidence)}</div>
        <div class="toolbar" style="margin-top:4px">
          <button class="button small good" data-action="ai-feedback" data-report="${rid}" data-idx="${i}" data-label="accepted" data-busy="false">✓ Accept</button>
          <button class="button small danger" data-action="ai-feedback" data-report="${rid}" data-idx="${i}" data-label="rejected" data-busy="false">✗ Reject</button>
        </div>
      </div>`).join('')
    : '<p class="field-help">No risk indicators recorded.</p>';

  // 3. Evidence extraction
  const ev = ai.evidence_extraction || ai.evidence || {};
  const entities = ev.entities || {};
  const entRows = Object.entries(entities).filter(([,v]) => v && (Array.isArray(v) ? v.length : true)).map(([key,val]) =>
    `<div class="kv"><span>${h(key.replaceAll('_',' '))}</span><b>${h(Array.isArray(val) ? val.join(', ') : String(val))}</b></div>`).join('');
  const inconsistencies = Array.isArray(ev.inconsistencies) ? ev.inconsistencies : [];
  const incHtml = inconsistencies.map((inc) => `<div class="config-row"><span>${h(inc)}</span></div>`).join('');
  const evidenceHtml = `${entRows ? `<div class="kv-grid" style="margin-bottom:10px">${entRows}</div>` : '<p class="field-help">No entities extracted.</p>'}${incHtml ? `<div style="margin-top:8px"><b style="font-size:.82em;text-transform:uppercase;color:#8ca0bb">Inconsistencies / suspicious patterns</b>${incHtml}</div>` : ''}`;

  // 4. Suggested questions
  const questions = Array.isArray(ai.suggested_questions) ? ai.suggested_questions : [];
  const questionsHtml = questions.length
    ? `<ul style="margin:0;padding-left:18px">${questions.map((q) => `<li style="margin-bottom:4px">${h(q)}</li>`).join('')}</ul>`
    : '<p class="field-help">No suggested questions recorded.</p>';

  // 5. Similar historical reports (pattern leads)
  const leads = Array.isArray(ai.pattern_leads) ? ai.pattern_leads : (Array.isArray(ai.similar_cases) ? ai.similar_cases : []);
  const leadsHtml = leads.length
    ? leads.map((lead) => `<div class="config-row" style="flex-direction:column;align-items:flex-start;gap:3px">
        <div style="display:flex;align-items:center;gap:8px"><b>TSH-${String(lead.report_id || lead.id || '?').padStart(6,'0')}</b><span class="status-pill">${Math.round((lead.similarity || lead.score || 0) * 100)}% match</span></div>
        <small style="color:#8ca0bb">${h(lead.matching_info || lead.note || lead.domain || '')}</small>
      </div>`).join('')
    : '<p class="field-help">No similar historical reports found.</p>';

  return `<section class="dialog-section"><details open><summary style="cursor:pointer">
    <h3 style="display:inline">AI Investigation Assistance <span class="status-pill warn">Automated — Not Verified</span></h3>
  </summary>
  <div class="notice info" style="margin:10px 0 14px">AI findings are unverified observations to assist your investigation. They do not constitute a determination of fraud and cannot change the report status.</div>
  <div style="margin-bottom:14px"><b style="font-size:.82em;text-transform:uppercase;color:#8ca0bb;display:block;margin-bottom:6px">Triage Assessment</b>${triageHtml}</div>
  <div style="margin-bottom:14px"><b style="font-size:.82em;text-transform:uppercase;color:#8ca0bb;display:block;margin-bottom:6px">Risk Indicators</b>${indicatorsHtml}</div>
  <div style="margin-bottom:14px"><b style="font-size:.82em;text-transform:uppercase;color:#8ca0bb;display:block;margin-bottom:6px">Evidence Extraction</b>${evidenceHtml}</div>
  <div style="margin-bottom:14px"><b style="font-size:.82em;text-transform:uppercase;color:#8ca0bb;display:block;margin-bottom:6px">Suggested Investigation Questions</b>${questionsHtml}</div>
  <div style="margin-bottom:14px"><b style="font-size:.82em;text-transform:uppercase;color:#8ca0bb;display:block;margin-bottom:6px">Similar Historical Reports</b>${leadsHtml}</div>
  <div class="toolbar" style="margin-top:10px">
    <button class="button" data-action="run-ai-analysis" data-id="${rid}" data-busy="false">↻ Refresh AI Analysis</button>
  </div>
  </details></section>`;
}

async function openReport(id) {
  try {
    const [report, details] = await Promise.all([api(`/api/admin/reports/${Number(id)}`), api(`/api/reports/${Number(id)}`)]);
    await ensureAdmins();
    const transitionOptions = (details.available_transitions || []).map((s) => `<option>${h(s)}</option>`).join('');
    const files = [`${report.evidence_name ? `<div class="config-row"><span><b>${h(report.evidence_name)}</b><small>Primary submitted evidence</small></span><button class="button small" data-action="download-evidence" data-report="${Number(id)}">Download</button></div>` : ''}`,
      ...(report.attachments || []).map((f) => `<div class="config-row"><span><b>${h(f.evidence_name)}</b><small>${h(f.mime_type)} · ${n(f.size_bytes)} bytes</small></span><button class="button small" data-action="download-attachment" data-report="${Number(id)}" data-file="${Number(f.id)}">Download</button></div>`)].join('') || '<div class="field-help">No uploaded evidence files are recorded.</div>';
    const notes = (report.notes || []).map((item) => `<div class="timeline-item"><span><b>${h(item.author_name)} · private note</b><p>${h(item.note)}</p><small>${h(date(item.created_at))}</small></span></div>`).join('') || '<div class="field-help">No internal investigation notes.</div>';
    const timeline = (report.timeline || []).map((item) => `<div class="timeline-item"><span><b>${h(item.old_status)} → ${h(item.new_status)}</b><p>${h(item.note)}</p><small>${h(item.moderator || 'Administrator')} · ${h(date(item.created_at))}</small></span></div>`).join('') || '<div class="field-help">No review status changes have been recorded.</div>';
    const safeUrl = /^https?:\/\//i.test(report.url || '') ? report.url : '';
    showDialog(`<div class="dialog-scroll" data-report-detail="${Number(id)}">${dialogHead(`REPORT TSH-${String(id).padStart(6,'0')}`,report.business || report.domain || report.url)}
      <div class="toolbar" style="margin-bottom:10px">${statusPill(report.status)}<span class="priority ${h(report.priority)}">${h(report.priority)} priority</span><span class="field-help">${h(date(report.created_at))}</span></div>
      <section class="dialog-section"><h3>Submitted information</h3><div class="kv-grid"><div class="kv"><span>Website / domain</span><b>${safeUrl ? `<a href="${h(safeUrl)}" target="_blank" rel="noopener noreferrer">${h(report.domain || report.url)} ↗</a>` : h(report.domain || report.url)}</b></div><div class="kv"><span>Category</span><b>${h(report.category)}</b></div><div class="kv"><span>Business</span><b>${h(report.business || 'Not provided')}</b></div><div class="kv"><span>Evidence triage</span><b>${h(report.evidence_analysis?.summary || 'No evidence analysis summary recorded')}</b></div></div><p style="margin:12px 0 0;color:#b9c7d9;white-space:pre-wrap">${h(report.details)}</p></section>
      <section class="dialog-section"><h3>Assignment and priority</h3><form data-form="report-assignment" data-id="${Number(id)}"><div class="grid two-col"><label class="field"><span>Assigned reviewer</span><select class="select" name="assigned_to">${adminOptions(report.assigned_to)}</select></label><label class="field"><span>Priority</span><select class="select" name="priority">${['urgent','high','normal','low'].map((p) => `<option value="${p}" ${report.priority===p?'selected':''}>${p}</option>`).join('')}</select></label></div><button class="button primary" type="submit">Save assignment</button></form></section>
      <section class="dialog-section"><h3>Evidence files</h3>${files}</section>
      <section class="dialog-section"><h3>Review status</h3><form data-form="report-status" data-id="${Number(id)}"><label class="field"><span>Available next status</span><select class="select" name="status" required>${transitionOptions || `<option value="">No status transition currently available</option>`}</select></label><label class="field"><span>Internal review reason</span><textarea class="textarea" name="note" required minlength="10" maxlength="1000" placeholder="What evidence did you review? Why does it support the decision?"></textarea></label><label class="field"><span>Reporter message (required for more information requests)</span><textarea class="textarea" name="public_message" minlength="8" maxlength="1000" placeholder="Explain what additional information would help."></textarea></label><button class="button primary" type="submit" ${transitionOptions?'':'disabled'}>Save status and notify reporter</button></form></section>
      <section class="dialog-section"><h3>Internal investigation notes</h3><div class="timeline">${notes}</div><form data-form="report-note" data-id="${Number(id)}" style="margin-top:12px"><label class="field"><span>Private note · visible only to administrators</span><textarea class="textarea" name="note" required minlength="8" maxlength="2000" placeholder="Record investigation steps. This note is not shown publicly."></textarea></label><button class="button" type="submit">Add internal note</button></form></section>
      <section class="dialog-section"><h3>Review history</h3><div class="timeline">${timeline}</div></section>
      ${report.status === 'Verified Findings' ? `<section class="dialog-section"><h3>Threat intelligence</h3><p class="field-help">Explicitly add this human-reviewed finding to the local threat database. The reporter’s allegation alone never creates a record.</p><form data-form="create-threat" data-id="${Number(id)}"><label class="field"><span>Verification basis · required</span><textarea class="textarea" name="verification_note" required minlength="20" maxlength="1200" placeholder="Summarize the evidence supporting this classification."></textarea></label><button class="button primary" type="submit">Create / re-verify threat record</button></form></section>` : ''}</div>`);
  } catch (error) { notify(error.message); }
}

async function openUser(id) {
  try {
    const data = await api(`/api/admin/users/${Number(id)}`); const u = data.user;
    const scans = data.scans.map((s) => `<div class="config-row"><span><b>${h(s.domain)} · ${h(s.label)}</b><small>${h(date(s.created_at))} · ${h(s.url)}</small></span><span class="mono">${h(s.score)}</span></div>`).join('') || '<p class="field-help">No scans are linked to this account.</p>';
    const reports = data.reports.map((r) => `<div class="config-row"><span><b>TSH-${String(r.id).padStart(6,'0')} · ${h(r.domain)}</b><small>${h(r.category)} · ${h(date(r.created_at))}</small></span>${statusPill(r.status)}</div>`).join('') || '<p class="field-help">No reports are linked to this account.</p>';
    await ensureAdmins();
    showDialog(`<div class="dialog-scroll">${dialogHead('ACCOUNT PROFILE',u.name)}<div class="kv-grid"><div class="kv"><span>Email</span><b>${h(u.email)}</b></div><div class="kv"><span>Account created</span><b>${h(date(u.created_at))}</b></div><div class="kv"><span>Current role</span><b>${h(u.role)}</b></div><div class="kv"><span>Account status</span><b>${h(u.status)}</b></div></div>
      <section class="dialog-section"><h3>Administrative access</h3><div class="toolbar"><button class="button ${u.status==='active'?'danger':'primary'}" data-action="user-status" data-id="${Number(u.id)}" data-value="${u.status==='active'?'suspended':'active'}">${u.status==='active'?'Suspend account':'Reactivate account'}</button><button class="button" data-action="user-role" data-id="${Number(u.id)}" data-value="${u.role==='admin'?'user':'admin'}">${u.role==='admin'?'Remove administrator role':'Grant administrator role'}</button></div><p class="field-help" style="margin-top:8px">Role and status changes are enforced by the backend, revoke sessions on suspension, and are recorded in the audit trail.</p></section>
      <section class="dialog-section"><h3>Recent scans</h3>${scans}</section><section class="dialog-section"><h3>Submitted complaints</h3>${reports}</section></div>`);
  } catch (error) { notify(error.message); }
}

function severityBadge(sev) {
  const s = String(sev || '').toLowerCase();
  const cls = s === 'high' || s === 'critical' ? 'bad' : s === 'moderate' || s === 'medium' ? 'warn' : '';
  return `<span class="status-pill ${cls}">${h(sev || 'low')}</span>`;
}
function confidenceBar(conf) {
  const pct = Math.min(100, Math.max(0, Math.round(Number(conf || 0) * 100)));
  return `<div style="display:flex;align-items:center;gap:8px"><div style="flex:1;background:#1e2d40;border-radius:3px;height:6px"><div style="width:${pct}%;background:#3b82f6;height:6px;border-radius:3px"></div></div><small style="min-width:34px;text-align:right">${pct}%</small></div>`;
}

async function openScan(id) {
  const scan = state.currentRows.find((item) => Number(item.id) === Number(id)); if (!scan) return;
  const checks = (scan.checks || []).map((item) => `<details class="config-row"><summary><b>${h(item.name)} · ${h(item.status)}</b><small>${h(item.explanation || '')}</small></summary><p class="field-help">Source: ${h(item.source || 'Live scan')}${item.evidence ? ` · Evidence: ${h(item.evidence)}` : ''}</p></details>`).join('') || '<p class="field-help">No check details were stored.</p>';

  // AI Content Analysis panel
  const ai = scan.ai_analysis;
  let aiSection = '';
  if (ai && typeof ai === 'object') {
    const flags = [];
    if (ai.investment_scam_language) flags.push({ label: 'Investment scam language', desc: h(ai.investment_scam_language_detail || 'Detected'), sev: 'high' });
    if (ai.urgency_pressure) flags.push({ label: 'Urgency / pressure tactics', desc: h(ai.urgency_pressure_detail || 'Detected'), sev: 'moderate' });
    if (ai.credential_harvesting) flags.push({ label: 'Credential harvesting indicators', desc: h(ai.credential_harvesting_detail || 'Detected'), sev: 'high' });
    if (ai.impersonation) flags.push({ label: 'Impersonation signals', desc: h(ai.impersonation_detail || 'Detected'), sev: 'high' });
    // Also surface any generic findings array
    const findings = Array.isArray(ai.findings) ? ai.findings : [];
    findings.forEach((f) => { if (f && f.name) flags.push({ label: h(f.name), desc: h(f.description || f.detail || ''), sev: f.severity || 'low', conf: f.confidence }); });
    const inner = flags.length
      ? flags.map((f) => `<div class="config-row" style="flex-direction:column;align-items:flex-start;gap:4px"><div style="display:flex;align-items:center;gap:8px"><b>${f.label}</b>${severityBadge(f.sev)}</div><p class="field-help" style="margin:2px 0">${f.desc}</p>${f.conf != null ? confidenceBar(f.conf) : ''}</div>`).join('')
      : '<p class="field-help">No significant AI content signals detected.</p>';
    const summary = ai.summary ? `<p style="margin:0 0 10px;color:#b9c7d9">${h(ai.summary)}</p>` : '';
    aiSection = `<section class="dialog-section"><details><summary style="cursor:pointer"><h3 style="display:inline">AI Content Analysis <span class="status-pill warn">Automated — Not Verified</span></h3></summary>${summary}${inner}</details></section>`;
  } else {
    aiSection = `<section class="dialog-section"><details><summary style="cursor:pointer"><h3 style="display:inline">AI Content Analysis</h3></summary><p class="field-help">No AI content analysis was recorded for this scan.</p></details></section>`;
  }

  // Phishing Heuristic Analysis panel
  const ph = scan.phishing_analysis;
  let phSection = '';
  if (Array.isArray(ph) && ph.length) {
    const items = ph.map((sig) => `<div class="config-row" style="flex-direction:column;align-items:flex-start;gap:4px"><div style="display:flex;align-items:center;gap:8px"><b>${h(sig.name || sig.type || 'Signal')}</b>${severityBadge(sig.severity)}</div><p class="field-help" style="margin:2px 0">${h(sig.description || sig.explanation || '')}</p>${sig.confidence != null ? confidenceBar(sig.confidence) : ''}</div>`).join('');
    phSection = `<section class="dialog-section"><details><summary style="cursor:pointer"><h3 style="display:inline">Phishing Heuristic Analysis <span class="status-pill warn">Automated — Not Verified</span></h3></summary>${items}</details></section>`;
  } else {
    phSection = `<section class="dialog-section"><details><summary style="cursor:pointer"><h3 style="display:inline">Phishing Heuristic Analysis</h3></summary><p class="field-help">No phishing heuristic signals were recorded for this scan.</p></details></section>`;
  }

  showDialog(`<div class="dialog-scroll">${dialogHead(`SCAN #${Number(id)}`,scan.domain)}<div class="kv-grid"><div class="kv"><span>Assessment</span><b>${h(scan.label)}</b></div><div class="kv"><span>Trust score</span><b>${scan.label==='Insufficient Data'?'—':h(scan.score)}</b></div><div class="kv"><span>Submitted URL</span><b>${h(scan.url)}</b></div><div class="kv"><span>Scanner version</span><b>${h(scan.scanner_version)}</b></div></div><section class="dialog-section"><h3>Recorded summary</h3><p>${h(scan.summary)}</p></section><section class="dialog-section"><h3>Technical checks (${(scan.checks||[]).length})</h3>${checks}</section>${aiSection}${phSection}<div class="notice info" style="margin-top:12px">Technical risk labels describe observed page security signals. They are not proof that a seller is fraudulent.</div></div>`);
}

async function reviewThreat(id, currentStatus) {
  const item = state.currentRows.find((t) => Number(t.id) === Number(id));
  showDialog(`<div class="dialog-scroll">${dialogHead('THREAT REVIEW',item?.domain || `Record #${id}`)}<p class="field-help">Source report #${Number(item?.source_report_id || 0)} · ${h(item?.category || '')} · current status: ${h(currentStatus)}</p><form data-form="threat-review" data-id="${Number(id)}"><label class="field"><span>Classification</span><select class="select" name="status"><option value="verified" ${currentStatus==='verified'?'selected':''}>Verified threat</option><option value="false_positive" ${currentStatus==='false_positive'?'selected':''}>False positive</option></select></label><label class="field"><span>Review note · required</span><textarea class="textarea" name="note" minlength="10" maxlength="1200" required placeholder="Record the basis for this review."></textarea></label><div class="dialog-footer"><button class="button primary" type="submit">Save review</button></div></form></div>`);
}

async function createIncidentDialog() {
  await ensureAdmins();
  showDialog(`<div class="dialog-scroll">${dialogHead('NEW CASE','Create incident')}<form data-form="incident-create"><label class="field"><span>Incident title</span><input class="input" name="title" minlength="5" maxlength="160" required placeholder="Concise investigation summary" /></label><div class="grid two-col"><label class="field"><span>Severity</span><select class="select" name="severity"><option>low</option><option selected>medium</option><option>high</option><option>critical</option></select></label><label class="field"><span>Assigned administrator</span><select class="select" name="assigned_to">${adminOptions(state.user.id)}</select></label></div><label class="field"><span>Linked complaint IDs (optional, comma separated)</span><input class="input" name="report_ids" placeholder="e.g. 12, 18" /><small class="field-help">Only existing report IDs are accepted; maximum 20.</small></label><label class="field"><span>Initial note</span><textarea class="textarea" name="note" maxlength="2000" placeholder="Context or response notes"></textarea></label><div class="dialog-footer"><button class="button primary" type="submit">Create incident</button></div></form></div>`);
}

async function openIncident(id) {
  try {
    const [incident] = await Promise.all([api(`/api/admin/incidents/${Number(id)}`), ensureAdmins()]);
    const events = (incident.events || []).map((e) => `<div class="timeline-item"><span><b>${h(e.event_type.replaceAll('.',' '))} · ${h(e.actor_name || 'Administrator')}</b><p>${h(e.note || '')}${e.new_json && e.new_json !== '{}' ? ` ${h(e.new_json)}` : ''}</p><small>${h(date(e.created_at))}</small></span></div>`).join('') || '<p class="field-help">No investigation events recorded.</p>';
    const linked = (incident.reports || []).map((r) => `<button class="button small" data-action="open-report" data-id="${Number(r.id)}">TSH-${String(r.id).padStart(6,'0')} · ${h(r.domain)} · ${h(r.status)}</button>`).join(' ') || '<p class="field-help">No reports linked to this incident.</p>';
    showDialog(`<div class="dialog-scroll">${dialogHead(`INC-${String(id).padStart(5,'0')}`,incident.title)}<p class="field-help">Created by ${h(incident.creator_name)} · ${h(date(incident.created_at))}</p><section class="dialog-section"><h3>Linked complaints</h3><div class="toolbar">${linked}</div></section><section class="dialog-section"><h3>Case controls</h3><form data-form="incident-update" data-id="${Number(id)}"><div class="grid two-col"><label class="field"><span>Status</span><select class="select" name="status">${['new','investigating','contained','resolved','closed'].map((s)=>`<option ${s===incident.status?'selected':''}>${s}</option>`).join('')}</select></label><label class="field"><span>Severity</span><select class="select" name="severity">${['low','medium','high','critical'].map((s)=>`<option ${s===incident.severity?'selected':''}>${s}</option>`).join('')}</select></label></div><label class="field"><span>Assignee</span><select class="select" name="assigned_to">${adminOptions(incident.assigned_to)}</select></label><label class="field"><span>Resolution note (required when resolving or closing)</span><textarea class="textarea" name="resolution_note" maxlength="2000">${h(incident.resolution_note || '')}</textarea></label><button class="button primary" type="submit">Update incident</button></form></section><section class="dialog-section"><h3>Investigation timeline</h3><div class="timeline">${events}</div><form data-form="incident-note" data-id="${Number(id)}" style="margin-top:12px"><label class="field"><span>Add an internal timeline note</span><textarea class="textarea" name="note" required minlength="3" maxlength="2000" placeholder="Document an investigation action or finding."></textarea></label><button class="button" type="submit">Add timeline note</button></form></section></div>`);
  } catch (error) { notify(error.message); }
}

async function downloadEvidence(button) {
  const id = Number(button.dataset.report); const file = button.dataset.file;
  const url = file ? `/api/reports/${id}/evidence/attachment/${Number(file)}` : `/api/reports/${id}/evidence`;
  try { const response = await fetch(url, { credentials: 'same-origin' }); if (!response.ok) throw new Error('Evidence download failed.'); const blob = await response.blob(); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = button.closest('.config-row')?.querySelector('b')?.textContent || 'evidence'; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); }
  catch (error) { notify(error.message); }
}

function exportCurrentPage() {
  const rows = state.currentRows || []; if (!rows.length) return notify('There are no records on this page to export.');
  const columns = state.view === 'reports' ? ['id','url','domain','business','category','status','priority','assigned_name','created_at','evidence_count'] : state.view === 'scans' ? ['id','url','domain','score','label','summary','user_email','created_at','scanner_version'] : [];
  if (!columns.length) return notify('Export is available for reports and scans.');
  const csvCell = (v) => `"${String(v ?? '').replaceAll('"','""')}"`;
  const csv = [columns.map(csvCell).join(','), ...rows.map((row) => columns.map((key) => csvCell(row[key])).join(','))].join('\r\n');
  const blob = new Blob(['\ufeff',csv], { type: 'text/csv;charset=utf-8' }); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `trustshield-${state.view}-${new Date().toISOString().slice(0,10)}.csv`; a.click(); setTimeout(() => URL.revokeObjectURL(a.href),1000);
}

$('#page-content').addEventListener('click', async (event) => {
  const link = event.target.closest('[data-action]'); if (!link) return; const action = link.dataset.action;
  if (action === 'reload') loadView();
  if (action === 'page') { state.page = Math.max(1, Number(link.dataset.page)); loadView(); }
  if (action === 'metric') { const filters = JSON.parse(link.dataset.filters || '{}'); go(link.dataset.go, filters); }
  if (action === 'export') exportCurrentPage();
  if (action === 'open-report') openReport(link.dataset.id);
  if (action === 'open-scan') openScan(link.dataset.id);
  if (action === 'open-user') openUser(link.dataset.id);
  if (action === 'review-threat') reviewThreat(link.dataset.id, link.dataset.status);
  if (action === 'create-incident') createIncidentDialog();
  if (action === 'open-incident') openIncident(link.dataset.id);
});

$('#admin-dialog').addEventListener('click', async (event) => {
  const button = event.target.closest('[data-action]'); if (!button) return;
  if (button.dataset.action === 'close-dialog') closeDialog();
  if (button.dataset.action === 'download-evidence' || button.dataset.action === 'download-attachment') downloadEvidence(button);
  if (button.dataset.action === 'open-report') openReport(button.dataset.id);
  if (button.dataset.action === 'user-status' || button.dataset.action === 'user-role') {
    const field = button.dataset.action === 'user-status' ? 'status' : 'role'; const value = button.dataset.value;
    if (!confirm(`Change this account's ${field} to ${value}?`)) return;
    try { await api(`/api/admin/users/${Number(button.dataset.id)}/${field}`, { method: 'PATCH', body: JSON.stringify({ [field]: value }) }); notify(`Account ${field} updated.`); closeDialog(); await loadView(); }
    catch (error) { notify(error.message); }
  }
});

$('#page-content').addEventListener('submit', async (event) => {
  const form = event.target.closest('form'); if (!form) return;
  if (form.classList.contains('filter-form')) {
    event.preventDefault(); const values = new FormData(form); state.q = String(values.get('q') || '').trim(); state.status = String(values.get('status') || ''); state.priority = String(values.get('priority') || ''); state.role = String(values.get('role') || ''); state.severity = String(values.get('severity') || ''); state.page = 1; loadView(); return;
  }
  if (form.id === 'scanner-settings') {
    event.preventDefault(); const button = form.querySelector('button[type="submit"]'); setBusy(button,true);
    const body = { request_timeout_seconds: Number(form.elements.request_timeout_seconds.value), max_redirects: Number(form.elements.max_redirects.value), phishing_heuristics_enabled: form.elements.phishing_heuristics_enabled.checked, ai_content_analysis_enabled: form.elements.ai_content_analysis_enabled.checked };
    try { await api('/api/admin/scanner/settings',{method:'PATCH',body:JSON.stringify(body)}); notify('Scanner configuration saved. It applies to subsequent scans.'); await loadScanner(); } catch (error) { notify(error.message); setBusy(button,false); }
  }
});

$('#page-content').addEventListener('change', (event) => {
  if (event.target.id === 'overview-days') {
    state.overviewDays = Number(event.target.value);
    if (![7,30,90].includes(state.overviewDays)) state.overviewDays = 30;
    loadView();
  }
});

$('#admin-dialog').addEventListener('submit', async (event) => {
  const form = event.target.closest('form[data-form]'); if (!form) return; event.preventDefault();
  const button = form.querySelector('button[type="submit"]'); const values = new FormData(form); const data = Object.fromEntries(values.entries()); const id = Number(form.dataset.id); setBusy(button,true);
  try {
    if (form.dataset.form === 'report-assignment') { data.assigned_to = data.assigned_to || null; await api(`/api/admin/reports/${id}`,{method:'PATCH',body:JSON.stringify(data)}); notify('Reviewer and priority saved.'); await openReport(id); }
    if (form.dataset.form === 'report-status') { await api(`/api/admin/reports/${id}/status`,{method:'PATCH',body:JSON.stringify(data)}); notify('Review status saved and reporter notified.'); await openReport(id); }
    if (form.dataset.form === 'report-note') { await api(`/api/admin/reports/${id}/notes`,{method:'POST',body:JSON.stringify(data)}); notify('Private investigation note added.'); await openReport(id); }
    if (form.dataset.form === 'create-threat') { await api('/api/admin/threats',{method:'POST',body:JSON.stringify({report_id:id,...data})}); notify('Human-reviewed threat record saved.'); await openReport(id); }
    if (form.dataset.form === 'threat-review') { await api(`/api/admin/threats/${id}/status`,{method:'PATCH',body:JSON.stringify(data)}); notify('Threat record review saved.'); closeDialog(); await loadView(); }
    if (form.dataset.form === 'incident-create') { data.assigned_to = data.assigned_to || null; data.report_ids = data.report_ids ? data.report_ids.split(',').map((item)=>Number(item.trim())).filter(Boolean) : []; const result = await api('/api/admin/incidents',{method:'POST',body:JSON.stringify(data)}); notify('Incident created.'); await loadView(); await openIncident(result.id); }
    if (form.dataset.form === 'incident-update') { data.assigned_to = data.assigned_to || null; await api(`/api/admin/incidents/${id}`,{method:'PATCH',body:JSON.stringify(data)}); notify('Incident updated and recorded in its timeline.'); await openIncident(id); }
    if (form.dataset.form === 'incident-note') { await api(`/api/admin/incidents/${id}/events`,{method:'POST',body:JSON.stringify(data)}); notify('Investigation timeline updated.'); await openIncident(id); }
  } catch (error) { notify(error.message); setBusy(button,false); }
});

$('#mobile-nav').addEventListener('click', () => { const open = $('#sidebar').classList.toggle('open'); $('#sidebar-scrim').classList.toggle('open',open); $('#mobile-nav').setAttribute('aria-expanded',String(open)); });
$('#sidebar-scrim').addEventListener('click', () => { $('#sidebar').classList.remove('open'); $('#sidebar-scrim').classList.remove('open'); $('#mobile-nav').setAttribute('aria-expanded','false'); });
$('.side-nav').addEventListener('click', (event) => { if (event.target.closest('[data-view]')) { state.page=1; state.q=''; state.status=''; state.priority=''; state.role=''; state.severity=''; $('#sidebar').classList.remove('open'); $('#sidebar-scrim').classList.remove('open'); } });
$('#sign-out').addEventListener('click', async () => { try { await api('/api/auth/logout',{method:'POST',body:'{}'}); } catch {} location.href = '/'; });

async function boot() {
  try {
    state.user = await api('/api/auth/me');
    if (state.user.role !== 'admin' || state.user.status !== 'active') throw new Error('This workspace is limited to active administrator accounts.');
    $('#admin-name').textContent = state.user.name || 'Administrator'; $('#admin-email').textContent = state.user.email || ''; $('#admin-avatar').textContent = (state.user.name || state.user.email || 'A').trim().charAt(0).toUpperCase();
    state.view = setViewFromHash(); await loadView();
  } catch (error) { $('#access-message').textContent = error.message.includes('not found') ? 'The administrator API is not connected to this static deployment. Host the TrustShield backend and configure a same-origin API route before sign in and admin workflows can work here.' : error.message; $('#access-wall').hidden = false; }
}
window.addEventListener('hashchange', () => { state.page = 1; loadView(); });
boot();
