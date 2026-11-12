const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const state = { user: null, scans: [], reports: [], ownReports: [], pendingEvidence: [], communityPage: 1, communityPages: 0, activityTab: 'scans', search: '', filter: 'all', category: 'all', sort: 'latest', notifications: [], aiStatus: null, toastTimer: null };
const statuses = ['Submitted', 'Under Review', 'More Information Required', 'Partially Supported', 'Verified Findings', 'Inconsistencies Found', 'Rejected', 'Disputed'];

function storedGuestReports() {
  try { return JSON.parse(localStorage.getItem('trustshield.guestReports') || '[]').filter((item) => item && item.token).slice(-30); }
  catch { return []; }
}

function rememberGuestReport(report) {
  if (!report?.guest_token) return false;
  try {
    const saved = storedGuestReports().filter((item) => item.id !== report.id);
    saved.push({ id: report.id, token: report.guest_token });
    localStorage.setItem('trustshield.guestReports', JSON.stringify(saved.slice(-30)));
    return true;
  } catch { return false; }
}

function escapeHtml(value = '') {
  return String(value).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}

async function api(path, options = {}) {
  const guestTokens = state.user ? '' : storedGuestReports().map((item) => item.token).join(',');
  const response = await fetch(path, { credentials: 'same-origin', ...options,
    headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(guestTokens ? { 'X-TrustShield-Guest-Tokens': guestTokens } : {}), ...(options.headers || {}) } });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = body.error || '';
    if (response.status === 404 && (!message || message === 'Not found.')) {
      throw new Error('TrustShield API not found. For local use, run `python server.py` and open http://127.0.0.1:8000. Static hosting such as Vercel serves the page only; it needs a separately hosted backend for sign in and account creation.');
    }
    throw new Error(message || `Request failed (${response.status}).`);
  }
  return body;
}

function toast(message) {
  const element = $('#toast');
  element.textContent = message;
  element.classList.add('visible');
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => element.classList.remove('visible'), 3000);
}

function dateLabel(value) {
  if (!value) return 'Date unavailable';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Date unavailable' : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' }).format(date);
}

function domainFrom(url) {
  try { return new URL(url).hostname; } catch { return url; }
}

function riskClass(label) {
  if (label === 'Low Risk') return 'risk-low';
  if (label === 'Moderate Risk') return 'risk-moderate';
  if (label === 'High Risk') return 'risk-high';
  if (label === 'Critical Risk') return 'risk-critical';
  return 'risk-insufficient';
}

function checkClass(check) {
  if (check.status === 'PASS') return 'positive';
  if (check.status === 'WARNING' || check.status === 'NOT DETECTED') return 'warning';
  if (check.status === 'FAIL') return 'negative';
  return 'unknown';
}

function riskNextStep(label) {
  if (label === 'Critical Risk' || label === 'High Risk') return 'Pause before buying. Do not enter passwords, payment information, or identity documents. Search for the business through independent sources and contact it using details you find elsewhere.';
  if (label === 'Insufficient Data') return 'We could not get enough evidence. Try again later, and verify the business using an independent contact method before sharing information.';
  if (label === 'Moderate Risk') return 'Read the full return policy, check independent seller reviews, and confirm contact details using a source outside this website before paying.';
  return 'Use a payment method with buyer protection, read the full terms, and verify the seller. These checks cannot guarantee a safe transaction.';
}

function modelConfidence(value) {
  if (!['low', 'moderate', 'high'].includes(value)) return '';
  return `<small class="ai-confidence">Model-reported confidence: ${escapeHtml(value)} · uncalibrated</small>`;
}

function renderWebsiteAi(ai) {
  if (!ai || ai.status === 'skipped') return `<section class="ai-panel"><div class="ai-panel-heading"><span class="ai-label">AI-ASSISTED ANALYSIS</span><h3>Website content intelligence</h3></div><p>${escapeHtml(ai?.message || 'No page text was available for analysis.')}</p></section>`;
  const findings = (ai.findings || []).map((item) => `<details class="ai-finding"><summary><span class="ai-severity severity-${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span><b>${escapeHtml(item.name)}</b></summary><p>${escapeHtml(item.description)}</p>${item.evidence ? `<blockquote>${escapeHtml(item.evidence)}</blockquote>` : ''}<p><b>Why it may matter:</b> ${escapeHtml(item.reasoning || '')}</p><p><b>Suggested next step:</b> ${escapeHtml(item.recommended_action || '')}</p>${modelConfidence(item.confidence)}</details>`).join('');
  const unavailable = ai.status !== 'available';
  return `<section class="ai-panel"><div class="ai-panel-heading"><span class="ai-label">AI-ASSISTED ANALYSIS</span><h3>Website content intelligence</h3><span class="ai-state ${unavailable ? 'unavailable' : ''}">${unavailable ? 'Unavailable' : 'Model-assisted'}</span></div><p>${escapeHtml(ai.summary || ai.message || '')}</p>${unavailable ? `<p class="ai-muted">${escapeHtml(ai.message || 'AI analysis is unavailable; automated security checks remain available.')}</p>` : `<div class="ai-run-meta">${escapeHtml(ai.provider)} · ${escapeHtml(ai.model)} · prompt ${escapeHtml(ai.prompt_version || 'unknown')}</div>${findings || '<p>No specific text-based signal was returned. This does not mean the site is safe.</p>'}<p class="ai-muted">${escapeHtml(ai.message || 'AI observations are not verified findings.')}</p>`}<details class="ai-limits"><summary>About this analysis</summary><p>Only bounded text from the retrieved public page was analyzed. Page content is untrusted input. Promotions and urgency are not proof of fraud; no AI result changes the trust score.</p></details></section>`;
}

function renderPhishingPanel(analysis) {
  if (!analysis) return '';
  const findings = (analysis.findings || []).map((item) => `<article class="phishing-finding"><span class="ai-severity severity-${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span><div><b>${escapeHtml(item.name)}</b><p>${escapeHtml(item.explanation)}</p>${item.evidence ? `<small>Observed: ${escapeHtml(item.evidence)}</small>` : ''}<p>${escapeHtml(item.recommended_action)}</p></div></article>`).join('');
  return `<section class="phishing-panel"><div class="ai-panel-heading"><span class="ai-label">AUTOMATED HEURISTIC</span><h3>Phishing and brand signals</h3></div>${findings || '<p>No selected URL or credential-form heuristic matched.</p>'}<p class="ai-muted">${escapeHtml(analysis.assessment || '')} ${escapeHtml(analysis.threat_intelligence?.message || 'No external threat feed was queried.')}</p></section>`;
}

function renderResult(result) {
  const area = $('#results-section');
  const circumference = 264;
  const progress = result.label === 'Insufficient Data' ? 0 : Math.round((result.score / 100) * circumference);
  const scoreColor = result.label === 'Low Risk' ? 'score-green' : ['High Risk', 'Critical Risk'].includes(result.label) ? 'score-red' : result.label === 'Moderate Risk' ? 'score-amber' : 'score-blue';
  const grouped = new Map();
  (result.findings || result.checks || []).forEach((check) => {
    if (!grouped.has(check.category || 'Other observations')) grouped.set(check.category || 'Other observations', []);
    grouped.get(check.category || 'Other observations').push(check);
  });
  const findings = [...grouped].map(([category, items]) => `<section class="finding-group"><h4>${escapeHtml(category)}</h4><div class="checks-grid">${items.map((check) => `
    <details class="check-card"><summary><span class="check-mark ${checkClass(check)}">${check.status === 'PASS' ? '✓' : ['UNKNOWN', 'NOT APPLICABLE'].includes(check.status) ? '—' : '!'}</span>
      <span class="check-title"><b>${escapeHtml(check.name)}</b><span class="finding-status status-${checkClass(check)}">${escapeHtml(check.status)}</span></span></summary>
      <p>${escapeHtml(check.explanation || check.detail || '')}</p><small>Source: ${escapeHtml(check.source || 'Live scan')}${check.score_contribution ? ` · Score impact: +${Number(check.score_contribution)} points` : ''}</small>${check.evidence ? `<small>Evidence: ${escapeHtml(check.evidence)}</small>` : ''}</details>`).join('')}</div></section>`).join('');
  $('#result-container').innerHTML = `
    <article class="result-summary"><div class="result-score"><div class="result-ring ${scoreColor}"><svg viewBox="0 0 100 100"><circle class="ring-track" cx="50" cy="50" r="42"/><circle class="ring-progress" cx="50" cy="50" r="42" style="stroke-dasharray:${progress} ${circumference}"/></svg><div><strong>${result.label === 'Insufficient Data' ? '—' : escapeHtml(result.score)}</strong><small>trust score</small></div></div><div class="result-score-copy"><span class="risk-badge ${riskClass(result.label)}">${escapeHtml(result.label)}</span><span class="result-domain">${escapeHtml(result.domain)}</span><span class="result-meta">Scanned ${dateLabel(result.created_at)}</span></div></div>
    <div class="result-explanation"><strong>${escapeHtml(result.summary)}</strong><p>Technical security signals do not establish who operates a business. Unknown or unavailable checks add no risk points. Score: 100 minus ${Number(result.calculation?.warning_points || 0)} weighted warning points; this is a prioritization aid, not a probability.</p><a class="method-link" href="#faq">How to read this report ↗</a><div class="result-meta">Scanner ${escapeHtml(result.scanner_version || 'unknown')}${result.title ? ` · ${escapeHtml(result.title)}` : ''}${result.status_code ? ` · HTTP ${Number(result.status_code)}` : ''}</div></div></article>
    <div class="result-block"><div class="result-block-heading"><h3>What we checked</h3><span>${(result.findings || result.checks || []).length} observations · expand a finding for evidence</span></div>${findings || '<div class="activity-empty">No page checks were available for this scan.</div>'}</div>
    ${renderWebsiteAi(result.ai_analysis)}
    ${renderPhishingPanel(result.phishing_analysis)}
    <div class="result-block"><div class="result-block-heading"><h3>Community activity</h3><span>Database-backed reports · allegations are not proof</span></div><div id="scan-community-activity" class="community-activity"><div class="skeleton" style="height:70px"></div></div></div>
    <div class="recommendation"><strong>What you can do next</strong><p>${escapeHtml(riskNextStep(result.label))}</p></div>`;
  area.hidden = false;
  loadDomainActivity(result.domain);
  if (!$('#scan-url').value) $('#scan-url').value = result.url;
  requestAnimationFrame(() => area.scrollIntoView({ behavior: 'smooth', block: 'start' }));
}

async function loadDomainActivity(domain) {
  const target = $('#scan-community-activity');
  if (!target) return;
  try {
    const summary = await api(`/api/community/domain/${encodeURIComponent(domain)}`);
    const statuses = Object.entries(summary.by_status || {}).map(([status, count]) => `${escapeHtml(status)}: ${Number(count)}`).join(' · ');
    target.innerHTML = `<div class="community-stat-row"><strong>${Number(summary.total)} report${summary.total === 1 ? '' : 's'} submitted</strong><span>${Number(summary.unverified_submitted || 0)} are still unverified and not shown as public report cards.</span><span>${Number(summary.under_review)} under review · ${Number(summary.partially_supported)} partially supported · ${Number(summary.verified_findings)} verified findings</span><span>${Number(summary.reviewed_evidence_reports)} contain supporting material reviewed by a moderator</span>${statuses ? `<small>${statuses}</small>` : '<small>No reviewed community reports are currently public for this domain.</small>'}</div>${(summary.reports || []).slice(0, 5).map((item) => `<button class="result-community-card" data-report-id="${Number(item.id)}"><span class="status-badge">${escapeHtml(item.status)}</span><strong>${escapeHtml(item.category)}</strong><small>${dateLabel(item.created_at)}${item.evidence_reviewed ? ' · supporting evidence reviewed' : ''}</small></button>`).join('')}`;
  } catch { target.innerHTML = '<div class="activity-empty">Community activity could not be loaded.</div>'; }
}

async function scan() {
  const input = $('#scan-url');
  const button = $('#scan-button');
  const url = input.value.trim();
  if (!url) { input.focus(); input.setCustomValidity('Enter a website address to scan.'); input.reportValidity(); return; }
  input.setCustomValidity('');
  button.disabled = true;
  button.innerHTML = '<span class="button-spinner"></span><span>Checking…</span>';
  const section = $('#results-section');
  section.hidden = false;
  $('#result-container').innerHTML = '<div class="result-summary"><div class="skeleton" style="height:95px"></div><div class="skeleton" style="height:95px"></div></div><div class="checks-grid" style="margin-top:16px"><div class="skeleton" style="height:72px"></div><div class="skeleton" style="height:72px"></div><div class="skeleton" style="height:72px"></div><div class="skeleton" style="height:72px"></div></div>';
  section.scrollIntoView({ behavior: 'smooth', block: 'start' });
  try {
    const result = await api('/api/scan', { method: 'POST', body: JSON.stringify({ url }) });
    state.scans = [result, ...state.scans.filter((item) => item.id !== result.id)].slice(0, 30);
    await loadHistory();
    renderResult(result);
  } catch (error) {
    section.hidden = true;
    toast(error.message);
    input.focus();
  } finally {
    button.disabled = false;
    button.innerHTML = '<span>Check website</span><span aria-hidden="true">↗</span>';
  }
}

function displayReportStatus(status) {
  return status === 'Submitted' ? 'Unverified Report' : status;
}

function reportCard(report) {
  const status = report.status || 'Submitted';
  const statusClass = `status-${status.toLowerCase().replaceAll(' ', '-')}`;
  const summary = report.description || report.details || '';
  return `<article class="report-card"><div class="report-card-top"><span class="status-badge ${statusClass}">${escapeHtml(displayReportStatus(status))}</span><span class="report-date">${dateLabel(report.created_at)}</span></div><div class="report-domain">${escapeHtml(report.business || report.domain || domainFrom(report.url))}</div><a class="report-url" href="${escapeHtml(report.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(report.domain || domainFrom(report.url))} ↗</a><div class="report-category">${escapeHtml(report.category)}</div><p class="report-description">${escapeHtml(summary)}</p><div class="community-card-meta"><span>${Number(report.related_count || 0)} related report${Number(report.related_count || 0) === 1 ? '' : 's'}</span><span class="evidence-chip ${report.evidence_reviewed ? 'reviewed' : ''}">${report.evidence_reviewed ? 'Supporting evidence reviewed' : report.evidence_submitted ? 'Evidence submitted' : 'No file attached'}</span></div><div class="report-card-bottom"><span>${escapeHtml(report.reference_code || `TSH-${String(report.id).padStart(6, '0')}`)}</span><button data-report-id="${Number(report.id)}">View details ↗</button></div>${state.user?.role === 'admin' ? `<div class="moderation-controls"><span>Moderator review</span><button data-review-id="${Number(report.id)}">Open review</button></div>` : '<button class="report-flag-link" data-flag-report="'+Number(report.id)+'">Report inaccurate information</button>'}</article>`;
}

function renderReports() {
  const reports = state.communityReports || [];
  $('#report-count').textContent = String(state.communityTotal || 0);
  const grid = $('#reports-grid');
  const adminPanel = $('#admin-panel');
  if (state.user?.role === 'admin' && state.adminStats) {
    if (!adminPanel) {
      const panel = document.createElement('div');
      panel.id = 'admin-panel'; panel.className = 'admin-panel';
      $('#community').insertBefore(panel, $('.community-toolbar'));
    }
    const evaluation = state.aiEvaluation?.overall;
    $('#admin-panel').innerHTML = `<div><span>TOTAL REPORTS</span><b>${Number(state.adminStats.reports)}</b></div><div><span>PENDING REVIEW</span><b>${Number(state.adminStats.review_queue)}</b></div><div><span>UNDER INVESTIGATION</span><b>${Number(state.adminStats.under_investigation)}</b></div><div><span>VERIFIED FINDINGS</span><b>${Number(state.adminStats.verified)}</b></div><div><span>DISPUTED REPORTS</span><b>${Number(state.adminStats.disputed)}</b></div><div><span>OPEN ACCURACY REQUESTS</span><b>${Number(state.adminStats.pending_flags)}</b></div><div class="ai-evaluation-stat"><span>CURATED EVALUATION CASES</span><b>${Number(state.aiEvaluation?.eligible_cases || 0)}</b><small>${evaluation?.accuracy == null ? 'Metrics need eligible human labels' : `Accuracy ${Math.round(evaluation.accuracy * 100)}% · Precision ${evaluation.precision == null ? '—' : Math.round(evaluation.precision * 100) + '%'}`}</small></div><button class="admin-export-button" id="admin-export-current" type="button" ${reports.length ? '' : 'disabled'}>Export visible page as CSV (${reports.length})</button>`;
  } else if (adminPanel) adminPanel.remove();
  if (!reports.length) {
    const hasFilters = state.search || state.filter !== 'all' || state.category !== 'all';
    grid.innerHTML = `<div class="empty-card"><span class="empty-illustration">◎</span><strong>${hasFilters ? 'No reports match those filters.' : 'Your community starts here.'}</strong><p>${hasFilters ? 'Try another website, category, or review status.' : 'Public reports appear here once they enter review. Reports are not proof of wrongdoing.'}</p>${!hasFilters ? '<button class="button button-outline" id="empty-report">Submit a report <span>↗</span></button>' : ''}</div>`;
  } else grid.innerHTML = reports.map(reportCard).join('');
  const pagination = $('#community-pagination');
  pagination.hidden = !state.communityPages || state.communityPages < 2;
  $('#community-page-label').textContent = state.communityPages ? `Page ${state.communityPage} of ${state.communityPages} · ${state.communityTotal} reports` : '';
  $('#community-prev').disabled = state.communityPage <= 1;
  $('#community-next').disabled = state.communityPage >= state.communityPages;
}

async function loadCommunity() {
  const params = new URLSearchParams({ q: state.search, status: state.filter, category: state.category, sort: state.sort, page: String(state.communityPage) });
  try {
    const result = await api(`/api/community?${params}`);
    state.communityReports = result.reports || [];
    state.communityTotal = result.total || 0;
    state.communityPages = result.pages || 0;
    const categorySelect = $('#report-category-filter');
    const selected = state.category;
    const choices = ['<option value="all">All categories</option>', ...(result.categories || []).map((category) => `<option value="${escapeHtml(category)}">${escapeHtml(category)}</option>`)];
    categorySelect.innerHTML = choices.join('');
    categorySelect.value = selected;
    renderReports();
  } catch (error) {
    $('#reports-grid').innerHTML = `<div class="empty-card"><strong>Reports could not be loaded.</strong><p>${escapeHtml(error.message)}</p><button class="button button-outline" id="retry-community">Try again</button></div>`;
  }
}

function exportAdminReports() {
  if (state.user?.role !== 'admin') return;
  const reports = state.communityReports || [];
  if (!reports.length) { toast('There are no reports on this page to export.'); return; }
  const csvCell = (value) => `"${String(value ?? '').replaceAll('"', '""')}"`;
  const rows = [
    ['Reference', 'Website', 'Business', 'Category', 'Status', 'Submitted', 'Summary', 'Related reports', 'Evidence submitted', 'Evidence reviewed'],
    ...reports.map((report) => [report.reference_code, report.url, report.business, report.category, report.status, report.created_at, report.description, report.related_count, report.evidence_submitted ? 'Yes' : 'No', report.evidence_reviewed ? 'Yes' : 'No'])
  ];
  const csv = `\uFEFF${rows.map((row) => row.map(csvCell).join(',')).join('\r\n')}`;
  const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = `trustshield-reports-page-${state.communityPage}.csv`;
  link.click();
  URL.revokeObjectURL(url);
  toast(`Exported ${reports.length} visible report${reports.length === 1 ? '' : 's'}.`);
}

async function loadAiStatus() {
  const target = $('#ai-status');
  try {
    state.aiStatus = await api('/api/ai/status');
    target.textContent = state.aiStatus.configured ? `Optional AI provider configured: ${state.aiStatus.provider} · ${state.aiStatus.model}` : 'AI provider not configured · rule-based checks remain available';
    target.title = state.aiStatus.evidence_privacy || '';
  } catch {
    state.aiStatus = { configured: false, availability: 'status unavailable' };
    target.textContent = 'AI availability could not be checked · rule-based checks remain available';
  }
}

async function loadAiEvaluation() {
  if (state.user?.role !== 'admin') { state.aiEvaluation = null; return; }
  try { state.aiEvaluation = await api('/api/admin/ai/evaluation'); }
  catch { state.aiEvaluation = null; }
}

function renderActivity() {
  const items = state.activityTab === 'scans' ? state.scans : state.ownReports;
  $('#scan-count').textContent = String(state.scans.length);
  $('#my-report-count').textContent = String(state.ownReports.length);
  const area = $('#activity-list');
  if (!items.length) {
    area.innerHTML = `<div class="activity-empty">${state.activityTab === 'scans' ? (state.user ? 'Your scans will appear here after your first check.' : 'Sign in to save scans and revisit them here.') : 'Reports submitted on this browser or while signed in will appear here.'}</div>`;
    return;
  }
  area.innerHTML = items.slice(0, 20).map((item) => {
    const report = state.activityTab === 'my-reports';
    const status = item.status || item.label || (report ? 'Submitted' : 'Insufficient Data');
    return `<button class="activity-row ${report ? 'activity-own-report' : 'activity-scan'}" ${report ? `data-own-report-id="${Number(item.id)}"` : `data-scan-id="${Number(item.id)}"`}><span class="activity-site-icon">${report ? '⌘' : '◎'}</span><span class="activity-site"><b>${escapeHtml(item.domain || item.business || domainFrom(item.url))}</b><small>${report ? escapeHtml(item.reference_code || `TSH-${String(item.id).padStart(6, '0')}`) : escapeHtml(item.label || 'Scan')}</small></span><span class="activity-result">${escapeHtml(displayReportStatus(status))}</span><span class="activity-time">${dateLabel(item.created_at)}</span>${report && item.public_update ? `<small class="activity-update">Latest update: ${escapeHtml(item.public_update)}</small>` : ''}</button>`;
  }).join('');
}

function renderDashboard() {
  const reports = state.ownReports || [];
  const summary = state.overview || {};
  $('#dashboard-overview').innerHTML = `<div><span>TOTAL SCANS</span><b>${state.user ? Number(summary.scans || 0) : '—'}</b></div><div><span>MY REPORTS</span><b>${Number(summary.reports || 0)}</b></div><div><span>AWAITING REVIEW</span><b>${Number(summary.awaiting_review || 0)}</b></div><div><span>MORE INFO REQUESTED</span><b>${Number(summary.more_information_required || 0)}</b></div>`;
  const next = reports.filter((item) => item.guidance_pending > 0 || item.status === 'More Information Required').slice(0, 4);
  $('#guidance-dashboard').innerHTML = next.length ? `<div class="guidance-dashboard-heading"><div><span class="eyebrow">YOUR NEXT ACTIONS</span><h3>Continue where you left off</h3></div></div><div class="guidance-dashboard-list">${next.map((item) => `<button data-guidance-report="${Number(item.id)}"><b>${escapeHtml(item.reference_code || '')} · ${escapeHtml(item.business || item.domain)}</b><span>${Number(item.guidance_completed || 0)} of ${Number(item.guidance_total || 0)} steps completed${item.status === 'More Information Required' ? ' · update requested' : ''}</span><i>Open report →</i></button>`).join('')}</div>` : '<div class="guidance-dashboard-empty">Your report guidance and completed actions will appear here.</div>';
}

async function loadNotifications() {
  try {
    const response = await api('/api/notifications');
    state.notifications = response.notifications || [];
    $('#notification-count').textContent = response.unread ? `${response.unread} unread update${response.unread === 1 ? '' : 's'}` : 'No unread updates';
    const list = $('#notification-list');
    list.innerHTML = state.notifications.length ? state.notifications.map((item) => `<button class="notification-item ${item.is_read ? 'read' : 'unread'}" data-notification-id="${Number(item.id)}" data-report-ref="${Number(item.report_id || 0)}"><span class="notification-dot"></span><span><b>${escapeHtml(item.title)}</b><small>${escapeHtml(item.message)}</small><time>${dateLabel(item.created_at)}</time></span>${item.is_read ? '' : '<span class="notification-new">New</span>'}</button>`).join('') : '<div class="activity-empty">Status updates for your reports will appear here.</div>';
  } catch { $('#notification-list').innerHTML = '<div class="activity-empty">Sign in or open this browser’s guest report link to view updates.</div>'; }
}

function reportTimeline(report) {
  const events = [{ old_status: '', new_status: 'Submitted', created_at: report.created_at }, ...(report.verification_history || [])];
  return events.map((event) => `<div class="timeline-event"><i></i><div><b>${escapeHtml(displayReportStatus(event.event_label || event.new_status))}</b><small>${dateLabel(event.created_at)}${event.note ? ` · ${escapeHtml(event.note)}` : ''}</small></div></div>`).join('');
}

function renderReportAi(report, isOwner, isAdmin) {
  const bundle = report.ai_analysis || {};
  const complaint = bundle.complaint || {};
  const complaintAi = complaint.ai || {};
  const local = complaint.local || {};
  const evidence = bundle.evidence || {};
  const evidenceAi = evidence.ai || {};
  const extracted = evidenceAi.status === 'available' ? evidenceAi.extracted_information : evidence.extracted_information;
  const indicators = (complaintAi.risk_indicators || []).map((item, index) => {
    const previous = (report.ai_feedback || []).filter((entry) => entry.finding_key === `risk_indicators:${index}`).at(-1);
    const previousHtml = previous ? `<p class="ai-muted">Last moderator decision: ${escapeHtml(previous.decision)}${previous.note ? ` · ${escapeHtml(previous.note)}` : ''} · ${escapeHtml(previous.moderator)}</p>` : '';
    const feedback = isAdmin && complaintAi.analysis_id ? `${previousHtml}<div class="ai-moderator-feedback"><label class="sr-only" for="ai-note-${index}">Moderator feedback note</label><input class="form-input" id="ai-note-${index}" data-ai-note placeholder="Optional moderator note" maxlength="1000"/><button type="button" data-ai-feedback="accepted" data-ai-run="${Number(complaintAi.analysis_id)}" data-ai-key="risk_indicators:${index}">Accept as useful</button><button type="button" data-ai-feedback="rejected" data-ai-run="${Number(complaintAi.analysis_id)}" data-ai-key="risk_indicators:${index}">Reject as incorrect</button></div>` : '';
    return `<details class="ai-finding"><summary><span class="ai-severity severity-${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span><b>${escapeHtml(item.name)}</b></summary><p>${escapeHtml(item.description)}</p>${item.evidence ? `<blockquote>${escapeHtml(item.evidence)}</blockquote>` : ''}<p><b>Suggested next step:</b> ${escapeHtml(item.recommended_action || '')}</p>${modelConfidence(item.confidence)}${feedback}</details>`;
  }).join('');
  const showRetry = isOwner && state.aiStatus?.configured;
  const showAdminRetry = isAdmin && report.ai_consent && state.aiStatus?.configured;
  const retry = showRetry ? `<div class="ai-consent-retry"><label class="check-label"><input type="checkbox" id="ai-retry-consent" /><span>Send report text and locally extracted evidence text after common email, phone, credential, and long-number redaction. Other sensitive details may remain, so review the report before consenting. The original files are not sent.</span></label><button class="button button-outline" type="button" id="retry-ai-analysis" disabled>Run AI-assisted analysis</button></div>` : showAdminRetry ? `<button class="button button-outline" type="button" id="retry-ai-analysis">Retry AI-assisted analysis</button>` : '';
  const entityList = extracted ? Object.entries(extracted).flatMap(([key, values]) => Array.isArray(values) && values.length ? [`<span><b>${escapeHtml(key.replaceAll('_', ' '))}:</b> ${values.map(escapeHtml).join(', ')}</span>`] : []).join('') : '';
  const missing = (complaintAi.status === 'available' ? complaintAi.missing_information : local.missing_information) || [];
  const questions = complaintAi.status === 'available' ? (complaintAi.suggested_questions || []) : [];
  const conflicts = [...(complaintAi.potential_inconsistencies || []), ...(evidence.potential_inconsistencies || [])];
  const extractionRows = (evidence.files || []).map((item) => `<span>${escapeHtml(item.name)} · ${escapeHtml(item.extraction_status)} · ${Number(item.characters_extracted)} characters</span>`).join('');
  const aiSummary = complaintAi.status === 'available' ? complaintAi.summary : (local.summary || 'AI analysis has not been run for this report.');
  const status = complaintAi.status === 'available' || evidenceAi.status === 'available' ? 'AI-assisted observations' : 'Rule-based assistance only';
  const reportLabel = isAdmin ? `<form class="ai-outcome-form" id="ai-outcome-form" data-report-id="${Number(report.id)}"><label class="field-label">Curate a human-reviewed outcome<select class="form-input" name="label"><option>confirmed malicious activity</option><option>supported complaint</option><option>insufficient evidence</option><option>inaccurate complaint</option><option>legitimate business</option><option>disputed</option><option>unresolved</option></select></label><label class="field-label">Dataset partition<select class="form-input" name="partition"><option value="unassigned">Keep outside evaluation/training</option><option value="training">Training candidate</option><option value="evaluation">Evaluation set</option></select></label><label class="field-label">Review note · required<textarea class="form-input" name="note" minlength="12" maxlength="1000" required placeholder="Summarize the human-reviewed basis for this label."></textarea></label><button class="button button-outline" type="submit">Save human label</button><small>Only reviewed cases should be labeled. Disputed and unresolved cases stay unassigned.</small></form>` : '';
  return `<section class="detail-section ai-report-panel"><div class="ai-panel-heading"><span class="ai-label">AI-ASSISTED · HUMAN REVIEW REQUIRED</span><h3>Investigation assistance</h3><span class="ai-state ${complaintAi.status === 'available' ? '' : 'unavailable'}">${status}</span></div><p class="ai-report-summary">${escapeHtml(aiSummary)}</p><p class="ai-muted">${escapeHtml(complaintAi.message || evidenceAi.message || 'Local extraction and deterministic completeness checks remain available. AI output cannot change the report status.')}</p>${complaintAi.status === 'available' ? `<div class="ai-run-meta">${escapeHtml(complaintAi.provider)} · ${escapeHtml(complaintAi.model)} · ${escapeHtml(complaintAi.model_version || 'version unknown')} · prompt ${escapeHtml(complaintAi.prompt_version || 'unknown')} · triage: ${escapeHtml(complaintAi.triage)}</div><div class="ai-observation-list">${indicators || '<p>No specific risk indicator was returned. That is not a safety determination.</p>'}</div>` : ''}${extractionRows ? `<details class="ai-details"><summary>Evidence extraction status</summary><div class="ai-extracted-list">${extractionRows}${entityList}</div><p class="ai-muted">${escapeHtml(evidence.limitations || 'OCR can be incomplete and does not prove authenticity.')}</p></details>` : ''}${conflicts.length ? `<div class="ai-warning-list"><b>Potential inconsistencies to review</b>${conflicts.map((item) => `<p>${escapeHtml(item)}</p>`).join('')}</div>` : ''}${missing.length ? `<details class="ai-details"><summary>Missing information to consider (${missing.length})</summary><ul>${missing.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul></details>` : ''}${questions.length ? `<details class="ai-details"><summary>Suggested moderator questions (${questions.length})</summary><ul>${questions.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul></details>` : ''}<details class="ai-details"><summary>Related pattern leads (${(bundle.related_patterns || []).length})</summary>${(bundle.related_patterns || []).length ? `<div>${(bundle.related_patterns || []).map((item) => `<p>Report #${Number(item.id)} · ${Math.round(Number(item.similarity) * 100)}% text similarity · ${escapeHtml((item.reasons || []).join(', '))}</p>`).join('')}</div>` : '<p>No likely related patterns were found by these rules. Similar reports are leads, not independent evidence.</p>'}</details>${retry}${reportLabel}<p class="ai-limits">Confidence bands are model-reported and uncalibrated. Evidence analysis does not determine authenticity or whether a complaint is true. Official status remains under human moderator control.</p></section>`;
}

function showReport(report) {
  const dialog = document.createElement('dialog');
  dialog.className = 'modal report-detail-modal';
  const isOwner = Boolean(report.is_owner);
  const isAdmin = Boolean(report.is_admin);
  const aiReportPanel = isOwner || isAdmin ? renderReportAi(report, isOwner, isAdmin) : '';
  const evidenceChecks = (report.evidence_analysis?.checks || []).map((check) => `<div class="evidence-check"><span class="evidence-check-status ${String(check.status).toLowerCase().replaceAll(' ', '-')}">${escapeHtml(check.status)}</span><div><b>${escapeHtml(check.label)}</b><p>${escapeHtml(check.explanation)}</p>${check.evidence ? `<small>${escapeHtml(check.evidence)}</small>` : ''}</div></div>`).join('');
  const guidance = report.guidance || { steps: [], resources: [], disclaimer: '' };
  const guidanceHtml = isOwner ? `<section class="detail-section guidance-section"><div class="detail-section-heading"><div><span class="eyebrow">PERSONALIZED NEXT STEPS</span><h3>What you can do now</h3></div><span class="small-muted">Check off steps as you go</span></div><div class="guidance-steps">${guidance.steps.map((step) => `<label class="guidance-step"><input type="checkbox" data-guidance-action="${escapeHtml(step.id)}" ${report.completed_guidance_actions?.includes(step.id) ? 'checked' : ''}/><span>${escapeHtml(step.text)}</span></label>`).join('')}</div><div class="official-resources">${guidance.resources.map((resource) => `<a href="${escapeHtml(resource.url)}" target="_blank" rel="noopener noreferrer"><b>${escapeHtml(resource.title)} ↗</b><small>${escapeHtml(resource.note)}</small></a>`).join('')}</div><p class="privacy-hint">${escapeHtml(guidance.disclaimer)}</p></section>` : '';
  const filesHtml = (report.evidence_files || []).map((file) => `<div class="evidence-file-row"><span>▧</span><b>${escapeHtml(file.name || 'Supporting file')}</b><button type="button" data-evidence-id="${Number(file.id)}" data-evidence-kind="${escapeHtml(file.kind)}">Download securely ↗</button></div>`).join('') || '<p>No files attached.</p>';
  const relatedHtml = (report.related_reports || []).map((item) => `<button type="button" class="related-report" data-report-id="${Number(item.id)}"><span class="status-badge">${escapeHtml(displayReportStatus(item.status))}</span><b>${escapeHtml(item.category)}</b><small>${escapeHtml(item.domain)} · ${dateLabel(item.created_at)}</small></button>`).join('') || '<p class="small-muted">No related reports are currently available.</p>';
  const followups = (report.followups || []).map((item) => `<div class="followup-entry"><b>${dateLabel(item.created_at)}</b><p>${escapeHtml(item.details)}</p>${item.evidence_name ? `<a href="#" data-followup-evidence="${Number(item.id)}">${escapeHtml(item.evidence_name)} · Download ↗</a>` : ''}</div>`).join('');
  const adminDisputes = (report.disputes || []).map((item) => `<div class="dispute-entry"><b>${escapeHtml(item.type)} · ${escapeHtml(item.status)}</b><p>${escapeHtml(item.reason)}</p>${item.contact ? `<small>Contact: ${escapeHtml(item.contact)}</small>` : ''}${item.status === 'Pending review' ? `<form class="flag-resolution-form" data-flag-id="${Number(item.id)}"><select class="form-input" name="status"><option>Actioned</option><option>No change</option><option>Needs follow-up</option></select><input class="form-input" name="reason" minlength="10" placeholder="Decision reason" required /><button class="button button-outline" type="submit">Save review</button></form>` : `<small>Decision: ${escapeHtml(item.review_note || '')}</small>`}</div>`).join('');
  const available = report.available_transitions || [];
  const reviewForm = isAdmin ? `<section class="detail-section admin-review-section"><div class="detail-section-heading"><div><span class="eyebrow">ADMIN REVIEW</span><h3>Record a review decision</h3></div></div><form id="moderation-form" data-report-id="${Number(report.id)}"><label class="field-label">New review status<select class="form-input" name="status" required>${available.map((status) => `<option>${escapeHtml(status)}</option>`).join('')}</select></label><label class="field-label">Internal reason · required<textarea class="form-input" name="note" minlength="10" maxlength="1000" placeholder="Record what was reviewed and why you chose this status." required></textarea></label><div class="public-message-wrap" hidden><label class="field-label">Message for the reporter · required<textarea class="form-input" name="public_message" minlength="8" maxlength="1000" placeholder="Tell them exactly what additional information would help."></textarea></label></div><button class="button button-primary" type="submit">Save status and notify reporter</button></form></section>` : '';
  const formsHtml = !isAdmin ? `<section class="detail-section"><h3>Request an accuracy review</h3><form class="report-feedback-form" data-kind="flags" data-report-id="${Number(report.id)}"><label class="field-label">What information may be inaccurate?<textarea class="form-input" name="reason" minlength="12" maxlength="2000" placeholder="Please explain what should be reviewed." required></textarea></label><input class="form-input" name="contact" maxlength="160" placeholder="Contact email (optional)"/><button class="button button-outline" type="submit">Send review request</button></form><form class="report-feedback-form" data-kind="disputes" data-report-id="${Number(report.id)}"><label class="field-label">Challenge this report<textarea class="form-input" name="reason" minlength="12" maxlength="2000" placeholder="Explain why you believe this report should be disputed." required></textarea></label><input class="form-input" name="contact" maxlength="160" placeholder="Business contact (optional)"/><button class="button button-outline" type="submit">Submit dispute</button></form></section>` : '';
  dialog.innerHTML = `<div class="report-detail"><div class="modal-heading"><div><div class="eyebrow"><span class="eyebrow-icon">⌘</span> REPORT ${escapeHtml(report.reference_code || '')}</div><h2>${escapeHtml(report.business || report.domain || domainFrom(report.url))}</h2><a class="report-url" href="${escapeHtml(report.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(report.url)} ↗</a></div><button class="modal-close" aria-label="Close report">×</button></div><div class="detail-status-row"><span class="status-badge status-${(report.status || 'Submitted').toLowerCase().replaceAll(' ', '-')}">${escapeHtml(displayReportStatus(report.status || 'Submitted'))}</span><span>${escapeHtml(report.category)}</span><span>${dateLabel(report.created_at)}</span></div>${report.public_update ? `<div class="public-update"><b>Latest message from the review team</b><p>${escapeHtml(report.public_update)}</p></div>` : ''}<div class="detail-two-col"><section class="detail-section"><h3>What was reported</h3><p class="detail-description">${escapeHtml(report.details || report.description || '')}</p><dl><dt>Website</dt><dd>${escapeHtml(report.url)}</dd><dt>Business</dt><dd>${escapeHtml(report.business || 'Not provided')}</dd><dt>Incident date</dt><dd>${escapeHtml(report.incident_date || 'Not provided')}</dd>${isOwner || isAdmin ? `<dt>Amount</dt><dd>${escapeHtml(report.amount || 'Not provided')}</dd><dt>Transaction reference</dt><dd>${escapeHtml(report.reference || 'Not provided')}</dd>` : ''}</dl></section><section class="detail-section"><h3>Status timeline</h3><div class="report-timeline">${reportTimeline(report)}</div></section></div><section class="detail-section"><div class="detail-section-heading"><div><span class="eyebrow">EVIDENCE REVIEW</span><h3>Evidence and consistency</h3></div><span class="evidence-chip ${report.evidence_reviewed ? 'reviewed' : ''}">${report.evidence_reviewed ? 'Supporting findings recorded' : report.evidence_submitted ? 'Submitted · not proof by itself' : 'No file submitted'}</span></div><p class="evidence-caveat">${escapeHtml(report.evidence_summary || 'Evidence authenticity and relevance require human review.')}</p><details class="evidence-details"><summary>Files and structured checks</summary><div class="evidence-files">${filesHtml}</div><div class="evidence-checks">${evidenceChecks || '<p>Basic checks were not available for this report.</p>'}</div></details>${report.evidence_analysis?.possible_duplicates?.length ? `<p class="review-caution">Possible similar reports: ${report.evidence_analysis.possible_duplicates.map((item) => `#${Number(item.id)} (${Math.round(Number(item.similarity) * 100)}% text similarity)`).join(', ')}. Similarity is a moderator lead, not proof or independent confirmation.</p>` : ''}</section>${aiReportPanel}${guidanceHtml}${isOwner && report.status === 'More Information Required' ? `<section class="detail-section"><h3>Send the review team an update</h3><form id="followup-form" data-report-id="${Number(report.id)}"><textarea class="form-input" name="details" minlength="8" maxlength="4000" required placeholder="Add the requested information or explain what you found."></textarea><label class="field-label">Attach another file (optional)<input class="form-input" name="file" type="file" accept="image/png,image/jpeg,image/webp,application/pdf,.txt" /></label><span class="field-hint" data-followup-filename>No file selected</span><p class="field-hint">Accepted formats: PNG, JPG, WEBP, PDF, TXT · Maximum 2 MB. Redact passwords, OTPs, full card numbers, and unnecessary personal details.</p><div class="form-error" role="alert"></div><button class="button button-primary" type="submit">Send additional information</button></form></section>` : ''}${followups ? `<section class="detail-section"><h3>Additional information history</h3>${followups}</section>` : ''}<section class="detail-section"><h3>Related reports <span class="small-muted">${(report.related_reports || []).length}</span></h3><div class="related-reports">${relatedHtml}</div><p class="privacy-hint">Related reports may overlap and are not treated as independent confirmation.</p></section>${isAdmin ? `<section class="detail-section"><h3>Accuracy requests and disputes</h3>${adminDisputes || '<p class="small-muted">No pending or previous requests.</p>'}</section>` : ''}${reviewForm}${formsHtml}<p class="privacy-hint">TrustShield review status reflects the information recorded in this platform. It is not a legal finding and does not guarantee recovery of money.</p></div>`;
  document.body.append(dialog);
  dialog.querySelector('.modal-close').addEventListener('click', () => dialog.close());
  dialog.addEventListener('close', () => dialog.remove());
  dialog.addEventListener('click', (event) => { if (event.target === dialog) dialog.close(); });
  dialog.querySelectorAll('[data-evidence-id]').forEach((button) => button.addEventListener('click', async () => {
    try {
      const kind = button.dataset.evidenceKind;
      const url = kind === 'submitted' ? `/api/reports/${Number(report.id)}/evidence` : kind === 'additional' ? `/api/reports/${Number(report.id)}/evidence/attachment/${Number(button.dataset.evidenceId)}` : `/api/reports/${Number(report.id)}/evidence/followup/${Number(button.dataset.evidenceId)}`;
      const response = await fetch(url, { credentials: 'same-origin', headers: { 'X-TrustShield-Guest-Tokens': storedGuestReports().map((item) => item.token).join(',') } });
      if (!response.ok) throw new Error('Evidence could not be downloaded.');
      const blobUrl = URL.createObjectURL(await response.blob());
      const link = document.createElement('a'); link.href = blobUrl; link.download = button.parentElement.querySelector('b')?.textContent || 'evidence'; link.click();
      setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
    } catch (error) { toast(error.message); }
  }));
  dialog.querySelectorAll('[data-followup-evidence]').forEach((link) => link.addEventListener('click', async (event) => {
    event.preventDefault();
    try {
      const response = await fetch(`/api/reports/${Number(report.id)}/evidence/followup/${Number(link.dataset.followupEvidence)}`, { credentials: 'same-origin', headers: { 'X-TrustShield-Guest-Tokens': storedGuestReports().map((item) => item.token).join(',') } });
      if (!response.ok) throw new Error('Evidence could not be downloaded.');
      const blobUrl = URL.createObjectURL(await response.blob()); const anchor = document.createElement('a'); anchor.href = blobUrl; anchor.download = link.textContent.replace(' · Download ↗', ''); anchor.click(); setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
    } catch (error) { toast(error.message); }
  }));
  dialog.querySelectorAll('[data-guidance-action]').forEach((checkbox) => checkbox.addEventListener('change', async () => {
    try { await api(`/api/reports/${Number(report.id)}/actions`, { method: 'POST', body: JSON.stringify({ action_id: checkbox.dataset.guidanceAction, completed: checkbox.checked }) }); }
    catch (error) { checkbox.checked = !checkbox.checked; toast(error.message); }
  }));
  dialog.querySelectorAll('[data-report-id]').forEach((button) => button.addEventListener('click', async () => {
    try { const other = await api(`/api/reports/${Number(button.dataset.reportId)}`); dialog.close(); showReport(other); }
    catch (error) { toast(error.message); }
  }));
  dialog.querySelectorAll('.report-feedback-form').forEach((form) => form.addEventListener('submit', async (event) => {
    event.preventDefault(); if (!form.reportValidity()) return;
    const body = Object.fromEntries(new FormData(form).entries());
    try { await api(`/api/reports/${Number(form.dataset.reportId)}/${form.dataset.kind}`, { method: 'POST', body: JSON.stringify(body) }); toast('Your request has been sent to the review team.'); dialog.close(); }
    catch (error) { toast(error.message); }
  }));
  const retryAiButton = dialog.querySelector('#retry-ai-analysis');
  const retryAiConsent = dialog.querySelector('#ai-retry-consent');
  retryAiConsent?.addEventListener('change', () => { retryAiButton.disabled = !retryAiConsent.checked; });
  retryAiButton?.addEventListener('click', async () => {
    if (!isAdmin && !retryAiConsent?.checked) return;
    retryAiButton.disabled = true;
    retryAiButton.textContent = 'Analyzing…';
    try {
      await api(`/api/reports/${Number(report.id)}/ai-analysis`, { method: 'POST', body: JSON.stringify({ consent: Boolean(retryAiConsent?.checked) }) });
      const refreshed = await api(`/api/reports/${Number(report.id)}`);
      dialog.close(); showReport(refreshed);
      toast('AI-assisted observations were refreshed; the report status did not change.');
    } catch (error) { toast(error.message); retryAiButton.disabled = false; retryAiButton.textContent = 'Retry AI-assisted analysis'; }
  });
  dialog.querySelectorAll('[data-ai-feedback]').forEach((button) => button.addEventListener('click', async () => {
    button.disabled = true;
    try {
      await api('/api/admin/ai/feedback', { method: 'POST', body: JSON.stringify({ run_id: Number(button.dataset.aiRun), finding_key: button.dataset.aiKey, decision: button.dataset.aiFeedback, note: button.parentElement.querySelector('[data-ai-note]')?.value || '' }) });
      button.textContent = button.dataset.aiFeedback === 'accepted' ? 'Accepted' : 'Rejected';
      toast('Moderator feedback saved.');
    } catch (error) { button.disabled = false; toast(error.message); }
  }));
  const aiOutcomeForm = dialog.querySelector('#ai-outcome-form');
  aiOutcomeForm?.addEventListener('submit', async (event) => {
    event.preventDefault(); if (!aiOutcomeForm.reportValidity()) return;
    try {
      await api(`/api/admin/reports/${Number(report.id)}/ai-outcome`, { method: 'POST', body: JSON.stringify(Object.fromEntries(new FormData(aiOutcomeForm).entries())) });
      await loadAiEvaluation(); renderReports();
      toast('Human-reviewed outcome label saved.');
    } catch (error) { toast(error.message); }
  });
  dialog.querySelector('#followup-form')?.querySelector('[name="file"]')?.addEventListener('change', (event) => {
    $('[data-followup-filename]', event.currentTarget.form).textContent = event.currentTarget.files[0]?.name || 'No file selected';
  });
  dialog.querySelector('#followup-form')?.addEventListener('submit', async (event) => {
    event.preventDefault(); const form = event.currentTarget; if (!form.reportValidity()) return;
    const error = $('.form-error', form); const file = $('input[type="file"]', form).files[0];
    try { await api(`/api/reports/${Number(form.dataset.reportId)}/followups`, { method: 'POST', body: JSON.stringify({ details: $('[name="details"]', form).value.trim(), evidence_file: await filePayload(file) }) }); toast('Your update was added to the report.'); dialog.close(); await loadHistory(); }
    catch (problem) { error.textContent = problem.message; }
  });
  const reviewFormEl = dialog.querySelector('#moderation-form');
  if (reviewFormEl) {
    const statusSelect = $('[name="status"]', reviewFormEl); const publicWrap = $('.public-message-wrap', reviewFormEl); const publicInput = $('[name="public_message"]', reviewFormEl);
    const togglePublic = () => { const needed = statusSelect.value === 'More Information Required'; publicWrap.hidden = !needed; publicInput.required = needed; };
    statusSelect.addEventListener('change', togglePublic); togglePublic();
    reviewFormEl.addEventListener('submit', async (event) => { event.preventDefault(); if (!reviewFormEl.reportValidity()) return;
      try { await api(`/api/admin/reports/${Number(report.id)}/status`, { method: 'PATCH', body: JSON.stringify(Object.fromEntries(new FormData(reviewFormEl).entries())) }); toast('Review status saved and reporter notified.'); dialog.close(); await loadHistory(); }
      catch (error) { toast(error.message); }
    });
  }
  dialog.querySelectorAll('.flag-resolution-form').forEach((form) => form.addEventListener('submit', async (event) => { event.preventDefault(); if (!form.reportValidity()) return;
    try { await api(`/api/admin/reports/${Number(report.id)}/flags/${Number(form.dataset.flagId)}`, { method: 'PATCH', body: JSON.stringify(Object.fromEntries(new FormData(form).entries())) }); toast('Review request decision saved.'); dialog.close(); await loadHistory(); }
    catch (error) { toast(error.message); }
  }));
  dialog.showModal();
}

function localDateValue(date = new Date()) {
  return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 10);
}

function setIncidentDateLimit() {
  const input = $('#report-date');
  input.max = localDateValue();
  input.setCustomValidity('');
}

async function openReportForm() {
  $('#report-error').textContent = '';
  $('#report-form').reset();
  setIncidentDateLimit();
  state.pendingEvidence = [];
  showReportStep(1);
  renderEvidenceSelection();
  $('#upload-progress').hidden = true;
  const currentUrl = $('#scan-url').value.trim();
  if (currentUrl) $('#report-url').value = currentUrl;
  $('#report-modal').showModal();
}

async function filePayload(file) {
  if (!file) return null;
  if (file.size > 2 * 1024 * 1024) throw new Error('Choose a file that is 2 MB or smaller.');
  const accepted = ['image/png', 'image/jpeg', 'image/webp', 'application/pdf', 'text/plain'];
  if (!accepted.includes(file.type)) throw new Error('Use a PNG, JPG, WEBP, PDF or TXT file.');
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error('Could not read that file.'));
    reader.onprogress = (event) => {
      if (!event.lengthComputable) return;
      const percent = Math.round((event.loaded / event.total) * 100);
      $('#upload-progress').hidden = false;
      $('#upload-progress-fill').style.width = `${percent}%`;
      $('#upload-progress-label').textContent = `Preparing file… ${percent}%`;
    };
    reader.onload = () => {
      $('#upload-progress').hidden = false;
      $('#upload-progress-fill').style.width = '100%';
      $('#upload-progress-label').textContent = 'File ready to submit';
      resolve({ name: file.name, mime_type: file.type, data: String(reader.result).split(',')[1] });
    };
    reader.readAsDataURL(file);
  });
}

function submitReportPayload(payload) {
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest();
    request.open('POST', '/api/reports');
    request.withCredentials = true;
    request.setRequestHeader('Content-Type', 'application/json');
    request.upload.onprogress = (event) => {
      if (!event.lengthComputable) return;
      const percent = Math.round((event.loaded / event.total) * 100);
      $('#upload-progress').hidden = false;
      $('#upload-progress-fill').style.width = `${percent}%`;
      $('#upload-progress-label').textContent = `Uploading… ${percent}%`;
    };
    request.onload = () => {
      let result;
      try { result = JSON.parse(request.responseText); } catch { return reject(new Error('The server returned an unreadable response.')); }
      if (request.status < 200 || request.status >= 300) return reject(new Error(result.error || 'Your report could not be submitted.'));
      $('#upload-progress-label').textContent = 'Upload complete';
      resolve(result);
    };
    request.onerror = () => reject(new Error('Network error while submitting the report.'));
    request.onabort = () => reject(new Error('Report submission was canceled.'));
    request.send(JSON.stringify(payload));
  });
}

async function submitReport(event) {
  event.preventDefault();
  const form = event.currentTarget;
  if (!form.reportValidity()) return;
  const submit = $('.submit-report', form);
  const errorBox = $('#report-error');
  submit.disabled = true;
  submit.innerHTML = '<span class="button-spinner"></span><span>Submitting…</span>';
  errorBox.textContent = '';
  try {
    const payload = {
      url: $('#report-url').value.trim(), business: $('#report-business').value.trim(),
      category: $('#report-category').value, details: $('#report-details').value.trim(),
      incident_date: $('#report-date').value, timezone_offset_minutes: new Date().getTimezoneOffset(), amount: $('#report-amount').value.trim() ? `${$('#report-currency').value} ${$('#report-amount').value.trim()}` : '',
      reference: $('#report-reference').value.trim(), links: $('#report-links').value.trim(),
      evidence_files: await Promise.all(state.pendingEvidence.map(filePayload)), agree: $('#report-agree').checked,
      ai_consent: $('#report-ai-consent').checked,
    };
    const result = await submitReportPayload(payload);
    const guestStatusSaved = rememberGuestReport(result);
    $('#report-modal').close();
    toast(result.guest_token ? (guestStatusSaved ? 'Report saved. Track its status in My activity on this browser.' : 'Report saved, but this browser could not store its private status token.') : (result.message || 'Your report was saved for review.'));
    await loadHistory();
    showReport(await api(`/api/reports/${Number(result.id)}`));
  } catch (error) { errorBox.textContent = error.message; }
  finally { submit.disabled = false; submit.innerHTML = '<span>Submit report</span><span>↗</span>'; }
}

function showReportStep(step) {
  state.reportStep = step;
  $$('[data-step]').forEach((section) => { section.hidden = Number(section.dataset.step) !== step; });
  $$('[data-progress-step]').forEach((item) => {
    const index = Number(item.dataset.progressStep);
    item.classList.toggle('active', index === step);
    item.classList.toggle('complete', index < step);
  });
  $('#report-back').hidden = step === 1;
  $('#report-next').hidden = step === 3;
  $('#report-submit').hidden = step !== 3;
  $('#report-error').textContent = '';
}

function validateReportStep(step) {
  for (const field of $$('input, select, textarea', $(`[data-step="${step}"]`))) {
    if (!field.checkValidity()) { field.reportValidity(); return false; }
  }
  return true;
}

function renderEvidenceSelection() {
  const area = $('#evidence-selection');
  if (!area) return;
  area.innerHTML = state.pendingEvidence.length ? state.pendingEvidence.map((file, index) => `<div class="evidence-file-row"><span>▧</span><b>${escapeHtml(file.name)}</b><small>${(file.size / 1024).toFixed(0)} KB</small><button type="button" data-remove-evidence="${index}" aria-label="Remove ${escapeHtml(file.name)}">Remove</button></div>`).join('') : 'No files selected';
}

function openAuth(mode = 'login') {
  state.authMode = mode;
  $('#auth-error').textContent = '';
  $('#auth-form').reset();
  setAuthMode(mode);
  $('#auth-modal').showModal();
}

function setAuthMode(mode) {
  state.authMode = mode;
  const register = mode === 'register';
  $('#auth-title').textContent = register ? 'Create your account.' : 'Welcome back.';
  $('#auth-copy').textContent = register ? 'Use an account to keep your scan and report history together.' : 'Sign in to track your scans and reports across visits.';
  $('#auth-name-wrap').hidden = !register;
  $('#auth-admin-wrap').hidden = !register;
  $('#auth-name').required = register;
  $('#auth-password').autocomplete = register ? 'new-password' : 'current-password';
  $('#auth-submit').innerHTML = `${register ? 'Create account' : 'Sign in'} <span>↗</span>`;
  $('#auth-switch').innerHTML = register ? 'Already have an account? Sign in <span>→</span>' : 'Create an account <span>→</span>';
}

async function submitAuth(event) {
  event.preventDefault();
  if (!event.currentTarget.reportValidity()) return;
  const submit = $('#auth-submit');
  submit.disabled = true;
  $('#auth-error').textContent = '';
  try {
    const register = state.authMode === 'register';
    const user = await api(register ? '/api/auth/register' : '/api/auth/login', { method: 'POST', body: JSON.stringify({ name: $('#auth-name').value.trim(), email: $('#auth-email').value.trim(), password: $('#auth-password').value, admin_token: $('#auth-admin-token').value }) });
    state.user = user;
    $('#auth-modal').close();
    renderAuth();
    await loadHistory();
    toast(`Signed in as ${user.name || user.email}.`);
  } catch (error) { $('#auth-error').textContent = error.message; }
  finally { submit.disabled = false; setAuthMode(state.authMode); }
}

function renderAuth() {
  const button = $('#auth-button');
  button.textContent = state.user ? (state.user.role === 'admin' ? 'Admin · Sign out' : `${state.user.name || 'Account'} · Sign out`) : 'Sign in';
  button.title = state.user?.email || 'Sign in';
  const dashboardLink = $('#main-nav a[data-nav="dashboard"]');
  dashboardLink.textContent = state.user?.role === 'admin' ? 'Admin review' : 'My activity';
  dashboardLink.href = state.user?.role === 'admin' ? '#community' : '#dashboard';
  renderReports();
}

async function loadHistory() {
  try {
    const history = await api('/api/history');
    state.reports = history.reports || [];
    state.scans = history.scans || [];
    state.ownReports = history.my_reports || [];
    state.adminStats = history.admin_stats || null;
    state.overview = history.overview || {};
    await loadAiEvaluation();
    renderActivity();
    renderDashboard();
    renderReports();
    await Promise.all([loadCommunity(), loadNotifications()]);
  } catch { renderReports(); renderActivity(); renderDashboard(); await Promise.all([loadCommunity(), loadNotifications()]); }
}

async function boot() {
  await loadAiStatus();
  try { state.user = await api('/api/auth/me'); } catch { state.user = null; }
  renderAuth();
  await loadHistory();
  if (location.hash.startsWith('#scan/')) {
    const domain = decodeURIComponent(location.hash.slice(6));
    if (domain && /^[a-z0-9.-]+$/i.test(domain)) { $('#scan-url').value = `https://${domain}`; scan(); }
  }
}

$('#scan-button').addEventListener('click', scan);
$('#scan-url').addEventListener('keydown', (event) => { if (event.key === 'Enter') scan(); });
$('#scan-url').addEventListener('input', (event) => event.currentTarget.setCustomValidity(''));
$('#new-scan').addEventListener('click', () => { $('#scan-url').value = ''; $('#results-section').hidden = true; $('#scan-url').focus(); });
$('#cta-scan').addEventListener('click', () => { window.scrollTo({ top: 0, behavior: 'smooth' }); setTimeout(() => $('#scan-url').focus(), 350); });
$('#open-report').addEventListener('click', openReportForm);
$('#footer-report').addEventListener('click', openReportForm);
$('#report-form').addEventListener('submit', submitReport);
$('#report-date').addEventListener('input', (event) => {
  const input = event.currentTarget;
  input.setCustomValidity(input.value && input.value > input.max ? 'Choose today or an earlier date.' : '');
});
$('#report-next').addEventListener('click', () => { if (validateReportStep(state.reportStep || 1)) showReportStep(Math.min(3, (state.reportStep || 1) + 1)); });
$('#report-back').addEventListener('click', () => showReportStep(Math.max(1, (state.reportStep || 1) - 1)));
$('#report-evidence').addEventListener('change', () => {
  const incoming = [...$('#report-evidence').files];
  const allowed = ['image/png', 'image/jpeg', 'image/webp', 'application/pdf', 'text/plain'];
  const valid = incoming.filter((file) => file.size > 0 && file.size <= 2 * 1024 * 1024 && allowed.includes(file.type));
  if (valid.length !== incoming.length) toast('Use PNG, JPG, WEBP, PDF or TXT files no larger than 2 MB each.');
  const combined = [...state.pendingEvidence, ...valid];
  const unique = combined.filter((file, index) => combined.findIndex((item) => item.name === file.name && item.size === file.size && item.lastModified === file.lastModified) === index);
  if (unique.length > 3) toast('Choose up to 3 files.');
  state.pendingEvidence = unique.slice(0, 3);
  $('#report-evidence').value = '';
  renderEvidenceSelection();
  $('#upload-progress').hidden = true;
});
$('#evidence-selection').addEventListener('click', (event) => {
  const remove = event.target.closest('[data-remove-evidence]');
  if (!remove) return;
  state.pendingEvidence.splice(Number(remove.dataset.removeEvidence), 1);
  renderEvidenceSelection();
});
$('#auth-form').addEventListener('submit', submitAuth);
$('#auth-switch').addEventListener('click', () => setAuthMode(state.authMode === 'login' ? 'register' : 'login'));
$$('[data-close]').forEach((button) => button.addEventListener('click', () => button.closest('dialog').close()));
$$('dialog.modal').forEach((dialog) => dialog.addEventListener('click', (event) => { if (event.target === dialog) dialog.close(); }));
let communitySearchTimer;
$('#report-search').addEventListener('input', (event) => { state.search = event.target.value; state.communityPage = 1; clearTimeout(communitySearchTimer); communitySearchTimer = setTimeout(loadCommunity, 180); });
$('#report-filter').addEventListener('change', (event) => { state.filter = event.target.value; state.communityPage = 1; loadCommunity(); });
$('#report-category-filter').addEventListener('change', (event) => { state.category = event.target.value; state.communityPage = 1; loadCommunity(); });
$('#report-sort').addEventListener('change', (event) => { state.sort = event.target.value; state.communityPage = 1; loadCommunity(); });
$('#community-prev').addEventListener('click', () => { if (state.communityPage > 1) { state.communityPage -= 1; loadCommunity(); } });
$('#community-next').addEventListener('click', () => { if (state.communityPage < state.communityPages) { state.communityPage += 1; loadCommunity(); } });
$('#community').addEventListener('click', (event) => { if (event.target.closest('#admin-export-current')) exportAdminReports(); });
$('#refresh-notifications').addEventListener('click', loadNotifications);
$('#notification-list').addEventListener('click', async (event) => {
  const item = event.target.closest('[data-notification-id]'); if (!item) return;
  try {
    await api(`/api/notifications/${Number(item.dataset.notificationId)}/read`, { method: 'POST', body: '{}' });
    if (Number(item.dataset.reportRef)) showReport(await api(`/api/reports/${Number(item.dataset.reportRef)}`));
    await loadNotifications();
  } catch (error) { toast(error.message); }
});
$('#guidance-dashboard').addEventListener('click', async (event) => {
  const button = event.target.closest('[data-guidance-report]'); if (!button) return;
  try { showReport(await api(`/api/reports/${Number(button.dataset.guidanceReport)}`)); }
  catch (error) { toast(error.message); }
});
$('#reports-grid').addEventListener('click', async (event) => {
  const cardButton = event.target.closest('[data-report-id]');
  const reviewButton = event.target.closest('[data-review-id]');
  const flagButton = event.target.closest('[data-flag-report]');
  if (cardButton) {
    const id = Number(cardButton.dataset.reportId);
    try { showReport(await api(`/api/reports/${id}`)); } catch (error) { toast(error.message); }
  }
  if (reviewButton || flagButton) {
    const id = Number((reviewButton || flagButton).dataset.reviewId || (reviewButton || flagButton).dataset.flagReport);
    try { showReport(await api(`/api/reports/${id}`)); } catch (error) { toast(error.message); }
  }
  if (event.target.closest('#empty-report')) openReportForm();
  if (event.target.closest('#retry-community')) loadCommunity();
});
$('#activity-list').addEventListener('click', async (event) => {
  const tab = event.target.closest('[data-tab]');
  if (tab) {
    state.activityTab = tab.dataset.tab;
    $$('.activity-tab').forEach((button) => button.classList.toggle('active', button === tab));
    renderActivity();
    return;
  }
  const row = event.target.closest('[data-scan-id]');
  if (row) {
    const result = state.scans.find((item) => item.id === Number(row.dataset.scanId));
    if (result) renderResult(result);
  }
  const ownReport = event.target.closest('[data-own-report-id]');
  if (ownReport) {
    try { showReport(await api(`/api/reports/${Number(ownReport.dataset.ownReportId)}`)); }
    catch (error) { toast(error.message); }
  }
});
$('#auth-button').addEventListener('click', async () => {
  if (!state.user) return openAuth();
  try { await api('/api/auth/logout', { method: 'POST', body: '{}' }); } catch {}
  state.user = null;
  state.scans = [];
  state.ownReports = [];
  renderAuth();
  await loadHistory();
  toast('Signed out.');
});
$('#mobile-menu').addEventListener('click', () => {
  const open = $('#main-nav').classList.toggle('open');
  $('#mobile-menu').setAttribute('aria-expanded', String(open));
});
$$('.main-nav a').forEach((link) => link.addEventListener('click', () => { $('#main-nav').classList.remove('open'); $('#mobile-menu').setAttribute('aria-expanded', 'false'); }));
boot();
