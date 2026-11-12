const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const state = { user: null, scans: [], reports: [], ownReports: [], activityTab: 'scans', search: '', filter: 'all', toastTimer: null };
const statuses = ['Submitted', 'Under Review', 'Evidence Requested', 'Partially Verified', 'Verified', 'Rejected', 'Disputed'];

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
  const guestTokens = storedGuestReports().map((item) => item.token).join(',');
  const response = await fetch(path, { credentials: 'same-origin', ...options,
    headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(guestTokens ? { 'X-TrustShield-Guest-Tokens': guestTokens } : {}), ...(options.headers || {}) } });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status}).`);
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
  if (check.status === 'positive') return 'positive';
  if (check.status === 'warning' || check.status === 'caution') return 'warning';
  if (check.status === 'negative') return 'negative';
  return 'unknown';
}

function riskNextStep(label) {
  if (label === 'Critical Risk' || label === 'High Risk') return 'Pause before buying. Do not enter passwords, payment information, or identity documents. Search for the business through independent sources and contact it using details you find elsewhere.';
  if (label === 'Insufficient Data') return 'We could not get enough evidence. Try again later, and verify the business using an independent contact method before sharing information.';
  if (label === 'Moderate Risk') return 'Read the full return policy, check independent seller reviews, and confirm contact details using a source outside this website before paying.';
  return 'Use a payment method with buyer protection, read the full terms, and verify the seller. These checks cannot guarantee a safe transaction.';
}

function renderResult(result) {
  const area = $('#results-section');
  const circumference = 264;
  const progress = result.label === 'Insufficient Data' ? 0 : Math.round((result.score / 100) * circumference);
  const scoreColor = result.label === 'Low Risk' ? 'score-green' : ['High Risk', 'Critical Risk'].includes(result.label) ? 'score-red' : result.label === 'Moderate Risk' ? 'score-amber' : 'score-blue';
  const checks = (result.checks || []).map((check) => `
    <article class="check-card"><span class="check-mark ${checkClass(check)}">${check.status === 'positive' ? '✓' : check.status === 'unknown' ? '—' : '!'}</span>
      <div><b>${escapeHtml(check.name)}</b><p>${escapeHtml(check.detail)}</p><small>Source: ${escapeHtml(check.source || 'Live scan')}${check.impact ? ` · Risk signal: +${Number(check.impact)}` : ''}</small></div></article>`).join('');
  const reportCount = state.reports.filter((report) => report.domain === result.domain).length;
  const recentReports = state.reports.filter((report) => report.domain === result.domain).slice(0, 3);
  $('#result-container').innerHTML = `
    <article class="result-summary"><div class="result-score"><div class="result-ring ${scoreColor}"><svg viewBox="0 0 100 100"><circle class="ring-track" cx="50" cy="50" r="42"/><circle class="ring-progress" cx="50" cy="50" r="42" style="stroke-dasharray:${progress} ${circumference}"/></svg><div><strong>${result.label === 'Insufficient Data' ? '—' : escapeHtml(result.score)}</strong><small>trust score</small></div></div><div class="result-score-copy"><span class="risk-badge ${riskClass(result.label)}">${escapeHtml(result.label)}</span><span class="result-domain">${escapeHtml(result.domain)}</span><span class="result-meta">Scanned ${dateLabel(result.created_at)}</span></div></div>
    <div class="result-explanation"><strong>${escapeHtml(result.summary)}</strong><p>This transparent score starts at 100 and subtracts the weighted points shown for warning signals. Missing information is labeled unknown and does not reduce the score. External threat feeds and domain registration data are not connected in this MVP.</p><a class="method-link" href="#faq">How to read this report ↗</a><div class="result-meta">${escapeHtml(result.title || 'Page content reviewed when available')}${result.status_code ? ` · HTTP ${Number(result.status_code)}` : ''}</div></div></article>
    <div class="result-block"><div class="result-block-heading"><h3>What we checked</h3><span>${(result.checks || []).length} observations · live website response</span></div><div class="checks-grid">${checks || '<div class="activity-empty">No page checks were available for this scan.</div>'}</div></div>
    <div class="result-block"><div class="result-block-heading"><h3>Community context</h3><span>${reportCount} report${reportCount === 1 ? '' : 's'} on file · user submitted</span></div><div class="result-reports">${recentReports.length ? recentReports.map((report) => `<div class="result-community-card"><span class="status-badge status-${report.status.toLowerCase().replaceAll(' ', '-')}">${escapeHtml(report.status)}</span><strong>${escapeHtml(report.category)}</strong><small>${dateLabel(report.created_at)}</small></div>`).join('') : '<div class="activity-empty">No community reports on file for this domain. No reports does not mean there are no concerns.</div>'}</div></div>
    <div class="recommendation"><strong>What you can do next</strong><p>${escapeHtml(riskNextStep(result.label))}</p></div>`;
  area.hidden = false;
  if (!$('#scan-url').value) $('#scan-url').value = result.url;
  requestAnimationFrame(() => area.scrollIntoView({ behavior: 'smooth', block: 'start' }));
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

function reportCard(report) {
  const status = report.status || 'Submitted';
  const statusClass = `status-${status.toLowerCase().replaceAll(' ', '-')}`;
  return `<article class="report-card"><div class="report-card-top"><span class="status-badge ${statusClass}">${escapeHtml(status)}</span><span class="report-date">${dateLabel(report.created_at)}</span></div><div class="report-domain">${escapeHtml(report.business || report.domain || domainFrom(report.url))}</div><div class="report-category">${escapeHtml(report.category)}</div><p class="report-description">${escapeHtml(report.details)}</p><div class="report-card-bottom"><span>${escapeHtml(report.domain || domainFrom(report.url))}</span><button data-report-id="${Number(report.id)}">Read report ↗</button></div>${state.user?.role === 'admin' ? `<div class="moderation-controls"><label class="sr-only" for="moderate-${Number(report.id)}">Update report status</label><select id="moderate-${Number(report.id)}" data-moderate-id="${Number(report.id)}">${statuses.map((item) => `<option ${item === status ? 'selected' : ''}>${item}</option>`).join('')}</select><button data-save-status="${Number(report.id)}">Save status</button></div>` : ''}</article>`;
}

function renderReports() {
  const query = state.search.toLowerCase().trim();
  const reports = state.reports.filter((report) => {
    const searchable = `${report.url} ${report.domain} ${report.business || ''} ${report.category} ${report.details}`.toLowerCase();
    return (!query || searchable.includes(query)) && (state.filter === 'all' || report.status === state.filter);
  });
  $('#report-count').textContent = String(reports.length);
  const grid = $('#reports-grid');
  let adminPanel = $('#admin-panel');
  if (state.user?.role === 'admin' && state.adminStats) {
    if (!adminPanel) {
      adminPanel = document.createElement('div');
      adminPanel.id = 'admin-panel';
      adminPanel.className = 'admin-panel';
      $('#community').insertBefore(adminPanel, $('.community-toolbar'));
    }
    adminPanel.innerHTML = `<div><span>OPEN REVIEW QUEUE</span><b>${Number(state.adminStats.review_queue)}</b></div><div><span>VERIFIED REPORTS</span><b>${Number(state.adminStats.verified)}</b></div><div><span>COMMUNITY REPORTS</span><b>${Number(state.adminStats.reports)}</b></div><div><span>REGISTERED USERS</span><b>${Number(state.adminStats.users)}</b></div>`;
  } else if (adminPanel) adminPanel.remove();
  if (!reports.length) {
    grid.innerHTML = `<div class="empty-card"><span class="empty-illustration">◎</span><strong>${query || state.filter !== 'all' ? 'No reports match that search.' : 'Your community starts here.'}</strong><p>${query || state.filter !== 'all' ? 'Try a different website name or status filter.' : 'There are no reports yet. If something felt off, you can help others by sharing what happened.'}</p>${!query && state.filter === 'all' ? '<button class="button button-outline" id="empty-report">Submit the first report <span>↗</span></button>' : ''}</div>`;
  } else grid.innerHTML = reports.map(reportCard).join('');
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
  area.innerHTML = items.slice(0, 10).map((item) => `<div class="activity-row ${state.activityTab === 'scans' ? 'activity-scan' : 'activity-own-report'}" ${state.activityTab === 'scans' ? `data-scan-id="${Number(item.id)}"` : `data-own-report-id="${Number(item.id)}"`}><div class="activity-site"><span class="activity-site-icon">${state.activityTab === 'scans' ? '◎' : '⌘'}</span><div><b>${escapeHtml(item.domain || item.business || domainFrom(item.url))}</b><small>${escapeHtml(item.label || item.category)}</small></div></div><span class="activity-result">${escapeHtml(item.label || item.status || 'Submitted')}</span><span class="activity-time">${dateLabel(item.created_at)}</span></div>`).join('');
}

function showReport(report) {
  const dialog = document.createElement('dialog');
  dialog.className = 'modal';
  const history = (report.verification_history || []).map((item) => `<div class="verification-event"><b>${escapeHtml(item.old_status)} → ${escapeHtml(item.new_status)}</b><small>${dateLabel(item.created_at)}${item.note ? ` · ${escapeHtml(item.note)}` : ''}</small></div>`).join('');
  const canViewEvidence = Boolean(report.evidence_name) && (state.user?.role === 'admin' || state.ownReports.some((item) => item.id === report.id));
  dialog.innerHTML = `<div class="report-detail"><div class="modal-heading"><div><div class="eyebrow"><span class="eyebrow-icon">⌘</span> COMMUNITY REPORT</div><h2>${escapeHtml(report.domain || domainFrom(report.url))}</h2></div><button class="modal-close" aria-label="Close report">×</button></div><p><span class="status-badge status-${(report.status || 'Submitted').toLowerCase().replaceAll(' ', '-')}">${escapeHtml(report.status || 'Submitted')}</span> &nbsp; ${escapeHtml(report.category)} · ${dateLabel(report.created_at)}</p><p>${escapeHtml(report.details)}</p><p><b>Business name:</b> ${escapeHtml(report.business || 'Not provided')}</p><p><b>Incident date:</b> ${escapeHtml(report.incident_date || 'Not provided')}</p><p><b>Amount:</b> ${escapeHtml(report.amount || 'Not provided')}</p><p><b>Evidence:</b> ${escapeHtml(report.evidence_name || 'No attachment submitted')}</p>${canViewEvidence ? `<p><a href="#" data-evidence-id="${Number(report.id)}">Download attached evidence ↗</a></p>` : ''}<p><a href="${escapeHtml(report.url)}" target="_blank" rel="noopener noreferrer">View submitted website ↗</a></p>${history ? `<h3>Verification history</h3><div class="verification-history">${history}</div>` : ''}<p class="privacy-hint">User-submitted claim · status: ${escapeHtml(report.status || 'Submitted')}. This report does not alone establish wrongdoing.</p></div>`;
  document.body.append(dialog);
  dialog.querySelector('.modal-close').addEventListener('click', () => dialog.close());
  dialog.querySelector('[data-evidence-id]')?.addEventListener('click', async (event) => {
    event.preventDefault();
    try {
      const response = await fetch(`/api/reports/${Number(report.id)}/evidence`, { credentials: 'same-origin', headers: { 'X-TrustShield-Guest-Tokens': storedGuestReports().map((item) => item.token).join(',') } });
      if (!response.ok) throw new Error('Evidence could not be downloaded.');
      const blobUrl = URL.createObjectURL(await response.blob());
      const link = document.createElement('a');
      link.href = blobUrl;
      link.download = report.evidence_name || 'evidence';
      link.click();
      URL.revokeObjectURL(blobUrl);
    } catch (error) { toast(error.message); }
  });
  dialog.addEventListener('close', () => dialog.remove());
  dialog.addEventListener('click', (event) => { if (event.target === dialog) dialog.close(); });
  dialog.showModal();
}

async function openReportForm() {
  $('#report-error').textContent = '';
  $('#report-form').reset();
  const currentUrl = $('#scan-url').value.trim();
  if (currentUrl) $('#report-url').value = currentUrl;
  $('#report-modal').showModal();
}

async function filePayload(file) {
  if (!file) return null;
  if (file.size > 2 * 1024 * 1024) throw new Error('Choose a file smaller than 2 MB.');
  const accepted = ['image/png', 'image/jpeg', 'image/webp', 'application/pdf', 'text/plain'];
  if (!accepted.includes(file.type)) throw new Error('Use a PNG, JPG, WEBP, PDF or TXT file.');
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error('Could not read that file.'));
    reader.onload = () => resolve({ name: file.name, mime_type: file.type, data: String(reader.result).split(',')[1] });
    reader.readAsDataURL(file);
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
    const evidenceFile = $('#report-evidence').files[0];
    const payload = {
      url: $('#report-url').value.trim(), business: $('#report-business').value.trim(),
      category: $('#report-category').value, details: $('#report-details').value.trim(),
      incident_date: $('#report-date').value, amount: $('#report-amount').value.trim(),
      reference: $('#report-reference').value.trim(), links: $('#report-links').value.trim(),
      evidence_file: await filePayload(evidenceFile), agree: $('#report-agree').checked,
    };
    const result = await api('/api/reports', { method: 'POST', body: JSON.stringify(payload) });
    const guestStatusSaved = rememberGuestReport(result);
    $('#report-modal').close();
    toast(result.guest_token ? (guestStatusSaved ? 'Report saved. Track its status in My activity on this browser.' : 'Report saved, but this browser could not store its private status token.') : (result.message || 'Your report was saved for review.'));
    await loadHistory();
  } catch (error) { errorBox.textContent = error.message; }
  finally { submit.disabled = false; submit.innerHTML = '<span>Submit report</span><span>↗</span>'; }
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
    renderReports();
    renderActivity();
  } catch { renderReports(); renderActivity(); }
}

async function moderateReport(id) {
  const select = $(`[data-moderate-id="${id}"]`);
  if (!select) return;
  try {
    await api(`/api/admin/reports/${id}/status`, { method: 'PATCH', body: JSON.stringify({ status: select.value }) });
    toast('Report status updated.');
    await loadHistory();
  } catch (error) { toast(error.message); }
}

async function boot() {
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
$('#auth-form').addEventListener('submit', submitAuth);
$('#auth-switch').addEventListener('click', () => setAuthMode(state.authMode === 'login' ? 'register' : 'login'));
$$('[data-close]').forEach((button) => button.addEventListener('click', () => button.closest('dialog').close()));
$$('dialog.modal').forEach((dialog) => dialog.addEventListener('click', (event) => { if (event.target === dialog) dialog.close(); }));
$('#report-search').addEventListener('input', (event) => { state.search = event.target.value; renderReports(); });
$('#report-filter').addEventListener('change', (event) => { state.filter = event.target.value; renderReports(); });
$('#reports-grid').addEventListener('click', async (event) => {
  const cardButton = event.target.closest('[data-report-id]');
  const saveButton = event.target.closest('[data-save-status]');
  if (cardButton) {
    const id = Number(cardButton.dataset.reportId);
    try { showReport(await api(`/api/reports/${id}`)); } catch (error) { toast(error.message); }
  }
  if (saveButton) moderateReport(Number(saveButton.dataset.saveStatus));
  if (event.target.closest('#empty-report')) openReportForm();
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
  state.ownReports = [];
  renderAuth();
  renderActivity();
  toast('Signed out.');
});
$('#mobile-menu').addEventListener('click', () => {
  const open = $('#main-nav').classList.toggle('open');
  $('#mobile-menu').setAttribute('aria-expanded', String(open));
});
$$('.main-nav a').forEach((link) => link.addEventListener('click', () => { $('#main-nav').classList.remove('open'); $('#mobile-menu').setAttribute('aria-expanded', 'false'); }));
boot();
