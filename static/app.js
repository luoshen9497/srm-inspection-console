const $ = selector => document.querySelector(selector);
const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const timeText = value => value ? new Date(value).toLocaleString('zh-CN', {hour12:false}) : '—';
const statusText = value => ({passed:'通过',failed:'失败',skipped:'跳过',running:'执行中'})[value] || '待执行';
const environmentText = value => value === 'production' ? '正式环境' : value || '环境未知';
const count = value => Number.isFinite(Number(value)) ? Math.max(0, Math.trunc(Number(value))) : 0;
let selectedReport = null;
let authSession = null;
let activeRun = null;
let previousCardState = null;
let configDocument = null;
let systems = [];
let selectedSystem = null;
let currentSummary = null;
let cachedChecks = [];
let currentCheckKind = 'api';
const checkViewStates = {
  api: {search:'', category:'', status:''},
  ui: {search:'', category:'', status:''},
};
let cachedReports = [];
let cachedIncidents = [];
let cachedNotifications = [];
let selectedReportData = null;
let reportCheckFilter = 'all';
let currentReportKind = 'api';
const reportViewStates = {
  api: {reports:[], selectedReport:null, selectedReportData:null, checkFilter:'all', search:'', status:'', trigger:''},
  ui: {reports:[], selectedReport:null, selectedReportData:null, checkFilter:'all', search:'', status:'', trigger:''},
};
let drawerReturnFocus = null;
let apiEditorInitialSnapshot = '';
let apiEditorTestedSnapshot = '';
let apiEditorDirty = false;
let lastCreatedCheckId = null;
const selectedApiCheckIds = new Set();
let apiChecksEnabling = false;
let analyticsRange = '12';
let settingsDirty = false;
let uiEditorDraft = null;
let uiEditorIndex = -1;
let selectedUiStepIndex = 0;
let uiEditorFullPassed = false;
let uiCapabilities = null;
let selectedRunTargets = ['api', 'ui'];
try {
  const savedRunTargets = JSON.parse(localStorage.getItem('srm-run-targets') || 'null');
  if (Array.isArray(savedRunTargets) && savedRunTargets.length && savedRunTargets.every(value => ['api', 'ui'].includes(value))) {
    selectedRunTargets = ['api', 'ui'].filter(value => savedRunTargets.includes(value));
  }
} catch { /* 使用默认执行范围 */ }

const runTargetsLabel = targets => targets.length === 2 ? 'API + UI' : targets[0]?.toUpperCase() || '巡检';
const runTargetCount = (summary, targets) => targets.reduce(
  (total, target) => total + count(summary?.enabled_checks_by_type?.[target]), 0,
);

function requestedReportDeepLink() {
  const params = new URLSearchParams(location.search);
  const system = params.get('system');
  const kind = params.get('kind');
  const run = params.get('run');
  if (params.get('view') !== 'reports' || !['api', 'ui'].includes(kind)
      || !/^[0-9TZ-]+[a-f0-9]{8}$/.test(run || '')) return null;
  return {system, kind, run};
}

function syncReportDeepLink(runId) {
  if (!runId || !selectedSystem || !['api', 'ui'].includes(currentReportKind)) return;
  const url = new URL(location.href);
  url.searchParams.set('view', 'reports');
  url.searchParams.set('system', selectedSystem);
  url.searchParams.set('kind', currentReportKind);
  url.searchParams.set('run', runId);
  history.replaceState(null, '', `${url.pathname}${url.search}${url.hash}`);
}

function clearReportDeepLink() {
  const url = new URL(location.href);
  if (url.searchParams.get('view') !== 'reports') return;
  ['view', 'system', 'kind', 'run'].forEach(key => url.searchParams.delete(key));
  history.replaceState(null, '', `${url.pathname}${url.search}${url.hash}`);
}

function selectRunTargets(targets) {
  selectedRunTargets = ['api', 'ui'].filter(value => targets.includes(value));
  try { localStorage.setItem('srm-run-targets', JSON.stringify(selectedRunTargets)); } catch { /* 仅当前页面生效 */ }
  if (currentSummary && !currentSummary.active_run_id) {
    $('#run').querySelector('span').textContent = `执行 ${runTargetsLabel(selectedRunTargets)}`;
    $('#run').disabled = runTargetCount(currentSummary, selectedRunTargets) === 0;
  }
}

function scopedApiPath(path) {
  const globalPaths = new Set(['/api/systems', '/api/overview', '/api/auth/session', '/api/auth/logout']);
  return selectedSystem && path.startsWith('/api/') && !globalPaths.has(path)
    ? `/api/systems/${encodeURIComponent(selectedSystem)}${path.slice(4)}`
    : path;
}

async function api(path, options) {
  const scoped = scopedApiPath(path);
  const method = String(options?.method || 'GET').toUpperCase();
  const headers = new Headers(options?.headers || {});
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && authSession?.csrf_token) {
    headers.set('X-CSRF-Token', authSession.csrf_token);
  }
  const response = await fetch(scoped, {cache:'no-store', ...options, headers});
  const data = await response.json().catch(() => ({}));
  if (response.status === 401) {
    const next = `${location.pathname}${location.search}${location.hash}`;
    location.replace(`/login?next=${encodeURIComponent(next)}`);
    throw new Error('登录会话已失效');
  }
  if (!response.ok) throw new Error(data.error || `请求失败：${response.status}`);
  return data;
}

async function loadAuthSession() {
  const response = await fetch('/api/auth/session', {cache:'no-store'});
  if (!response.ok) {
    const next = `${location.pathname}${location.search}${location.hash}`;
    location.replace(`/login?next=${encodeURIComponent(next)}`);
    throw new Error('登录会话已失效');
  }
  authSession = await response.json();
  const displayName = authSession.username || '管理员';
  const initial = [...displayName][0]?.toLocaleUpperCase() || 'A';
  $('#current-username').textContent = displayName;
  $('#current-username-menu').textContent = displayName;
  $('#user-avatar').textContent = initial;
  $('#user-avatar-large').textContent = initial;
}

function artifactUrl(runId, artifactId) {
  const encodedArtifact = String(artifactId || '').split('/').map(encodeURIComponent).join('/');
  return scopedApiPath(`/api/runs/${encodeURIComponent(runId)}/artifacts/${encodedArtifact}`);
}

function uiTestArtifactUrl(testId, artifactId) {
  const encodedArtifact = String(artifactId || '').split('/').map(encodeURIComponent).join('/');
  return scopedApiPath(`/api/ui/tests/${encodeURIComponent(testId)}/artifacts/${encodedArtifact}`);
}

function currentSystem() {
  return systems.find(item => item.system_id === selectedSystem) || null;
}

function syncSystemLabels() {
  const system = currentSystem();
  const name = system?.display_name || selectedSystem || 'SRM 多系统';
  $('#system-switcher-name').textContent = name;
  $('#environment').textContent = environmentText(system?.environment);
  $('#breadcrumb-system').textContent = name;
  document.title = `${name} · 巡检中心`;
  $('#overview-description').textContent = `聚合 ${name} API 与 UI 的最新健康状态和运行证据。`;
  syncCheckKindChrome();
  renderSystemOptions();
}

function renderSystemOptions() {
  $('#system-count').textContent = `共 ${systems.length} 个`;
  $('#system-options').innerHTML = systems.map(item => {
    const active = item.system_id === selectedSystem;
    const alerts = count(item.incidents?.open);
    const enabled = count(item.enabled_checks);
    const total = count(item.total_checks);
    const state = alerts ? `${alerts} 个告警` : enabled ? '运行正常' : '尚未启用';
    const stateClass = alerts ? 'has-alert' : enabled ? '' : 'is-inactive';
    return `<button class="system-option ${active ? 'active' : ''}" type="button" role="option" aria-selected="${active}" data-system-id="${escapeHtml(item.system_id)}"><span class="system-option-check">${active ? '✓' : ''}</span><span class="system-option-copy"><span class="system-option-title"><strong>${escapeHtml(item.display_name)}</strong>${active ? '<em>当前</em>' : ''}</span><small>${escapeHtml(environmentText(item.environment))} · ${enabled} / ${total} 项检查</small></span><span class="system-option-state ${stateClass}">${state}</span></button>`;
  }).join('');
  $('#system-options').querySelectorAll('[data-system-id]').forEach(button => button.addEventListener('click', () => {
    const systemId = button.dataset.systemId;
    closeSystemMenu();
    if (systemId === selectedSystem) return;
    $('#system-select').value = systemId;
    switchSystem(systemId).catch(error => notice(error.message, 'error'));
  }));
}

async function loadSystems() {
  systems = await api('/api/systems');
  if (!systems.length) throw new Error('系统注册表为空');
  const remembered = (() => { try { return localStorage.getItem('srm-system'); } catch { return null; } })();
  const linkedSystem = requestedReportDeepLink()?.system;
  if (!selectedSystem || !systems.some(item => item.system_id === selectedSystem)) {
    selectedSystem = systems.some(item => item.system_id === linkedSystem)
      ? linkedSystem : systems.some(item => item.system_id === remembered)
      ? remembered : (systems.find(item => item.default) || systems[0]).system_id;
  }
  $('#system-select').innerHTML = systems.map(item =>
    `<option value="${escapeHtml(item.system_id)}">${escapeHtml(item.display_name)}</option>`
  ).join('');
  $('#system-select').value = selectedSystem;
  syncSystemLabels();
}

async function switchSystem(systemId) {
  if (!systems.some(item => item.system_id === systemId) || systemId === selectedSystem) return;
  selectedSystem = systemId;
  try { localStorage.setItem('srm-system', systemId); } catch { /* 可在当前页面继续使用 */ }
  selectedReport = null;
  activeRun = null;
  previousCardState = null;
  configDocument = null;
  selectedApiCheckIds.clear();
  syncApiCheckSelection();
  cachedChecks = [];
  cachedReports = [];
  cachedIncidents = [];
  cachedNotifications = [];
  selectedReportData = null;
  reportCheckFilter = 'all';
  Object.values(checkViewStates).forEach(state => Object.assign(state, {search:'', category:'', status:''}));
  restoreCheckViewState();
  syncCheckKindChrome();
  Object.values(reportViewStates).forEach(state => Object.assign(state, {
    reports:[], selectedReport:null, selectedReportData:null, checkFilter:'all', search:'', status:'', trigger:'',
  }));
  restoreReportViewState();
  syncReportKindChrome();
  uiEditorDraft = null;
  uiEditorIndex = -1;
  uiEditorFullPassed = false;
  $('#system-select').value = systemId;
  $('#download-report').classList.add('hidden');
  $('#report-detail-actions').classList.add('hidden');
  $('#report-detail').className = 'empty';
  $('#report-detail').textContent = '尚未选择报告';
  syncSystemLabels();
  await Promise.all([loadSummary(), loadChecks()]);
  if (!$('#reports').classList.contains('hidden')) await loadReports();
  if (!$('#incidents').classList.contains('hidden')) await loadIncidents();
  if (!$('#settings').classList.contains('hidden')) await loadConfig();
  if (!$('#api-checks').classList.contains('hidden')) await loadConfig();
  if (!$('#ui-scenes').classList.contains('hidden')) await loadUiWorkspace();
  notice(`已切换至 ${currentSystem()?.display_name || systemId}`, 'success');
}

const messageQueue = [];
let activeMessage = null;
let messageTimer = null;

function normalizeMessageOptions(options={}) {
  const type = ['success', 'error', 'warning', 'info', 'loading'].includes(options.type) ? options.type : 'info';
  const titles = {success:'操作成功', error:'操作失败', warning:'请注意', info:'提示', loading:'处理中'};
  return {
    type,
    mode: options.mode === 'confirm' ? 'confirm' : 'message',
    title: options.title || titles[type],
    message: String(options.message || ''),
    details: options.details ? String(options.details) : '',
    meta: Array.isArray(options.meta) ? options.meta : [],
    confirmText: options.confirmText || (options.mode === 'confirm' ? '确认' : '知道了'),
    cancelText: options.cancelText || '取消',
    dismissible: options.dismissible ?? type !== 'loading',
  };
}

function renderMessageDialog(item) {
  if (activeMessage !== item) return;
  const options = item.options;
  const dialog = $('#message-dialog');
  dialog.className = `message-dialog ${options.type} ${options.mode}`;
  dialog.setAttribute('aria-busy', String(options.type === 'loading'));
  $('#message-icon').textContent = ({success:'✓', error:'!', warning:'!', info:'i', loading:''})[options.type];
  $('#message-title').textContent = options.title;
  $('#message-text').textContent = options.message;
  $('#message-close').classList.toggle('hidden', !options.dismissible);

  const meta = $('#message-meta');
  meta.replaceChildren();
  options.meta.forEach(entry => {
    const term = document.createElement('dt');
    const value = document.createElement('dd');
    term.textContent = String(entry.label || '');
    value.textContent = String(entry.value ?? '—');
    meta.append(term, value);
  });
  meta.classList.toggle('hidden', options.meta.length === 0);

  const details = $('#message-details');
  details.textContent = options.details;
  details.classList.toggle('hidden', !options.details);
  const loading = options.type === 'loading';
  $('#message-cancel').textContent = options.cancelText;
  $('#message-cancel').classList.toggle('hidden', loading || options.mode !== 'confirm');
  $('#message-confirm').textContent = options.confirmText;
  $('#message-confirm').classList.toggle('hidden', loading || options.mode !== 'confirm');
  dialog.querySelector('.message-actions').classList.toggle('hidden', options.mode !== 'confirm');

  clearTimeout(messageTimer);
  if (!loading && options.mode === 'message') {
    const delay = ({success:2600, info:3200, warning:4200, error:5200})[options.type] || 3200;
    messageTimer = setTimeout(() => {
      if (activeMessage === item && dialog.open) dialog.close('dismiss');
    }, delay);
  }
}

function presentNextMessage() {
  if (activeMessage || !messageQueue.length) return;
  activeMessage = messageQueue.shift();
  const dialog = $('#message-dialog');
  dialog.returnValue = 'cancel';
  renderMessageDialog(activeMessage);
  if (activeMessage.options.mode === 'confirm') dialog.showModal();
  else dialog.show();
}

function enqueueMessage(options) {
  const item = {options: normalizeMessageOptions(options), returnFocus: document.activeElement};
  item.promise = new Promise(resolve => { item.resolve = resolve; });
  messageQueue.push(item);
  presentNextMessage();
  return item;
}

function showMessage(options) {
  return enqueueMessage(options).promise;
}

function showConfirm(options) {
  return showMessage({...options, mode:'confirm'});
}

function showProgress(options) {
  const item = enqueueMessage({...options, type:'loading', dismissible:false});
  return {
    update(nextOptions) {
      const dismissible = Object.prototype.hasOwnProperty.call(nextOptions, 'dismissible')
        ? nextOptions.dismissible : nextOptions.type ? nextOptions.type !== 'loading' : item.options.dismissible;
      item.options = normalizeMessageOptions({...item.options, ...nextOptions, dismissible});
      renderMessageDialog(item);
    },
    close() {
      if (activeMessage === item) $('#message-dialog').close('cancel');
      else {
        const index = messageQueue.indexOf(item);
        if (index >= 0) messageQueue.splice(index, 1);
        item.resolve(false);
      }
    },
    result: item.promise,
  };
}

function notice(message, kind='success') {
  return showMessage({type: kind, message});
}

function validateForm(form) {
  const invalid = [...form.elements].find(field => typeof field.checkValidity === 'function' && !field.checkValidity());
  if (!invalid) return;
  const label = invalid.closest('label')?.querySelector(':scope > span')?.textContent?.trim() || '表单字段';
  const validity = invalid.validity;
  const reason = validity.valueMissing ? '不能为空'
    : validity.typeMismatch ? '格式不正确'
      : validity.patternMismatch ? '格式不符合要求'
        : validity.rangeUnderflow ? `不能小于 ${invalid.min}`
          : validity.rangeOverflow ? `不能大于 ${invalid.max}`
            : validity.stepMismatch ? '数值不符合步进要求'
              : '输入内容无效';
  invalid.classList.add('is-invalid');
  invalid.addEventListener('input', () => invalid.classList.remove('is-invalid'), {once:true});
  invalid.focus();
  throw new Error(`${label}${reason}`);
}

function setReportNavExpanded(expanded) {
  const group = document.querySelector('.report-nav-group');
  const button = document.querySelector('.report-nav-parent');
  group.classList.toggle('is-collapsed', !expanded);
  button.setAttribute('aria-expanded', String(expanded));
}

function setCheckNavExpanded(expanded) {
  const group = document.querySelector('.check-nav-group');
  const button = document.querySelector('.check-nav-parent');
  group.classList.toggle('is-collapsed', !expanded);
  button.setAttribute('aria-expanded', String(expanded));
}

function showView(name) {
  document.querySelectorAll('.view').forEach(view => {
    const visible = view.id === name;
    view.classList.toggle('hidden', !visible);
    if (visible) {
      view.classList.remove('is-entering');
      void view.offsetWidth;
      view.classList.add('is-entering');
    }
  });
  document.querySelectorAll('.nav').forEach(button => {
    const active = button.dataset.view === name;
    button.classList.toggle('active', active);
    if (active) button.setAttribute('aria-current', 'page');
    else button.removeAttribute('aria-current');
  });
  $('#page-name').textContent = ({overview:'运行总览',checks:currentCheckKind === 'api' ? 'API 巡检项' : 'UI 场景项',reports:currentReportKind === 'api' ? 'API 巡检报告' : 'UI 场景报告',incidents:'告警中心','api-checks':'API 巡检','ui-scenes':'UI 场景',settings:'系统设置',help:'帮助中心'})[name];
  if (name === 'checks') setCheckNavExpanded(true);
  if (name === 'reports') setReportNavExpanded(true);
  closeSystemMenu();
  closeMobileMenu();
  if (name === 'reports' && location.protocol !== 'file:') loadReports();
  if (name === 'incidents' && location.protocol !== 'file:') loadIncidents();
  if (name === 'api-checks' && location.protocol !== 'file:') loadConfig();
  if (name === 'ui-scenes' && location.protocol !== 'file:') loadUiWorkspace();
  if (name === 'settings' && location.protocol !== 'file:') loadConfig();
  if (name === 'help') window.scrollTo({top:0, behavior:'instant'});
  if (name !== 'reports') clearReportDeepLink();
}

function syncThemeButton() {
  const dark = document.documentElement.dataset.theme === 'dark';
  const button = $('#theme-toggle');
  button.setAttribute('aria-label', dark ? '切换浅色模式' : '切换深色模式');
  button.setAttribute('title', dark ? '切换浅色模式' : '切换深色模式');
  button.setAttribute('aria-pressed', String(dark));
}

const formatDuration = value => {
  const ms = Math.max(0, Number(value) || 0);
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(ms < 10000 ? 1 : 0)} s`;
  return `${Math.floor(ms / 60000)}m ${Math.round(ms % 60000 / 1000)}s`;
};

function analyticsPeriods(runs) {
  const ordered = [...(runs || [])].sort((a, b) => String(a.started_at).localeCompare(String(b.started_at)));
  const numeric = Number(analyticsRange);
  if (Number.isFinite(numeric)) {
    return {current:ordered.slice(-numeric), previous:ordered.slice(-numeric * 2, -numeric)};
  }
  const days = analyticsRange === '7d' ? 7 : 30;
  const end = Date.now();
  const start = end - days * 86400000;
  const previousStart = start - days * 86400000;
  return {
    current: ordered.filter(item => new Date(item.started_at).getTime() >= start),
    previous: ordered.filter(item => { const time = new Date(item.started_at).getTime(); return time >= previousStart && time < start; }),
  };
}

function summarizeRuns(runs) {
  const totals = runs.reduce((sum, run) => {
    sum.passed += count(run.counts?.passed);
    sum.failed += count(run.counts?.failed);
    sum.skipped += count(run.counts?.skipped);
    sum.duration += Math.max(0, Number(run.duration_ms) || 0);
    sum.failedRuns += run.status === 'failed' ? 1 : 0;
    return sum;
  }, {passed:0, failed:0, skipped:0, duration:0, failedRuns:0});
  const checks = totals.passed + totals.failed + totals.skipped;
  return {...totals, checks, passRate:checks ? totals.passed / checks * 100 : 0, averageDuration:runs.length ? totals.duration / runs.length : 0};
}

function percentageChange(current, previous) {
  return Number.isFinite(current) && Number.isFinite(previous) && previous > 0
    ? (current - previous) / previous * 100
    : NaN;
}

function changeBadge(selector, value, lowerIsBetter=false) {
  const badge = $(selector);
  if (!Number.isFinite(value)) {
    badge.textContent = '无对比';
    badge.className = 'change-badge neutral';
    return;
  }
  const good = lowerIsBetter ? value <= 0 : value >= 0;
  const displayed = Math.abs(value) < .05 ? 0 : value;
  badge.textContent = `${displayed > 0 ? '+' : ''}${displayed.toFixed(1)}%`;
  badge.className = `change-badge ${Math.abs(value) < .05 ? 'neutral' : good ? 'good' : 'bad'}`;
}

function sparkline(selector, values, tone='accent') {
  const target = $(selector);
  if (!values.length) { target.innerHTML = ''; return; }
  const width = 82, height = 30, min = Math.min(...values), max = Math.max(...values);
  const points = values.map((value, index) => {
    const x = values.length === 1 ? width / 2 : index * width / (values.length - 1);
    const y = max === min ? height / 2 : height - 3 - (value - min) / (max - min) * (height - 6);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  target.innerHTML = `<svg viewBox="0 0 ${width} ${height}" focusable="false"><polyline class="spark-line ${tone}" points="${points}"/></svg>`;
}

function chartDate(value, withTime=false) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString('zh-CN', {month:'numeric', day:'numeric', ...(withTime ? {hour:'2-digit', minute:'2-digit', hour12:false} : {})});
}

function openAnalyticsReport(runId) {
  if (!runId) return;
  selectedReport = runId;
  showView('reports');
  selectReport(runId);
}

function bindRunTargets(container) {
  container.querySelectorAll('[data-run-id]').forEach(target => {
    const content = () => `<b>${escapeHtml(target.dataset.runId)}</b><span>${escapeHtml(target.dataset.tooltip || '')}</span>`;
    const show = event => {
      const tooltip = $('#chart-tooltip');
      tooltip.innerHTML = content();
      tooltip.classList.remove('hidden');
      const rect = target.getBoundingClientRect();
      tooltip.style.left = `${Math.min(window.innerWidth - 230, Math.max(10, event.clientX || rect.left + rect.width / 2))}px`;
      tooltip.style.top = `${Math.max(10, (event.clientY || rect.top) - 58)}px`;
    };
    target.addEventListener('mouseenter', show);
    target.addEventListener('focus', show);
    target.addEventListener('mouseleave', () => $('#chart-tooltip').classList.add('hidden'));
    target.addEventListener('blur', () => $('#chart-tooltip').classList.add('hidden'));
    target.addEventListener('click', () => openAnalyticsReport(target.dataset.runId));
    target.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); openAnalyticsReport(target.dataset.runId); } });
  });
}

function renderPassRateChart(current, previous) {
  const target = $('#pass-rate-chart');
  if (!current.length) { target.className = 'chart-empty'; target.textContent = '当前时间范围内暂无运行数据'; return; }
  const width = 720, height = 250, left = 42, right = 52, top = 18, bottom = 42;
  const plotWidth = width - left - right, plotHeight = height - top - bottom;
  const coords = (runs, index, total) => ({
    x: total === 1 ? left + plotWidth / 2 : left + index * plotWidth / (total - 1),
    y: top + (100 - Math.max(0, Math.min(100, Number(runs[index].pass_rate) || 0))) / 100 * plotHeight,
  });
  const durationMax = Math.max(1, ...current.map(run => Math.max(0, Number(run.duration_ms) || 0)));
  const durationCoords = (run, index) => ({
    x: current.length === 1 ? left + plotWidth / 2 : left + index * plotWidth / (current.length - 1),
    y: top + (1 - Math.max(0, Number(run.duration_ms) || 0) / durationMax) * plotHeight,
  });
  const pathFor = runs => runs.map((run, index) => { const p = coords(runs, index, runs.length); return `${index ? 'L' : 'M'} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`; }).join(' ');
  const currentPath = pathFor(current);
  const previousPath = previous.length ? pathFor(previous) : '';
  const durationPath = current.map((run, index) => { const p = durationCoords(run, index); return `${index ? 'L' : 'M'} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`; }).join(' ');
  const area = current.length > 1 ? `<path class="trend-area" d="${currentPath} L ${(left + plotWidth).toFixed(1)} ${top + plotHeight} L ${left} ${top + plotHeight} Z"/>` : '';
  const grid = [0,25,50,75,100].map(rate => { const y = top + (100 - rate) / 100 * plotHeight; return `<line class="chart-grid" x1="${left}" y1="${y}" x2="${left + plotWidth}" y2="${y}"/><text class="chart-axis" x="${left - 8}" y="${y + 3}" text-anchor="end">${rate}%</text>`; }).join('');
  const durationAxis = `<text class="chart-axis duration-axis" x="${left + plotWidth + 9}" y="${top + 3}" text-anchor="start">${escapeHtml(formatDuration(durationMax))}</text><text class="chart-axis duration-axis" x="${left + plotWidth + 9}" y="${top + plotHeight + 3}" text-anchor="start">0</text>`;
  const tickIndexes = [...new Set([0,1,2,3,4].map(i => Math.round(i * (current.length - 1) / 4)))];
  const ticks = tickIndexes.map(index => { const point = coords(current, index, current.length); return `<text class="trend-tick" x="${point.x}" y="${height - 10}" text-anchor="middle">${escapeHtml(chartDate(current[index].started_at, current.length <= 12))}</text>`; }).join('');
  const dots = current.map((run, index) => {
    const point = coords(current, index, current.length);
    const tooltip = `${chartDate(run.started_at, true)} · 通过率 ${run.pass_rate}% · ${formatDuration(run.duration_ms)}`;
    const failed = run.status === 'failed' || Number(run.pass_rate) < 100;
    return `<circle class="trend-dot chart-target${failed ? ' is-failed' : ''}" cx="${point.x}" cy="${point.y}" r="5" tabindex="0" role="button" data-run-id="${escapeHtml(run.run_id)}" data-tooltip="${escapeHtml(tooltip)}" aria-label="${escapeHtml(tooltip)}"></circle>`;
  }).join('');
  const durationDots = current.map((run, index) => { const point = durationCoords(run, index); return `<circle class="duration-dot" cx="${point.x}" cy="${point.y}" r="2.8"></circle>`; }).join('');
  target.className = 'chart-plot';
  target.innerHTML = `<svg class="analytics-svg" viewBox="0 0 ${width} ${height}" role="group" aria-label="${current.length} 轮检查项通过率与耗时趋势"><defs><linearGradient id="analytics-trend-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="var(--chart-accent)" stop-opacity=".2"/><stop offset="100%" stop-color="var(--chart-accent)" stop-opacity="0"/></linearGradient></defs>${grid}${durationAxis}${area}${previousPath ? `<path class="trend-line previous" d="${previousPath}"/>` : ''}<path class="duration-line" d="${durationPath}"/>${durationDots}<path class="trend-line" d="${currentPath}"/>${dots}${ticks}</svg>`;
  bindRunTargets(target);
}

function renderResultMixChart(runs) {
  const target = $('#result-mix-chart');
  if (!runs.length) { target.className = 'chart-empty'; target.textContent = '当前时间范围内暂无运行数据'; return; }
  const width = 420, height = 250, left = 20, right = 10, top = 18, bottom = 42;
  const plotWidth = width - left - right, plotHeight = height - top - bottom;
  const maxTotal = Math.max(1, ...runs.map(run => count(run.counts?.passed) + count(run.counts?.failed) + count(run.counts?.skipped)));
  const step = plotWidth / runs.length, barWidth = Math.max(5, Math.min(24, step * .58));
  const bars = runs.map((run, index) => {
    const values = [['passed', count(run.counts?.passed)], ['failed', count(run.counts?.failed)], ['skipped', count(run.counts?.skipped)]];
    let cursor = top + plotHeight;
    const rects = values.map(([status, value]) => { const barHeight = value / maxTotal * plotHeight; cursor -= barHeight; return `<rect class="bar-${status}" x="${(left + index * step + (step - barWidth) / 2).toFixed(1)}" y="${cursor.toFixed(1)}" width="${barWidth.toFixed(1)}" height="${Math.max(0, barHeight).toFixed(1)}" rx="2"/>`; }).join('');
    const total = values.reduce((sum, value) => sum + value[1], 0);
    const tooltip = `${chartDate(run.started_at, true)} · 通过 ${values[0][1]} · 失败 ${values[1][1]} · 跳过 ${values[2][1]}`;
    return `<g class="chart-target" tabindex="0" role="button" data-run-id="${escapeHtml(run.run_id)}" data-tooltip="${escapeHtml(tooltip)}" aria-label="${escapeHtml(tooltip)}">${rects}<rect class="bar-hit" x="${(left + index * step).toFixed(1)}" y="${top}" width="${step.toFixed(1)}" height="${plotHeight}"/><text class="bar-total" x="${(left + index * step + step / 2).toFixed(1)}" y="${Math.max(12, top + plotHeight - total / maxTotal * plotHeight - 6).toFixed(1)}" text-anchor="middle">${total}</text></g>`;
  }).join('');
  const labelIndexes = [...new Set([0, Math.floor((runs.length - 1) / 2), runs.length - 1])];
  const labels = labelIndexes.map(index => `<text class="trend-tick" x="${(left + index * step + step / 2).toFixed(1)}" y="${height - 11}" text-anchor="middle">${escapeHtml(chartDate(runs[index].started_at, true))}</text>`).join('');
  target.className = 'chart-plot';
  target.innerHTML = `<svg class="analytics-svg" viewBox="0 0 ${width} ${height}" role="group" aria-label="${runs.length} 轮检查结果构成"><line class="chart-grid" x1="${left}" y1="${top + plotHeight}" x2="${left + plotWidth}" y2="${top + plotHeight}"/>${bars}${labels}</svg>`;
  bindRunTargets(target);
}

function aggregateCategories(runs) {
  const items = new Map();
  runs.forEach(run => (run.categories || []).forEach(category => {
    const item = items.get(category.name) || {name:category.name, passed:0, failed:0, skipped:0};
    item.passed += count(category.passed); item.failed += count(category.failed); item.skipped += count(category.skipped);
    items.set(category.name, item);
  }));
  return [...items.values()].map(item => { const total = item.passed + item.failed + item.skipped; return {...item, total, rate:total ? item.passed / total * 100 : 0}; }).sort((a,b) => a.rate - b.rate || b.failed - a.failed || a.name.localeCompare(b.name, 'zh-CN'));
}

function renderCategoryHealth(runs) {
  const target = $('#category-health');
  const categories = aggregateCategories(runs);
  $('#category-caption').textContent = categories.length ? `${categories.length} 个模块` : '暂无数据';
  if (!categories.length) { target.className = 'chart-empty compact'; target.textContent = '当前时间范围内暂无模块数据'; return; }
  target.className = 'category-list';
  target.innerHTML = categories.map(item => {
    const passed = item.total ? item.passed / item.total * 100 : 0;
    const failed = item.total ? item.failed / item.total * 100 : 0;
    return `<button class="category-row" type="button" data-category="${escapeHtml(item.name)}"><span class="category-label"><b>${escapeHtml(item.name)}</b><em>${item.rate.toFixed(1)}%</em></span><span class="category-track" aria-label="${escapeHtml(item.name)}通过 ${item.passed}，失败 ${item.failed}，跳过 ${item.skipped}"><i class="passed" style="width:${passed}%"></i><i class="failed" style="width:${failed}%"></i><i class="skipped" style="width:${Math.max(0, 100-passed-failed)}%"></i></span><small>通过 ${item.passed} · 失败 ${item.failed} · 跳过 ${item.skipped}</small></button>`;
  }).join('');
  target.querySelectorAll('[data-category]').forEach(button => button.addEventListener('click', () => {
    $('#check-category-filter').value = button.dataset.category;
    showView('checks');
    renderChecks();
  }));
}

function renderSlowChecks(runs) {
  const target = $('#slow-checks');
  const totals = new Map();
  runs.forEach(run => (run.checks || []).forEach(check => {
    const item = totals.get(check.id) || {id:check.id, name:check.name, category:check.category, duration:0, samples:0, failures:0, runId:run.run_id};
    item.duration += Math.max(0, Number(check.duration_ms) || 0); item.samples += 1; item.failures += check.status === 'failed' ? 1 : 0; item.runId = run.run_id;
    totals.set(check.id, item);
  }));
  const checks = [...totals.values()].map(item => ({...item, average:item.samples ? item.duration / item.samples : 0})).sort((a,b) => b.average - a.average).slice(0, 6);
  $('#slow-caption').textContent = checks.length ? `Top ${checks.length}` : '暂无数据';
  if (!checks.length) { target.className = 'chart-empty compact'; target.textContent = '当前时间范围内暂无耗时数据'; return; }
  const max = Math.max(1, ...checks.map(item => item.average));
  target.className = 'latency-list';
  target.innerHTML = checks.map(item => `<button class="latency-row" type="button" data-run-id="${escapeHtml(item.runId)}"><span class="latency-label"><b>${escapeHtml(item.name)}</b><small>${escapeHtml(item.category)}${item.failures ? ` · ${item.failures} 次失败` : ''}</small></span><span class="latency-bar"><i style="width:${item.average / max * 100}%"></i></span><strong>${formatDuration(item.average)}</strong></button>`).join('');
  target.querySelectorAll('[data-run-id]').forEach(button => button.addEventListener('click', () => openAnalyticsReport(button.dataset.runId)));
}

function renderAnalytics(analytics={runs:[]}) {
  const {current, previous} = analyticsPeriods(analytics.runs || []);
  const currentSummary = summarizeRuns(current);
  const previousSummary = summarizeRuns(previous);
  const compare = $('#analytics-compare').checked;
  const label = analyticsRange.endsWith('d') ? `近 ${analyticsRange.replace('d','')} 天` : `最近 ${analyticsRange} 轮`;
  $('#trend-range').textContent = current.length ? `${label} · ${current.length} 轮` : `${label} · 暂无记录`;
  $('#trend-current-rate').textContent = current.length ? `${currentSummary.passRate.toFixed(1)}%` : '—';
  $('#trend-current-duration').textContent = current.length ? `平均耗时 ${formatDuration(currentSummary.averageDuration)}` : '平均耗时 —';
  $('#period-pass-rate').textContent = current.length ? `${currentSummary.passRate.toFixed(1)}%` : '—';
  $('#pass-rate-hint').textContent = current.length ? `${currentSummary.passed} 通过 · ${currentSummary.failed} 失败 · ${currentSummary.skipped} 跳过` : '当前筛选周期暂无运行';
  $('#period-duration').textContent = current.length ? formatDuration(currentSummary.averageDuration) : '—';
  $('#duration-hint').textContent = current.length ? `${current.length} 轮巡检 · 最近 ${formatDuration(current.at(-1).duration_ms)}` : '按完整巡检轮次统计';
  const canCompare = compare && current.length && previous.length;
  const passDelta = canCompare ? percentageChange(currentSummary.passRate, previousSummary.passRate) : NaN;
  const durationDelta = canCompare ? percentageChange(currentSummary.averageDuration, previousSummary.averageDuration) : NaN;
  changeBadge('#pass-rate-change', passDelta);
  changeBadge('#duration-change', durationDelta, true);
  sparkline('#pass-rate-spark', current.map(item => Number(item.pass_rate) || 0));
  sparkline('#duration-spark', current.map(item => Number(item.duration_ms) || 0), 'duration');
  $('#failed-run-count').textContent = `${currentSummary.failedRuns} 轮失败`;
  $('#incident-hint').textContent = currentSummary.failedRuns ? `筛选周期内 ${currentSummary.failedRuns} 轮异常` : '当前筛选周期运行稳定';
  const total = currentSummary.checks;
  $('#period-result-passed').style.width = `${total ? currentSummary.passed / total * 100 : 0}%`;
  $('#period-result-failed').style.width = `${total ? currentSummary.failed / total * 100 : 0}%`;
  $('#period-result-skipped').style.width = `${total ? currentSummary.skipped / total * 100 : 0}%`;
  $('#period-result-progress').setAttribute('aria-label', total ? `通过 ${currentSummary.passed} 项，失败 ${currentSummary.failed} 项，跳过 ${currentSummary.skipped} 项` : '暂无检查结果');
  renderPassRateChart(current, compare ? previous : []);
  renderResultMixChart(current);
  renderCategoryHealth(current);
  renderSlowChecks(current);
  return currentSummary;
}

function renderAttention(data, periodSummary={failedRuns:0}) {
  const openAlerts = count(data.incidents?.open);
  const enabled = count(data.enabled_checks);
  const candidates = count(data.total_checks);
  const pending = Math.max(0, candidates - Math.min(enabled, candidates));
  const latest = data.latest;
  const failed = count(latest?.counts?.failed);
  const skipped = count(latest?.counts?.skipped);
  const issues = [];
  if (openAlerts) issues.push({
    tone:'critical', title:`${openAlerts} 个告警尚未恢复`,
    detail:'进入告警中心查看影响范围和恢复进度', target:'incidents',
  });
  if (latest?.status === 'failed' && !openAlerts) issues.push({
    tone:'critical', title:'最近一轮巡检失败',
    detail:`${failed} 项失败${skipped ? ` · ${skipped} 项跳过` : ''}`, target:'reports', runId:latest.run_id,
  });
  if (periodSummary.failedRuns && latest?.status !== 'failed') issues.push({
    tone:'warning', title:`筛选周期内有 ${periodSummary.failedRuns} 轮异常`,
    detail:'查看趋势节点或历史报告定位异常轮次', target:'reports',
  });
  if (pending) issues.push({
    tone:'warning', title:`${pending} 个检查项待配置`,
    detail:`当前已启用 ${enabled} / ${candidates} 项`, target:'checks', filter:'disabled',
  });
  if (!latest && !data.active_run_id) issues.push({
    tone:'warning', title:'尚无巡检运行证据',
    detail:'核实检查项配置后手动执行首次巡检', target:'checks',
  });
  const visible = issues.slice(0, 3);
  const critical = visible.some(item => item.tone === 'critical');
  const panel = $('#attention-panel');
  panel.className = `panel attention-panel ${visible.length ? critical ? 'has-critical' : 'has-warning' : 'is-healthy'}`;
  $('#attention-title').textContent = visible.length ? critical ? '需要立即关注' : '需要关注' : '运行稳定';
  $('#attention-summary').textContent = visible.length
    ? `发现 ${issues.length} 项需要核实的问题，按优先级展示。`
    : '当前筛选周期和最新运行没有需要处理的异常。';
  const badge = $('#attention-count');
  badge.textContent = visible.length ? `${issues.length} 项待处理` : '0 项待处理';
  badge.className = `badge ${visible.length ? critical ? 'bad' : 'neutral' : 'good'}`;
  $('#attention-icon').innerHTML = critical
    ? '<svg viewBox="0 0 24 24"><path d="M12 3 2.8 19h18.4L12 3Z"/><path d="M12 9v4m0 3h.01"/></svg>'
    : visible.length
      ? '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 8v5m0 3h.01"/></svg>'
      : '<svg viewBox="0 0 24 24"><path d="M20 6 9 17l-5-5"/></svg>';
  const target = $('#attention-items');
  target.innerHTML = visible.map(item => `<button class="attention-item ${item.tone}" type="button" data-attention-target="${item.target}"${item.runId ? ` data-run-id="${escapeHtml(item.runId)}"` : ''}${item.filter ? ` data-filter="${escapeHtml(item.filter)}"` : ''}><i aria-hidden="true"></i><span class="attention-item-copy"><b>${escapeHtml(item.title)}</b><small>${escapeHtml(item.detail)}</small></span><span aria-hidden="true">→</span></button>`).join('');
  target.querySelectorAll('[data-attention-target]').forEach(button => button.addEventListener('click', () => {
    if (button.dataset.attentionTarget === 'reports' && button.dataset.runId) {
      openAnalyticsReport(button.dataset.runId);
      return;
    }
    if (button.dataset.attentionTarget === 'checks' && button.dataset.filter) {
      $('#check-status-filter').value = button.dataset.filter;
      renderChecks();
    }
    showView(button.dataset.attentionTarget);
  }));
}

function renderSummary(data) {
  currentSummary = data;
  $('#environment').textContent = environmentText(data.environment);
  const system = currentSystem();
  if (system) {
    system.environment = data.environment;
    system.enabled_checks = data.enabled_checks;
    system.total_checks = data.total_checks;
    system.incidents = data.incidents;
    renderSystemOptions();
  }
  $('#config-version').textContent = `配置版本 ${data.config_version}`;
  $('#report-range').textContent = `最近 ${data.report_limit || 30} 轮`;
  const enabled = count(data.enabled_checks);
  const candidates = count(data.total_checks);
  const passed = count(data.latest?.counts?.passed);
  const failed = count(data.latest?.counts?.failed);
  const skipped = count(data.latest?.counts?.skipped);
  const openAlerts = count(data.incidents?.open);
  const runButton = $('#run');
  const runMenuTrigger = $('#run-menu-trigger');
  runButton.disabled = !!data.active_run_id || runTargetCount(data, selectedRunTargets) === 0;
  runMenuTrigger.disabled = !!data.active_run_id || enabled === 0;
  document.querySelectorAll('[data-run-targets]').forEach(option => {
    const targets = option.dataset.runTargets.split(',');
    option.disabled = runTargetCount(data, targets) === 0;
  });
  runButton.classList.toggle('is-running', !!data.active_run_id);
  runButton.classList.remove('is-launching');
  runButton.querySelector('span').textContent = data.active_run_id
    ? `${runTargetsLabel(data.active_targets || [])} 巡检中…`
    : `执行 ${runTargetsLabel(selectedRunTargets)}`;
  if (data.active_run_id) runButton.setAttribute('aria-busy', 'true');
  else runButton.removeAttribute('aria-busy');
  const badge = $('#health-badge');
  badge.textContent = data.latest ? statusText(data.latest.status) : '待执行';
  badge.className = `badge ${data.latest?.status === 'passed' ? 'good' : data.latest?.status === 'failed' ? 'bad' : 'neutral'}`;
  $('#health-content').innerHTML = data.latest
    ? `<b>最近运行：${escapeHtml(data.latest.run_id)}</b><br>触发方式：${data.latest.trigger === 'scheduled' ? '定时' : '手动'} · 通过 ${passed} 项，失败 ${failed} 项，跳过 ${skipped} 项。<br>完成时间：${escapeHtml(timeText(data.latest.finished_at))} · 当前未恢复告警：${count(data.incidents?.open)}`
    : '尚无巡检报告。请先核实接口配置与业务断言。';
  const healthTone = data.active_run_id ? 'running' : openAlerts || data.latest?.status === 'failed' ? 'failed' : data.latest?.status === 'passed' ? 'passed' : 'neutral';
  const healthValue = {running:'巡检中', failed:'异常', passed:'健康', neutral:'待执行'}[healthTone];
  const healthState = {running:'执行中', failed:'需处理', passed:'正常', neutral:'待执行'}[healthTone];
  const healthDetail = data.active_run_id
    ? '正在采集最新运行证据'
    : openAlerts
      ? `${openAlerts} 个告警尚未恢复`
      : data.latest?.status === 'failed'
        ? `${failed} 项检查失败${skipped ? ` · ${skipped} 项跳过` : ''}`
        : data.latest?.status === 'passed'
          ? `${passed} 项检查全部通过`
          : '等待首次巡检';
  $('#health-card').dataset.tone = healthTone;
  $('#current-health-value').textContent = healthValue;
  $('#current-health-meta').textContent = `${enabled} / ${candidates} 项启用`;
  $('#current-health-detail').textContent = healthDetail;
  $('#health-card-hint').textContent = data.active_run_id
    ? `运行标识 ${data.active_run_id}`
    : data.latest
      ? `最近完成 ${timeText(data.latest.finished_at)}`
      : '尚无可用运行证据';
  const healthStateBadge = $('#current-health-state');
  healthStateBadge.textContent = healthState;
  healthStateBadge.className = `status-pill ${healthTone}`;
  const runtimeStatus = $('#overview-runtime-status');
  runtimeStatus.className = `runtime-status ${healthTone}`;
  runtimeStatus.querySelector('span').textContent = {running:'巡检执行中', failed:'存在运行异常', passed:'运行正常', neutral:'等待首次运行'}[healthTone];
  $('#overview-last-run').textContent = data.latest ? `最近巡检 ${timeText(data.latest.finished_at)}` : '最近巡检 —';
  $('#open-incident-count').textContent = String(openAlerts);
  $('#incident-card').dataset.tone = openAlerts ? 'failed' : 'passed';
  $('#nav-alert-count').textContent = String(openAlerts);
  $('#nav-alert-count').classList.toggle('hidden', openAlerts === 0);
  const cardState = {
    health: `${healthTone}:${data.active_run_id || data.latest?.run_id || ''}:${enabled}/${candidates}`,
    passRate: `${data.latest?.run_id || ''}:${passed}/${failed}/${skipped}`,
    duration: `${data.latest?.run_id || ''}:${data.latest?.finished_at || ''}`,
    incident: String(openAlerts),
  };
  if (previousCardState) {
    for (const [key, id] of [['health', 'health-card'], ['passRate', 'pass-rate-card'], ['duration', 'duration-card'], ['incident', 'incident-card']]) {
      if (previousCardState[key] !== cardState[key]) {
        const card = $(`#${id}`);
        card.classList.remove('is-updated');
        void card.offsetWidth;
        card.classList.add('is-updated');
      }
    }
  }
  previousCardState = cardState;
  const analytics = data.analytics || {runs:(data.trend || []).map(run => {
    const runPassed = count(run.counts?.passed);
    const runFailed = count(run.counts?.failed);
    const runSkipped = count(run.counts?.skipped);
    const runTotal = runPassed + runFailed + runSkipped;
    const started = new Date(run.started_at).getTime();
    const finished = new Date(run.finished_at).getTime();
    return {...run,
      duration_ms:Number.isFinite(started) && Number.isFinite(finished) ? Math.max(0, finished - started) : 0,
      pass_rate:runTotal ? runPassed / runTotal * 100 : 0,
      categories:[], checks:[],
    };
  })};
  const periodSummary = renderAnalytics(analytics);
  renderAttention(data, periodSummary);
  activeRun = data.active_run_id;
}

async function loadSummary() {
  try { renderSummary(await api('/api/summary')); }
  catch(error) { notice(error.message, 'error'); }
}

function typedChecks() {
  return cachedChecks.filter(item => currentCheckKind === 'ui' ? item.type === 'ui' : item.type !== 'ui');
}

function persistCheckViewState() {
  Object.assign(checkViewStates[currentCheckKind], {
    search: $('#check-search').value,
    category: $('#check-category-filter').value,
    status: $('#check-status-filter').value,
  });
}

function refreshCheckCategories(preferredCategory='') {
  const categories = [...new Set(typedChecks().map(item => item.category).filter(Boolean))].sort((a, b) => a.localeCompare(b, 'zh-CN'));
  const selectedCategory = preferredCategory || $('#check-category-filter').value;
  $('#check-category-filter').innerHTML = '<option value="">全部模块</option>' + categories.map(category => `<option value="${escapeHtml(category)}">${escapeHtml(category)}</option>`).join('');
  $('#check-category-filter').value = categories.includes(selectedCategory) ? selectedCategory : '';
}

function restoreCheckViewState() {
  const state = checkViewStates[currentCheckKind];
  $('#check-search').value = state.search;
  $('#check-status-filter').value = state.status;
  refreshCheckCategories(state.category);
}

function syncCheckKindChrome() {
  const apiCheck = currentCheckKind === 'api';
  const systemName = currentSystem()?.display_name || selectedSystem || '当前系统';
  const labels = apiCheck ? {
    eyebrow:'接口维度 · 独立巡检清单', title:'API 巡检项',
    description:`查看 ${systemName} 的 API 接口、启用状态与配置详情。`,
    total:'API 总数', totalHint:'当前系统接口配置',
    enabled:'已启用', enabledHint:'参与自动 API 巡检',
    pending:'待配置', pendingHint:'完成核实后启用',
    module:'业务模块', moduleHint:'已覆盖模块',
    nameHeading:'API 巡检项', targetHeading:'请求',
  } : {
    eyebrow:'用户旅程维度 · 独立场景清单', title:'UI 场景项',
    description:`查看 ${systemName} 的 UI 场景、步骤覆盖与截图执行状态。`,
    total:'场景总数', totalHint:'当前系统场景配置',
    enabled:'已启用', enabledHint:'参与自动 UI 巡检',
    pending:'待配置', pendingHint:'完成场景后启用',
    module:'步骤总数', moduleHint:'全部场景操作步骤',
    nameHeading:'UI 场景项', targetHeading:'页面与步骤',
  };
  $('#checks').dataset.checkKind = currentCheckKind;
  $('#check-eyebrow').textContent = labels.eyebrow;
  $('#check-page-title').textContent = labels.title;
  $('#checks-description').textContent = labels.description;
  $('#checks-total-label').textContent = labels.total;
  $('#checks-total-hint').textContent = labels.totalHint;
  $('#checks-enabled-label').textContent = labels.enabled;
  $('#checks-enabled-hint').textContent = labels.enabledHint;
  $('#checks-pending-label').textContent = labels.pending;
  $('#checks-pending-hint').textContent = labels.pendingHint;
  $('#checks-module-label').textContent = labels.module;
  $('#checks-module-hint').textContent = labels.moduleHint;
  $('#checks-name-heading').textContent = labels.nameHeading;
  $('#checks-target-heading').textContent = labels.targetHeading;
  document.querySelectorAll('[data-check-kind]').forEach(button => {
    const active = button.dataset.checkKind === currentCheckKind;
    button.classList.toggle('active', active);
    if (button.getAttribute('role') === 'tab') button.setAttribute('aria-selected', String(active));
  });
  if (!$('#checks').classList.contains('hidden')) $('#page-name').textContent = labels.title;
}

function setCheckKind(kind) {
  if (!['api', 'ui'].includes(kind)) return;
  if (kind !== currentCheckKind) {
    persistCheckViewState();
    currentCheckKind = kind;
    restoreCheckViewState();
  }
  syncCheckKindChrome();
  renderChecks();
  if ($('#checks').classList.contains('hidden')) showView('checks');
  else setCheckNavExpanded(true);
}

async function loadChecks() {
  try {
    cachedChecks = await api('/api/checks');
    refreshCheckCategories(checkViewStates[currentCheckKind].category);
    renderChecks();
  } catch(error) { notice(error.message, 'error'); }
}

function renderChecks() {
  const query = $('#check-search').value.trim().toLocaleLowerCase('zh-CN');
  const category = $('#check-category-filter').value;
  const status = $('#check-status-filter').value;
  const scopedChecks = typedChecks();
  const checks = scopedChecks.filter(item => {
    const uiPath = (item.steps || []).find(step => step.action === 'goto')?.path || '';
    const haystack = `${item.name || ''} ${item.id || ''} ${item.category || ''} ${item.path || ''} ${uiPath}`.toLocaleLowerCase('zh-CN');
    return (!query || haystack.includes(query))
      && (!category || item.category === category)
      && (!status || (status === 'enabled') === !!item.enabled);
  });
  const enabled = scopedChecks.filter(item => item.enabled).length;
  const pending = scopedChecks.length - enabled;
  const coverage = currentCheckKind === 'ui'
    ? scopedChecks.reduce((total, item) => total + (item.steps || []).length, 0)
    : new Set(scopedChecks.map(item => item.category).filter(Boolean)).size;
  $('#check-summary').textContent = `${enabled} / ${scopedChecks.length} 已启用`;
  $('#checks-total-count').textContent = String(scopedChecks.length);
  $('#checks-enabled-count').textContent = String(enabled);
  $('#checks-pending-count').textContent = String(pending);
  $('#checks-module-count').textContent = String(coverage);
  $('#check-filter-result').textContent = `显示 ${checks.length} / ${scopedChecks.length} 项`;
  $('#check-filter-reset').classList.toggle('hidden', !(query || category || status));
  $('#checks-body').innerHTML = checks.length
    ? checks.map((item, index) => {
      const isUi = item.type === 'ui';
      const method = isUi ? 'UI' : String(item.method || 'GET').toUpperCase();
      const methodClass = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method) ? method.toLocaleLowerCase() : 'other';
      const target = isUi ? (item.steps || []).find(step => step.action === 'goto')?.path : item.path;
      const detail = isUi ? `${(item.steps || []).length} 个带截图步骤` : target || '待核实';
      return `<tr class="check-row ${item.enabled ? '' : 'is-pending'}"><td>${String(index + 1).padStart(2,'0')}</td><td><b>${escapeHtml(item.name)}</b><br><small>${escapeHtml(item.id || '—')}</small></td><td>${escapeHtml(item.category)}</td><td><span class="request-cell"><span class="method-chip method-${methodClass}">${escapeHtml(method)}</span><code title="${escapeHtml(target || detail)}">${escapeHtml(detail)}</code></span></td><td><span class="status-stack"><span class="badge ${item.enabled ? 'good' : 'neutral'}">${item.enabled ? '已启用' : '待配置'}</span></span></td></tr>`;
    }).join('')
    : `<tr><td colspan="5">没有符合筛选条件的${currentCheckKind === 'api' ? ' API 巡检项' : ' UI 场景项'}</td></tr>`;
  persistCheckViewState();
}

const cloneJson = value => JSON.parse(JSON.stringify(value));
const pretty = value => JSON.stringify(value, null, 2);

function setSettingsDirty(dirty) {
  settingsDirty = dirty;
  const state = $('#settings-save-state');
  state.className = `save-state ${dirty ? 'dirty' : 'saved'}`;
  state.innerHTML = `<i aria-hidden="true"></i>${dirty ? '有未保存修改' : '配置已同步'}`;
}

function renderSettingsOverview(config, credentials={}) {
  const checks = config.checks || [];
  const enabled = checks.filter(item => item.enabled).length;
  const apiChecks = checks.filter(item => item.type !== 'ui');
  const uiScenes = checks.filter(item => item.type === 'ui');
  const enabledApis = apiChecks.filter(item => item.enabled).length;
  const enabledUiScenes = uiScenes.filter(item => item.enabled).length;
  const envReady = !!(config.system_id && config.environment && config.base_url);
  const apiCredentialReady = !!credentials.password_configured;
  const uiNeedsCredentials = uiScenes.some(item => item.enabled && JSON.stringify(item).includes('SRM_UI_'));
  const uiCredentialReady = !!(credentials.ui_username && credentials.ui_password_configured);
  const credentialReady = apiCredentialReady && (!uiNeedsCredentials || uiCredentialReady);
  const scheduleEnabled = !!config.schedule?.enabled;
  const alertsEnabled = !!config.alerts?.enabled;
  const webhookReady = !!credentials.webhook_configured;
  const operationState = scheduleEnabled && alertsEnabled ? '调度 + 告警'
    : scheduleEnabled ? '仅调度' : alertsEnabled ? '仅告警' : '手动模式';

  $('#settings-env-state').textContent = envReady ? environmentText(config.environment) : '待完善';
  $('#settings-env-detail').textContent = envReady ? config.base_url : '缺少环境或基础地址';
  $('#settings-credential-state').textContent = credentialReady ? '已配置' : '未配置';
  $('#settings-credential-detail').textContent = credentialReady
    ? `API ${credentials.username || '已保存'}${uiNeedsCredentials ? ` · UI ${credentials.ui_username || '已保存'}` : ''}`
    : !apiCredentialReady ? '需要录入 API 巡检密码' : '需要录入 UI 登录凭据';
  $('#settings-operation-state').textContent = operationState;
  $('#settings-operation-detail').textContent = alertsEnabled ? (webhookReady ? '通知通道已连接' : 'Webhook 尚未配置') : '告警通知未启用';
  $('#settings-api-state').textContent = `${enabledApis} / ${apiChecks.length}`;
  $('#settings-api-detail').textContent = apiChecks.length === enabledApis ? '全部 API 已启用' : `${apiChecks.length - enabledApis} 项待启用`;
  $('#settings-ui-state').textContent = `${enabledUiScenes} / ${uiScenes.length}`;
  $('#settings-ui-detail').textContent = uiScenes.length === enabledUiScenes ? '全部场景已启用' : `${uiScenes.length - enabledUiScenes} 项待启用`;
  $('#settings-env-state').closest('article').dataset.state = envReady ? 'good' : 'warning';
  $('#settings-credential-state').closest('article').dataset.state = credentialReady ? 'good' : 'warning';
  $('#settings-operation-state').closest('article').dataset.state = alertsEnabled && !webhookReady ? 'warning' : scheduleEnabled || alertsEnabled ? 'good' : 'neutral';
  $('#settings-api-state').closest('button').dataset.state = apiChecks.length && enabledApis === apiChecks.length ? 'good' : 'warning';
  $('#settings-ui-state').closest('button').dataset.state = uiScenes.length && enabledUiScenes === uiScenes.length ? 'good' : 'warning';

  const blockers = [];
  if (!envReady) blockers.push('环境信息不完整');
  if (!credentialReady) blockers.push('巡检凭据未配置');
  if (!enabled) blockers.push('没有已启用检查项');
  if (alertsEnabled && !webhookReady) blockers.push('告警已开启但 Webhook 未配置');
  const production = config.environment === 'production';
  const readiness = $('#settings-readiness');
  readiness.className = `settings-readiness ${blockers.length ? 'has-warning' : production ? 'is-production' : 'is-ready'}`;
  $('#settings-risk-title').textContent = blockers.length
    ? '配置需要完善'
    : production ? '正式环境 · 配置可运行' : '配置可运行';
  $('#settings-risk-detail').textContent = blockers.length
    ? blockers.join('；')
    : production ? '执行前请核对启用项配置，并优先完成登录预检。' : '环境、凭据和检查项已具备运行条件。';
  $('#settings-readiness-badge').textContent = blockers.length ? `${blockers.length} 项待处理` : '准备就绪';
  $('#settings-readiness-badge').className = `badge ${blockers.length ? 'neutral' : 'good'}`;
  readiness.querySelector('.settings-readiness-icon').textContent = blockers.length ? '!' : production ? 'P' : '✓';

  const tabState = (name, state) => {
    const dot = document.querySelector(`[data-settings-tab="${name}"] i`);
    if (dot) dot.className = state;
  };
  tabState('environment', envReady && credentialReady ? 'good' : 'warning');
  tabState('operations', alertsEnabled && !webhookReady ? 'warning' : scheduleEnabled || alertsEnabled ? 'good' : 'neutral');
  tabState('advanced', 'neutral');
}

function renderConfig(document) {
  configDocument = {
    config: cloneJson(document.config), config_version: document.config_version,
    settings_version: document.settings_version, api_version: document.api_version,
    ui_version: document.ui_version, credentials: {...document.credentials},
    api_enablement: cloneJson(document.api_enablement || {}),
    ui_verification: cloneJson(document.ui_verification || {}),
  };
  const config = configDocument.config;
  const credentials = configDocument.credentials || {};
  $('#settings-version').textContent = `设置版本 ${configDocument.settings_version || configDocument.config_version}`;
  $('#config-system-id').value = config.system_id || '';
  $('#config-environment').value = config.environment || '';
  $('#config-base-url').value = config.base_url || '';
  $('#config-account').value = credentials.account || '';
  $('#config-username').value = credentials.username || '';
  $('#config-password').value = '';
  $('#config-password').placeholder = credentials.password_configured ? '已配置，留空不修改' : '尚未配置';
  $('#config-client-id').value = credentials.client_id || '';
  $('#config-ui-username').value = credentials.ui_username || '';
  $('#config-ui-password').value = '';
  $('#config-ui-password').placeholder = credentials.ui_password_configured ? '已配置，留空不修改' : '尚未配置';
  $('#config-timeout').value = config.default_timeout_seconds ?? 10;
  $('#config-report-limit').value = config.report_limit ?? 30;
  const schedule = config.schedule || {};
  const scheduleTargets = schedule.targets || ['api', 'ui'];
  $('#schedule-enabled').checked = !!schedule.enabled;
  $('#schedule-target-api').checked = scheduleTargets.includes('api');
  $('#schedule-target-ui').checked = scheduleTargets.includes('ui');
  $('#schedule-mode').value = schedule.mode || 'interval';
  $('#schedule-interval').value = schedule.interval_minutes ?? 15;
  $('#schedule-daily-times').value = (schedule.daily_times || ['09:00']).join(',');
  $('#schedule-timezone').value = schedule.timezone || 'Asia/Shanghai';
  $('#schedule-grace').value = schedule.misfire_grace_minutes ?? 30;
  const runRetry = config.run_retry || {};
  $('#run-retry-enabled').checked = !!runRetry.enabled;
  $('#run-retry-max').value = runRetry.max_retries ?? 2;
  $('#run-retry-delay').value = runRetry.delay_seconds ?? 30;
  const alerts = config.alerts || {};
  $('#alerts-enabled').checked = !!alerts.enabled;
  $('#alerts-notify-success').checked = !!alerts.notify_on_success;
  $('#alerts-severity').value = alerts.default_severity || 'P2';
  $('#alerts-failure-threshold').value = alerts.failure_threshold ?? 2;
  $('#alerts-recovery-threshold').value = alerts.recovery_threshold ?? 1;
  $('#alerts-repeat').value = alerts.repeat_interval_minutes ?? 60;
  $('#alerts-report-base-url').value = alerts.report_base_url || '';
  $('#alerts-webhook').value = '';
  $('#alerts-webhook').placeholder = credentials.webhook_configured ? '已配置，留空不修改' : '尚未配置';
  $('#alerts-dingtalk-secret').value = '';
  $('#alerts-dingtalk-secret').placeholder = credentials.dingtalk_secret_configured ? '已配置，留空不修改' : '未配置加签';
  $('#webhook-status').textContent = credentials.webhook_configured
    ? `Webhook 已配置${credentials.dingtalk_secret_configured ? ' · 钉钉加签已配置' : ''}`
    : 'Webhook 未配置';
  $('#webhook-status').className = `badge ${credentials.webhook_configured ? 'good' : 'neutral'}`;
  const uiCredentialsRequired = (config.checks || []).some(item => item.type === 'ui' && item.enabled && JSON.stringify(item).includes('SRM_UI_'));
  const credentialsReady = credentials.password_configured
    && (!uiCredentialsRequired || (credentials.ui_username && credentials.ui_password_configured));
  $('#credential-status').textContent = credentialsReady ? '凭据已配置' : '凭据未完整配置';
  $('#credential-status').className = `badge ${credentialsReady ? 'good' : 'neutral'}`;
  $('#advanced-config').value = pretty(config);
  renderSettingsOverview(config, credentials);
  syncScheduleFields();
  syncRunRetryFields();
  syncAlertFields();
  renderApiChecks();
  renderUiScenes();
  setSettingsDirty(false);
}

function renderApiChecks() {
  if (!configDocument) return;
  renderAuthFlows();
  const grouped = new Set((configDocument.config.api_auth_flows || []).flatMap(flow => flow.step_ids));
  const checks = (configDocument.config.checks || []).map((item, index) => ({item, index})).filter(({item}) => item.type !== 'ui' && !grouped.has(item.id));
  const selectedCategory = $('#api-check-category').value;
  const categories = [...new Set(checks.map(({item}) => item.category).filter(Boolean))].sort((a, b) => a.localeCompare(b, 'zh-CN'));
  $('#api-check-category').innerHTML = '<option value="">全部模块</option>' + categories.map(category => `<option value="${escapeHtml(category)}">${escapeHtml(category)}</option>`).join('');
  if (categories.includes(selectedCategory)) $('#api-check-category').value = selectedCategory;
  const query = $('#api-check-search').value.trim().toLocaleLowerCase('zh-CN');
  const category = $('#api-check-category').value;
  const status = $('#api-check-status').value;
  const filtered = checks.filter(({item}) => {
    const haystack = `${item.name || ''} ${item.id || ''} ${item.category || ''} ${item.path || ''}`.toLocaleLowerCase('zh-CN');
    return (!query || haystack.includes(query))
      && (!category || item.category === category)
      && (!status || (status === 'enabled') === !!item.enabled);
  });
  const enabled = checks.filter(({item}) => item.enabled).length;
  const visibleIds = new Set(filtered.map(({item}) => item.id));
  for (const id of selectedApiCheckIds) {
    if (!visibleIds.has(id)) selectedApiCheckIds.delete(id);
  }
  const modules = new Set(checks.map(({item}) => item.category).filter(Boolean)).size;
  $('#api-check-total').textContent = String(checks.length);
  $('#api-check-enabled').textContent = String(enabled);
  $('#api-check-disabled').textContent = String(checks.length - enabled);
  $('#api-check-modules').textContent = String(modules);
  $('#api-check-summary').textContent = `${enabled} / ${checks.length} 已启用`;
  $('#api-check-summary').className = `badge ${enabled === checks.length && checks.length ? 'good' : 'neutral'}`;
  $('#api-check-result').textContent = `显示 ${filtered.length} / ${checks.length} 项`;
  $('#api-check-reset').classList.toggle('hidden', !(query || category || status));
  $('#api-checks-body').innerHTML = filtered.length ? filtered.map(({item, index}, rowIndex) => {
    const method = String(item.method || 'GET').toUpperCase();
    const methodClass = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method) ? method.toLocaleLowerCase() : 'other';
    const path = item.path || '';
    const payload = item.body == null ? '无' : item.body_encoding === 'form' ? '表单' : 'JSON';
    const assertions = (item.assertions || []).length;
    const extracts = (item.extract || []).length;
    const role = item.auth_flow_id ? `<span class="inline-note">前置：${escapeHtml((configDocument.config.api_auth_flows || []).find(f => f.id === item.auth_flow_id)?.name || item.auth_flow_id)}</span>` : item.login_precheck ? '<span class="inline-note">登录预检</span>' : '';
    const reasons = apiCheckEnablementReasons(item);
    const blockers = reasons.length ? `<div class="api-check-blockers">${reasons.map(reason => `<span>${escapeHtml(reason)}</span>`).join('')}</div>` : '';
    return `<tr class="${item.id === lastCreatedCheckId ? 'is-new' : ''} ${item.enabled ? '' : 'is-disabled'}"><td class="api-check-select-cell"><label class="api-check-checkbox"><input class="api-check-select" type="checkbox" data-id="${escapeHtml(item.id)}" aria-label="勾选 ${escapeHtml(item.name || item.id)}" ${selectedApiCheckIds.has(item.id) ? 'checked' : ''}></label></td><td>${String(rowIndex + 1).padStart(2, '0')}</td><td><b>${escapeHtml(item.name)}</b>${role}<br><small>${escapeHtml(item.category || '')} · ${escapeHtml(item.id || '—')}</small>${blockers}</td><td><span class="request-cell"><span class="method-chip method-${methodClass}">${escapeHtml(method)}</span><span class="payload-note">${escapeHtml(payload)}</span><code title="${escapeHtml(path)}">${escapeHtml(path || '待配置')}</code></span></td><td>${assertions} 项 / ${extracts} 项</td><td><span class="badge ${item.enabled ? 'good' : reasons.length ? 'warning' : 'neutral'}">${item.enabled ? '已启用' : reasons.length ? '待完善' : '待启用'}</span></td><td><div class="config-item-actions"><button class="button secondary edit-check" type="button" data-index="${index}" aria-label="编辑 ${escapeHtml(item.name)}">编辑</button><button class="button secondary danger-button delete-check" type="button" data-id="${escapeHtml(item.id)}" aria-label="删除 ${escapeHtml(item.name)}">删除</button></div></td></tr>`;
  }).join('') : '<tr><td colspan="7">没有符合筛选条件的 API 巡检</td></tr>';
  $('#api-checks-body').querySelectorAll('.api-check-select').forEach(checkbox => checkbox.addEventListener('change', () => {
    if (checkbox.checked) selectedApiCheckIds.add(checkbox.dataset.id);
    else selectedApiCheckIds.delete(checkbox.dataset.id);
    syncApiCheckSelection();
  }));
  syncApiCheckSelection();
  document.querySelectorAll('.edit-check').forEach(button => button.addEventListener('click', () => openCheckEditor(Number(button.dataset.index))));
  $('#api-checks-body').querySelectorAll('.delete-check').forEach(button => button.addEventListener('click', () => deleteConfigItem('api', button.dataset.id, button)));
}

function apiCheckEnablementReasons(item) {
  const readiness = configDocument?.api_enablement?.[item.id];
  if (Array.isArray(readiness?.reasons)) return readiness.reasons;
  const labels = {
    insecure_callback:'CAS 回调地址使用 HTTP，需核实并确认实际回调地址',
    business_assertion:'缺少业务断言，请根据接口成功响应补充断言',
    body_template:'导入的请求体模板无法解析，请填写有效的 JSON 请求体',
  };
  return [...new Set((item.pending_arguments || []).map(argument => labels[argument.name] || '需先确认导出参数的位置和用途'))];
}

function syncApiCheckSelection() {
  const checkboxes = [...$('#api-checks-body').querySelectorAll('.api-check-select')];
  const selectedCount = selectedApiCheckIds.size;
  const pendingCount = (configDocument?.config.checks || []).filter(item => item.type !== 'ui'
    && selectedApiCheckIds.has(item.id) && !item.enabled).length;
  const selectAll = $('#api-check-select-all');
  selectAll.checked = checkboxes.length > 0 && checkboxes.every(checkbox => selectedApiCheckIds.has(checkbox.dataset.id));
  selectAll.indeterminate = !selectAll.checked && checkboxes.some(checkbox => selectedApiCheckIds.has(checkbox.dataset.id));
  selectAll.disabled = apiChecksEnabling || !configDocument || !checkboxes.length;
  checkboxes.forEach(checkbox => {
    checkbox.checked = selectedApiCheckIds.has(checkbox.dataset.id);
    checkbox.disabled = apiChecksEnabling || !configDocument;
    checkbox.closest('tr').classList.toggle('is-selected', checkbox.checked);
  });
  const button = $('#api-check-enable');
  button.disabled = apiChecksEnabling || pendingCount === 0;
  button.textContent = apiChecksEnabling ? '启用中…' : pendingCount ? `启用勾选项（${pendingCount}）` : '启用勾选项';
  button.setAttribute('aria-busy', String(apiChecksEnabling));
  $('#api-check-selection').textContent = `已勾选 ${selectedCount} 项${selectedCount ? `，${pendingCount} 项待启用` : ''}`;
}

async function enableSelectedApiChecks() {
  if (!configDocument || apiChecksEnabling) return;
  const ids = new Set((configDocument.config.checks || []).filter(item => item.type !== 'ui'
    && selectedApiCheckIds.has(item.id) && !item.enabled).map(item => item.id));
  if (!ids.size) return;
  const blocked = configDocument.config.checks.filter(item => item.type !== 'ui' && ids.has(item.id))
    .map(item => ({item, reasons:apiCheckEnablementReasons(item)})).filter(({reasons}) => reasons.length);
  if (blocked.length) {
    showMessage({
      type:'error', title:'请先完善巡检配置',
      message:`勾选项中有 ${blocked.length} 项暂时无法启用，本次未保存。请编辑以下巡检项，修正后保存草稿并测试。`,
      details:blocked.map(({item, reasons}) => `${item.name || item.id}（${item.id}）\n${reasons.map(reason => `• ${reason}`).join('\n')}`).join('\n\n'),
    });
    return;
  }
  const systemId = selectedSystem;
  const checks = cloneJson(configDocument.config.checks);
  checks.forEach(item => {
    if (item.type !== 'ui' && ids.has(item.id)) item.enabled = true;
  });
  apiChecksEnabling = true;
  syncApiCheckSelection();
  try {
    await persistApiChecks(checks);
    if (selectedSystem !== systemId) return;
    selectedApiCheckIds.clear();
    notice(`已启用 ${ids.size} 项 API 巡检`, 'success');
  } catch (error) {
    notice(`启用失败：${error.message}`, 'error');
  } finally {
    apiChecksEnabling = false;
    syncApiCheckSelection();
  }
}

async function deleteConfigItem(kind, itemId, button) {
  const item = configDocument?.config.checks.find(check => check.id === itemId
    && (check.type === 'ui' ? 'ui' : 'api') === kind);
  if (!item || button.disabled) return;
  const systemId = selectedSystem;
  const systemName = currentSystem()?.display_name || systemId || '当前系统';
  const version = configDocument[`${kind}_version`];
  const label = kind === 'ui' ? 'UI 场景' : 'API 巡检';
  button.disabled = true;
  try {
    const confirmed = await showConfirm({
      type:'warning', title:`删除${label}？`,
      message:`“${item.name || item.id}”将从当前系统的巡检配置中永久删除，后续巡检不再执行此项。历史报告仍会保留。`,
      meta:[
        {label:'当前系统', value:systemName},
        {label:label, value:item.name || item.id},
        {label:'标识', value:item.id},
      ],
      confirmText:'确认删除', cancelText:'取消',
    });
    if (!confirmed) return;
    if (selectedSystem !== systemId) throw new Error('当前系统已切换，请在目标系统中重新删除');
    const collection = kind === 'ui' ? 'ui-scenes' : 'api-checks';
    await api(`/api/${collection}/${encodeURIComponent(itemId)}`, {
      method:'DELETE', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({version}),
    });
    if (selectedSystem !== systemId) return;
    if (lastCreatedCheckId === itemId) lastCreatedCheckId = null;
    await loadConfig();
    await Promise.all([loadSummary(), loadChecks()]);
    notice(`${label}已删除`);
  } catch (error) {
    notice(error.message, 'error');
    if (selectedSystem === systemId) await loadConfig();
  } finally {
    button.disabled = false;
  }
}

async function loadConfig() {
  try {
    const [settings, apiChecks, uiScenes] = await Promise.all([
      api('/api/settings'), api('/api/api-checks'), api('/api/ui-scenes'),
    ]);
    renderConfig({
      config: {
        ...settings.settings,
        api_auth_flows: apiChecks.auth_flows || [],
        checks: [
          ...apiChecks.items.map(item => ({...item, type:'api'})),
          ...uiScenes.items.map(item => ({...item, type:'ui'})),
        ],
      },
      config_version: settings.config_version,
      settings_version: settings.version,
      api_version: apiChecks.version,
      api_enablement: apiChecks.enablement || {},
      auth_verification: apiChecks.verification || {},
      ui_version: uiScenes.version,
      credentials: settings.credentials,
      ui_verification: uiScenes.verification || {},
    });
  }
  catch (error) { notice(error.message, 'error'); }
}

function blankUiScene() {
  return {
    id: '', name: '', category: '', type: 'ui', enabled: false,
    login_precheck: false, alert_enabled: false, severity: 'P2',
    steps: [{id:'open-page', description:'打开业务页面', action:'goto', path:'/', wait_until:'domcontentloaded'}],
  };
}

function normalizeUiId(value) {
  return String(value || '').trim()
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1-$2')
    .replace(/([a-z0-9])([A-Z])/g, '$1-$2')
    .replace(/[^A-Za-z0-9_-]+/g, '-')
    .replace(/[-_]{2,}/g, '-')
    .replace(/^[-_]+|[-_]+$/g, '')
    .toLowerCase();
}

function uiVerification(check) {
  return configDocument?.ui_verification?.[check.id] || {verified:false, verified_at:null};
}

function renderUiScenes() {
  if (!configDocument || !$('#ui-scene-list')) return;
  const scenes = (configDocument.config.checks || []).map((item, index) => ({item, index})).filter(({item}) => item.type === 'ui');
  const query = $('#ui-scene-search').value.trim().toLocaleLowerCase('zh-CN');
  const status = $('#ui-scene-status').value;
  const filtered = scenes.filter(({item}) => {
    const path = (item.steps || []).find(step => step.action === 'goto')?.path || '';
    const verified = uiVerification(item).verified;
    return (!query || `${item.name || ''} ${item.id || ''} ${item.category || ''} ${path}`.toLocaleLowerCase('zh-CN').includes(query))
      && (!status || status === 'enabled' && item.enabled || status === 'draft' && !item.enabled || status === 'verified' && verified);
  });
  const enabled = scenes.filter(({item}) => item.enabled).length;
  const verified = scenes.filter(({item}) => uiVerification(item).verified).length;
  $('#ui-scene-total').textContent = scenes.length;
  $('#ui-scene-enabled').textContent = enabled;
  $('#ui-scene-verified').textContent = verified;
  $('#ui-scene-login').textContent = scenes.filter(({item}) => item.login_precheck).length;
  $('#ui-scene-result').textContent = `显示 ${filtered.length} / ${scenes.length} 项`;
  const target = $('#ui-scene-list');
  target.classList.toggle('empty', filtered.length === 0);
  target.innerHTML = filtered.length ? filtered.map(({item, index}) => {
    const path = (item.steps || []).find(step => step.action === 'goto')?.path || '未配置页面路径';
    const verification = uiVerification(item);
    const dependencyId = item.auth_dependency?.scene_id || item.auth_dependency?.api_flow_id;
    const dependency = item.auth_dependency?.api_flow_id
      ? (configDocument.config.api_auth_flows || []).find(flow => flow.id === dependencyId)
      : dependencyId ? scenes.find(({item: candidate}) => candidate.id === dependencyId)?.item : null;
    const authBadge = item.login_precheck
      ? '<span class="badge accent">登录前置</span>'
      : dependencyId ? `<span class="badge accent">前置：${escapeHtml(dependency?.name || dependencyId)}</span>` : '';
    return `<article class="ui-scene-card"><div class="ui-scene-card-main"><div class="ui-scene-card-title"><b>${escapeHtml(item.name || item.id)}</b><span class="badge ${item.enabled ? 'good' : 'neutral'}">${item.enabled ? '已启用' : '草稿'}</span><span class="badge ${verification.verified ? 'good' : 'neutral'}">${verification.verified ? '已验证' : '待验证'}</span>${authBadge}</div><div class="ui-scene-card-meta"><span>${escapeHtml(item.category || '未分类')}</span><span>·</span><span>${(item.steps || []).length} 步</span><span>·</span><code>${escapeHtml(path)}</code>${verification.verified_at ? `<span>· 验证于 ${escapeHtml(timeText(verification.verified_at))}</span>` : ''}</div></div><div class="ui-scene-card-actions"><button class="button secondary ui-scene-edit" type="button" data-index="${index}">编辑场景</button><button class="button secondary danger-button ui-scene-delete" type="button" data-id="${escapeHtml(item.id)}" aria-label="删除 ${escapeHtml(item.name || item.id)}">删除</button></div></article>`;
  }).join('') : '暂无符合条件的 UI 场景，点击“新建场景”开始配置。';
  target.querySelectorAll('.ui-scene-edit').forEach(button => button.addEventListener('click', () => openUiSceneEditor(Number(button.dataset.index))));
  target.querySelectorAll('.ui-scene-delete').forEach(button => button.addEventListener('click', () => deleteConfigItem('ui', button.dataset.id, button)));
}

async function loadUiWorkspace() {
  try {
    const capabilities = await api('/api/ui/capabilities');
    uiCapabilities = capabilities;
    await loadConfig();
    $('#ui-runtime-state').textContent = capabilities.playwright_installed ? 'Playwright 已安装' : '缺少 Playwright';
    $('#ui-runtime-state').className = `badge ${capabilities.playwright_installed ? 'good' : 'neutral'}`;
  } catch (error) {
    notice(error.message, 'error');
  }
}

function setUiEditorVerified(passed, failed=false) {
  uiEditorFullPassed = !!passed;
  $('#ui-editor-test-state').textContent = passed ? '完整测试已通过' : failed ? '完整测试未通过' : '尚未完整测试';
  $('#ui-editor-test-state').className = `badge ${passed ? 'good' : 'neutral'}`;
}

function invalidateUiVerification() {
  if (!uiEditorDraft) return;
  setUiEditorVerified(false);
}

function commitUiStepForm() {
  if (!uiEditorDraft?.steps?.[selectedUiStepIndex]) return;
  const action = $('#ui-step-action').value;
  const step = {
    id: normalizeUiId($('#ui-step-id').value),
    description: $('#ui-step-description').value.trim(),
    action,
  };
  const timeout = $('#ui-step-timeout').value;
  if (timeout) step.timeout_seconds = Number(timeout);
  if (action === 'goto') {
    step.path = $('#ui-step-path').value.trim();
    step.wait_until = $('#ui-step-wait-until').value;
  } else if (action === 'assert_url') {
    step.expected = $('#ui-step-expected').value;
    step.match = $('#ui-step-match').value;
  } else {
    const type = $('#ui-locator-type').value;
    step.locator = {[type]: $('#ui-locator-value').value.trim()};
    if (type === 'role' && $('#ui-locator-name').value.trim()) step.locator.name = $('#ui-locator-name').value.trim();
    if ($('#ui-locator-exact').checked) step.locator.exact = true;
    if (['fill', 'select'].includes(action)) step.value = $('#ui-step-value').value;
    if (action === 'assert_text') {
      step.expected = $('#ui-step-expected').value;
      step.match = $('#ui-step-match').value;
      if ($('#ui-step-record-actual').checked) step.record_actual = true;
    }
    if (action === 'assert_count') step.expected = Number($('#ui-step-expected').value);
    if (action === 'fill' && $('#ui-step-sensitive').checked) step.sensitive = true;
  }
  // assert_url does not use a locator and therefore follows its own branch above.
  // Persist the login-result marker for every assertion action, regardless of
  // which action-specific fields were collected.
  if (action.startsWith('assert_') && $('#ui-step-authentication').checked) step.authentication_assertion = true;
  uiEditorDraft.steps[selectedUiStepIndex] = step;
}

function uiLoginProviders(currentId='') {
  return (configDocument?.config?.checks || []).filter(item =>
    item.type === 'ui' && item.login_precheck && item.id !== currentId
  );
}

function renderUiAuthDependency() {
  const select = $('#ui-scene-auth-dependency');
  const item = $('#ui-auth-dependency-item');
  const isProvider = $('#ui-scene-login-precheck').checked;
  const apiFlowId = select.value.startsWith('api:') ? select.value.slice(4) : '';
  const apiProvider = (configDocument.config.api_auth_flows || []).find(flow => flow.id === apiFlowId);
  const entryField = $('#ui-api-entry-url');
  if (entryField.dataset.flowId !== apiFlowId) {
    entryField.value = apiProvider?.browser_entry_url || '';
    entryField.dataset.flowId = apiFlowId;
  }
  $('#ui-api-entry-hint').textContent = apiProvider?.browser_entry_url
    ? '已使用流程默认入口，可修改；留空时仍会使用默认入口。'
    : '使用流程输出变量，例如 ${token}。仅依赖 Cookie 时可留空。';
  $('#ui-api-entry-field').classList.toggle('hidden', isProvider || !apiFlowId);
  select.disabled = isProvider;
  if (isProvider) {
    item.classList.add('active', 'provider');
    item.innerHTML = '<span>00</span><i><b>提供登录态</b><small>业务场景可以引用此登录流程</small></i>';
    return;
  }
  item.classList.remove('provider');
  const dependencyId = select.value;
  const provider = apiFlowId
    ? (configDocument.config.api_auth_flows || []).find(flow => flow.id === apiFlowId)
    : uiLoginProviders(uiEditorDraft?.id).find(candidate => candidate.id === dependencyId);
  item.classList.toggle('active', !!dependencyId);
  item.innerHTML = dependencyId
    ? `<span>00</span><i><b>${apiFlowId ? 'API · ' : ''}${escapeHtml(provider?.name || dependencyId)}</b><small>${apiFlowId ? '每轮获取新登录态 · 本轮共享会话' : '登录态失效时执行 · 共享浏览器会话'}</small></i>`
    : '<span>00</span><i><b>未关联登录场景</b><small>业务步骤将直接执行</small></i>';
}

function renderUiStepList() {
  const steps = uiEditorDraft?.steps || [];
  $('#ui-step-count').textContent = `${steps.length} 个业务步骤`;
  renderUiAuthDependency();
  $('#ui-step-list-editor').innerHTML = steps.map((step, index) => `<button class="ui-step-item ${index === selectedUiStepIndex ? 'active' : ''}" type="button" data-step-index="${index}"><span>${String(index + 1).padStart(2, '0')}</span><i><b>${escapeHtml(step.description || '未命名步骤')}</b><small>${escapeHtml(step.action || '待配置')} · ${escapeHtml(step.id || '无 ID')}</small></i></button>`).join('');
  $('#ui-step-list-editor').querySelectorAll('[data-step-index]').forEach(button => button.addEventListener('click', () => {
    commitUiStepForm();
    selectedUiStepIndex = Number(button.dataset.stepIndex);
    renderUiStepList();
    renderUiStepForm();
  }));
}

function syncUiStepFields() {
  const action = $('#ui-step-action').value;
  const locator = !['goto', 'assert_url'].includes(action);
  const visibility = {
    path: action === 'goto', wait_until: action === 'goto', locator_type: locator,
    locator_value: locator, role_name: locator && $('#ui-locator-type').value === 'role', exact: locator,
    value: ['fill', 'select'].includes(action), expected: ['assert_text', 'assert_count', 'assert_url'].includes(action),
    match: ['assert_text', 'assert_url'].includes(action), record_actual: action === 'assert_text',
    sensitive: action === 'fill', authentication: action.startsWith('assert_') && $('#ui-scene-login-precheck').checked,
  };
  document.querySelectorAll('[data-ui-field]').forEach(field => field.classList.toggle('hidden', !visibility[field.dataset.uiField]));
  $('#ui-locator-value-label').textContent = ({test_id:'Test ID',role:'角色名称',label:'表单标签',placeholder:'占位文字',text:'页面文本',css:'CSS 选择器'})[$('#ui-locator-type').value] || '定位值';
}

function renderUiStepForm() {
  const step = uiEditorDraft?.steps?.[selectedUiStepIndex];
  if (!step) return;
  $('#ui-step-number').textContent = `STEP ${String(selectedUiStepIndex + 1).padStart(2, '0')}`;
  $('#ui-step-id').value = step.id || '';
  $('#ui-step-description').value = step.description || '';
  $('#ui-step-action').value = step.action || 'goto';
  $('#ui-step-path').value = step.path || '';
  $('#ui-step-wait-until').value = step.wait_until || 'domcontentloaded';
  const locatorType = ['test_id','role','label','placeholder','text','css'].find(key => step.locator && Object.prototype.hasOwnProperty.call(step.locator, key)) || 'test_id';
  $('#ui-locator-type').value = locatorType;
  $('#ui-locator-value').value = step.locator?.[locatorType] || '';
  $('#ui-locator-name').value = step.locator?.name || '';
  $('#ui-locator-exact').checked = !!step.locator?.exact;
  $('#ui-step-value').value = step.value ?? '';
  $('#ui-step-expected').value = step.expected ?? '';
  $('#ui-step-match').value = step.match || 'contains';
  $('#ui-step-timeout').value = step.timeout_seconds ?? '';
  $('#ui-step-record-actual').checked = !!step.record_actual;
  $('#ui-step-sensitive').checked = !!step.sensitive;
  $('#ui-step-authentication').checked = !!step.authentication_assertion;
  $('#ui-step-up').disabled = selectedUiStepIndex === 0;
  $('#ui-step-down').disabled = selectedUiStepIndex >= uiEditorDraft.steps.length - 1;
  $('#ui-step-delete').disabled = uiEditorDraft.steps.length <= 1;
  syncUiStepFields();
}

function renderUiTestResult(result) {
  const target = $('#ui-test-result');
  const check = result.check;
  if (!check) {
    target.className = 'ui-test-empty';
    target.innerHTML = `<span>!</span><b>会话准备失败</b><p>${escapeHtml(result.session_checks?.find(item => item.status !== 'passed')?.reason || '候选场景未执行')}</p>`;
    return;
  }
  const steps = check.steps || [];
  target.className = '';
  const prerequisites = (result.session_checks || []).map(item => `<div class="ui-test-prerequisite ${item.status === 'passed' ? 'passed' : 'failed'}"><b>${item.status === 'passed' ? '✓' : '×'} 前置登录 · ${escapeHtml(item.name || item.id)}</b><small>${item.status === 'passed' ? '已在共享浏览器会话中完成' : escapeHtml(item.reason || '执行失败')}</small></div>`).join('');
  target.innerHTML = `<div class="ui-test-summary"><b>${result.status === 'passed' ? '✓ 测试通过' : '× 测试失败'} · ${escapeHtml(check.name)}</b><small>${result.full_test ? '完整场景' : '到当前步骤'} · ${steps.length} 步 · ${formatDuration(check.duration_ms)}</small></div>${prerequisites}<div class="ui-test-steps">${steps.map(step => {
    const evidence = step.failure_screenshot || step.screenshot;
    const image = evidence?.artifact_id ? uiTestArtifactUrl(result.test_id, evidence.artifact_id) : '';
    return `<article class="ui-test-step"><div class="ui-test-step-copy"><b>${step.status === 'passed' ? '✓' : '×'} ${String(step.sequence).padStart(2, '0')} · ${escapeHtml(step.description)}</b><small>${escapeHtml(step.action)} · ${formatDuration(step.duration_ms)}${step.reason ? ` · ${escapeHtml(step.reason)}` : ''}</small></div>${image ? renderScreenshotButton(image, `${step.description} 的测试截图`, step, step.failure_screenshot ? '失败截图' : '测试截图') : ''}</article>`;
  }).join('')}</div>`;
}

function openUiSceneEditor(index=-1) {
  if (!configDocument) return notice('配置尚未载入，请稍后重试', 'error');
  const existing = index >= 0 ? configDocument.config.checks[index] : null;
  uiEditorIndex = index;
  uiEditorDraft = cloneJson(existing || blankUiScene());
  selectedUiStepIndex = 0;
  $('#ui-scene-index').value = String(index);
  $('#ui-editor-title').textContent = existing ? `编辑 UI 场景 · ${existing.name}` : '新建 UI 场景';
  $('#ui-scene-id').value = uiEditorDraft.id || '';
  $('#ui-scene-id').readOnly = !!existing;
  $('#ui-scene-name').value = uiEditorDraft.name || '';
  $('#ui-scene-category').value = uiEditorDraft.category || '';
  $('#ui-scene-severity').value = uiEditorDraft.severity || 'P2';
  $('#ui-scene-login-precheck').checked = !!uiEditorDraft.login_precheck;
  const authSelect = $('#ui-scene-auth-dependency');
  const providers = uiLoginProviders(uiEditorDraft.id);
  const apiProviders = (configDocument.config.api_auth_flows || []).filter(flow => flow.enabled);
  authSelect.innerHTML = '<option value="">不使用前置登录态</option>'
    + (apiProviders.length ? `<optgroup label="API 登录流程">${apiProviders.map(flow => `<option value="api:${escapeHtml(flow.id)}">${escapeHtml(flow.name || flow.id)}</option>`).join('')}</optgroup>` : '')
    + (providers.length ? `<optgroup label="UI 登录场景">${providers.map(provider => `<option value="${escapeHtml(provider.id)}">${escapeHtml(provider.name || provider.id)}（${escapeHtml(provider.id)}）${provider.enabled ? '' : ' · 草稿'}</option>`).join('')}</optgroup>` : '');
  const apiFlowId = uiEditorDraft.auth_dependency?.api_flow_id;
  if (apiFlowId && !apiProviders.some(flow => flow.id === apiFlowId)) {
    authSelect.insertAdjacentHTML('beforeend', `<option value="api:${escapeHtml(apiFlowId)}">${escapeHtml(apiFlowId)} · 未启用</option>`);
  }
  authSelect.value = apiFlowId ? `api:${apiFlowId}` : uiEditorDraft.auth_dependency?.scene_id || '';
  $('#ui-api-entry-url').value = uiEditorDraft.auth_dependency?.entry_url
    || apiProviders.find(flow => flow.id === apiFlowId)?.browser_entry_url || '';
  $('#ui-api-entry-url').dataset.flowId = apiFlowId || '';
  $('#ui-scene-alert').checked = !!uiEditorDraft.alert_enabled;
  $('#ui-test-result').className = 'ui-test-empty';
  $('#ui-test-result').innerHTML = '<span>◎</span><b>等待测试</b><p>选择“测试到当前步骤”快速调试；测试未通过也可保存并启用。</p>';
  setUiEditorVerified(!!existing && uiVerification(existing).verified);
  renderUiStepList();
  renderUiStepForm();
  $('#ui-editor-layer').classList.remove('hidden');
  $('#ui-editor-layer').setAttribute('aria-hidden', 'false');
  document.body.classList.add('ui-editor-open');
  (existing ? $('#ui-scene-name') : $('#ui-scene-id')).focus();
}

function closeUiSceneEditor() {
  if ($('#ui-editor-layer').classList.contains('hidden')) return;
  $('#ui-editor-layer').classList.add('hidden');
  $('#ui-editor-layer').setAttribute('aria-hidden', 'true');
  document.body.classList.remove('ui-editor-open');
  uiEditorDraft = null;
}

function collectUiScene(enabled=false) {
  commitUiStepForm();
  const scene = cloneJson(uiEditorDraft);
  scene.id = normalizeUiId($('#ui-scene-id').value);
  scene.name = $('#ui-scene-name').value.trim();
  scene.category = $('#ui-scene-category').value.trim();
  scene.type = 'ui';
  scene.enabled = enabled;
  scene.login_precheck = $('#ui-scene-login-precheck').checked;
  const dependencyId = $('#ui-scene-auth-dependency').value;
  if (!scene.login_precheck && dependencyId) {
    scene.auth_dependency = {
      ...(dependencyId.startsWith('api:')
        ? {api_flow_id: dependencyId.slice(4), entry_url: $('#ui-api-entry-url').value.trim()}
        : {scene_id: dependencyId, run_policy: 'when-invalid'}),
      share_browser_context: true,
    };
  } else {
    delete scene.auth_dependency;
  }
  scene.alert_enabled = $('#ui-scene-alert').checked;
  scene.severity = $('#ui-scene-severity').value;
  if (!/^[a-z0-9][a-z0-9_-]{1,63}$/.test(scene.id)) throw new Error('场景 ID 需使用 2-64 位小写字母、数字、- 或 _');
  if (!scene.name) throw new Error('场景名称不能为空');
  if (!scene.category) throw new Error('业务模块不能为空');
  const duplicate = configDocument.config.checks.some((item, index) => index !== uiEditorIndex && item.id === scene.id);
  if (duplicate) throw new Error(`检查项 ID 已存在：${scene.id}`);
  uiEditorDraft = cloneJson(scene);
  return scene;
}

function setUiEditorBusy(busy) {
  ['#ui-scene-save-draft','#ui-scene-test-through','#ui-scene-test-full','#ui-editor-close'].forEach(selector => { $(selector).disabled = busy; });
  $('#ui-scene-save-enable').disabled = busy;
}

async function saveUiScene(enabled=false) {
  try {
    setUiEditorBusy(true);
    const scene = collectUiScene(enabled);
    const config = cloneJson(configDocument.config);
    if (uiEditorIndex >= 0) config.checks[uiEditorIndex] = scene;
    else config.checks.push(scene);
    await persistUiScenes(config.checks);
    uiEditorIndex = configDocument.config.checks.findIndex(item => item.id === scene.id);
    if (enabled) closeUiSceneEditor();
    notice(`${enabled ? '已保存并启用' : '草稿已保存'}：${scene.name}`);
  } catch (error) {
    notice(error.message, 'error');
  } finally {
    setUiEditorBusy(false);
  }
}

async function testUiScene(throughStep=false) {
  let scene;
  try {
    scene = collectUiScene(false);
    setUiEditorBusy(true);
    $('#ui-test-result').className = 'ui-test-empty';
    $('#ui-test-result').innerHTML = '<span>◌</span><b>浏览器正在执行</b><p>正在逐步操作页面并生成截图证据…</p>';
    const path = throughStep ? '/api/ui-scenes/test-through-step' : '/api/ui-scenes/test';
    const body = {check:scene};
    if (throughStep) body.through_step_id = scene.steps[selectedUiStepIndex]?.id;
    const result = await api(path, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
    renderUiTestResult(result);
    if (!throughStep) {
      setUiEditorVerified(result.status === 'passed' && result.verified, result.status !== 'passed');
      if (uiEditorFullPassed) {
        configDocument.ui_verification[scene.id] = {verified:true, verified_at:new Date().toISOString()};
        renderUiScenes();
      }
    }
    notice(result.status === 'passed' ? 'UI 场景测试通过，截图证据已生成' : 'UI 场景测试未通过，请查看右侧失败步骤', result.status === 'passed' ? 'success' : 'error');
  } catch (error) {
    setUiEditorVerified(false);
    notice(error.message, 'error');
    $('#ui-test-result').className = 'ui-test-empty';
    $('#ui-test-result').innerHTML = `<span>!</span><b>无法执行测试</b><p>${escapeHtml(error.message)}</p>`;
  } finally {
    setUiEditorBusy(false);
  }
}

function addUiStep() {
  commitUiStepForm();
  const sequence = uiEditorDraft.steps.length + 1;
  uiEditorDraft.steps.push({id:`step-${sequence}`, description:'新步骤', action:'assert_visible', locator:{test_id:''}});
  selectedUiStepIndex = uiEditorDraft.steps.length - 1;
  invalidateUiVerification(); renderUiStepList(); renderUiStepForm();
}

function moveUiStep(offset) {
  commitUiStepForm();
  const target = selectedUiStepIndex + offset;
  if (target < 0 || target >= uiEditorDraft.steps.length) return;
  [uiEditorDraft.steps[selectedUiStepIndex], uiEditorDraft.steps[target]] = [uiEditorDraft.steps[target], uiEditorDraft.steps[selectedUiStepIndex]];
  selectedUiStepIndex = target;
  invalidateUiVerification(); renderUiStepList(); renderUiStepForm();
}

function duplicateUiStep() {
  commitUiStepForm();
  const step = cloneJson(uiEditorDraft.steps[selectedUiStepIndex]);
  step.id = `${step.id || 'step'}-copy`.slice(0, 64);
  step.description = `${step.description || '步骤'}（副本）`;
  uiEditorDraft.steps.splice(selectedUiStepIndex + 1, 0, step);
  selectedUiStepIndex += 1;
  invalidateUiVerification(); renderUiStepList(); renderUiStepForm();
}

function deleteUiStep() {
  if (uiEditorDraft.steps.length <= 1) return;
  uiEditorDraft.steps.splice(selectedUiStepIndex, 1);
  selectedUiStepIndex = Math.min(selectedUiStepIndex, uiEditorDraft.steps.length - 1);
  invalidateUiVerification(); renderUiStepList(); renderUiStepForm();
}

function environmentDraft() {
  if (!configDocument) throw new Error('配置尚未载入');
  const config = cloneJson(configDocument.config);
  config.system_id = $('#config-system-id').value.trim();
  config.environment = $('#config-environment').value.trim();
  config.base_url = $('#config-base-url').value.trim().replace(/\/$/, '');
  config.default_timeout_seconds = Number($('#config-timeout').value);
  config.report_limit = Number($('#config-report-limit').value);
  const scheduleTargets = [
    $('#schedule-target-api').checked ? 'api' : null,
    $('#schedule-target-ui').checked ? 'ui' : null,
  ].filter(Boolean);
  if (!scheduleTargets.length) throw new Error('定时执行范围至少选择 API 或 UI');
  config.schedule = {
    enabled: $('#schedule-enabled').checked,
    targets: scheduleTargets,
    timezone: $('#schedule-timezone').value.trim(),
    mode: $('#schedule-mode').value,
    interval_minutes: Number($('#schedule-interval').value),
    daily_times: $('#schedule-daily-times').value.split(',').map(value => value.trim()).filter(Boolean),
    misfire_grace_minutes: Number($('#schedule-grace').value),
    overlap_policy: 'skip',
  };
  config.run_retry = {
    enabled: $('#run-retry-enabled').checked,
    max_retries: Number($('#run-retry-max').value),
    delay_seconds: Number($('#run-retry-delay').value),
  };
  config.alerts = {
    enabled: $('#alerts-enabled').checked,
    notify_on_success: $('#alerts-notify-success').checked,
    report_base_url: $('#alerts-report-base-url').value.trim().replace(/\/+$/, ''),
    failure_threshold: Number($('#alerts-failure-threshold').value),
    recovery_threshold: Number($('#alerts-recovery-threshold').value),
    repeat_interval_minutes: Number($('#alerts-repeat').value),
    default_severity: $('#alerts-severity').value,
    channels: ['webhook'],
  };
  return config;
}

function credentialDraft() {
  return {
    account: $('#config-account').value.trim(),
    username: $('#config-username').value.trim(),
    password: $('#config-password').value,
    client_id: $('#config-client-id').value.trim(),
    ui_username: $('#config-ui-username').value.trim(),
    ui_password: $('#config-ui-password').value,
    webhook_url: $('#alerts-webhook').value.trim(),
    dingtalk_secret: $('#alerts-dingtalk-secret').value.trim(),
  };
}

async function persistSettings(config, credentials={}) {
  const webhookWasSubmitted = !!credentials.webhook_url?.trim();
  const dingtalkSecretWasSubmitted = !!credentials.dingtalk_secret?.trim();
  const uiPasswordWasSubmitted = !!credentials.ui_password;
  const settings = cloneJson(config);
  delete settings.checks;
  delete settings.api_auth_flows;
  const saved = await api('/api/settings', {
    method: 'PUT', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({version: configDocument.settings_version, settings, credentials}),
  });
  if (webhookWasSubmitted && saved.credentials?.webhook_configured !== true) {
    throw new Error('Webhook 未被后端保存，请重启巡检服务后重试');
  }
  if (dingtalkSecretWasSubmitted && saved.credentials?.dingtalk_secret_configured !== true) {
    throw new Error('钉钉加签密钥未被后端保存，请重启巡检服务后重试');
  }
  if (uiPasswordWasSubmitted && saved.credentials?.ui_password_configured !== true) {
    throw new Error('UI 登录密码未被后端保存，请重启巡检服务后重试');
  }
  await loadConfig();
  await Promise.all([loadSummary(), loadChecks()]);
  return saved;
}

async function persistApiChecks(checks, authFlows=configDocument.config.api_auth_flows || []) {
  const items = checks.filter(item => item.type !== 'ui').map(item => {
    const copy = cloneJson(item); delete copy.type; return copy;
  });
  const saved = await api('/api/api-checks', {
    method:'PUT', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({version:configDocument.api_version, items, auth_flows:authFlows}),
  });
  await loadConfig();
  await Promise.all([loadSummary(), loadChecks()]);
  return saved;
}

async function persistUiScenes(checks) {
  const items = checks.filter(item => item.type === 'ui').map(item => {
    const copy = cloneJson(item); delete copy.type; return copy;
  });
  const saved = await api('/api/ui-scenes', {
    method:'PUT', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({version:configDocument.ui_version, items}),
  });
  await loadConfig();
  await Promise.all([loadSummary(), loadChecks()]);
  return saved;
}

async function persistFullConfig(config, credentials={}) {
  const saved = await api('/api/config', {
    method:'PUT', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({config_version:configDocument.config_version, config, credentials}),
  });
  await loadConfig();
  await Promise.all([loadSummary(), loadChecks()]);
  return saved;
}

let authFlowEditor = null;
let authFlowBusy = false;

function renderAuthFlows() {
  const flows = configDocument.config.api_auth_flows || [];
  const checks = configDocument.config.checks || [];
  $('#auth-flow-count').textContent = `${flows.length} 个流程`;
  $('#auth-flow-list').innerHTML = flows.length ? flows.map(flow => {
    const verified = configDocument.auth_verification?.[flow.id]?.verified;
    const steps = flow.step_ids.map(id => checks.find(check => check.id === id));
    const dependents = checks.filter(check => check.auth_flow_id === flow.id).length;
    const uiDependents = checks.filter(check => check.auth_dependency?.api_flow_id === flow.id).length;
    return `<section class="auth-flow-card"><div class="auth-flow-card-title"><div><h3>${escapeHtml(flow.name)}</h3><small>${escapeHtml(flow.id)} · ${steps.length} 个步骤 · ${dependents} 个接口引用${uiDependents ? ` · ${uiDependents} 个 UI 场景引用` : ''}</small></div><span class="badge ${flow.enabled ? 'good' : verified ? 'accent' : 'neutral'}">${flow.enabled ? '已启用' : verified ? '已验证 · 待启用' : '草稿 · 待验证'}</span></div><ol class="auth-flow-chain">${steps.map(step => `<li>${escapeHtml(step?.name || '步骤不存在')}<small>${escapeHtml((step?.extract || []).map(rule => rule.variable).join('、') || '验证登录状态')}</small></li>`).join('')}</ol><div class="auth-flow-card-footer"><span>输出 ${escapeHtml(Object.keys(flow.outputs).join('、'))} · 本轮共享，运行后释放</span><div><button class="button secondary auth-flow-edit" type="button" data-id="${escapeHtml(flow.id)}">编辑流程</button><button class="button secondary danger-button auth-flow-delete" type="button" data-id="${escapeHtml(flow.id)}">删除</button></div></div></section>`;
  }).join('') : '<div class="empty">暂无登录前置流程，可创建流程并配置步骤。</div>';
  document.querySelectorAll('.auth-flow-edit').forEach(button => button.addEventListener('click', () => openAuthFlow(button.dataset.id)));
  document.querySelectorAll('.auth-flow-delete').forEach(button => button.addEventListener('click', () => deleteAuthFlow(button.dataset.id)));
}

function renderAuthEditorControls() {
  const active = !!authFlowEditor;
  $('#check-form').classList.toggle('is-auth-flow', active);
  $('#auth-flow-meta').classList.toggle('hidden', !active);
  $('#auth-flow-steps').classList.toggle('hidden', !active);
  $('#auth-flow-step-actions').classList.toggle('hidden', !active);
  $('#check-auth-flow-field').classList.toggle('hidden', active);
  $('.api-section-rail-head h3').textContent = active ? '登录步骤' : '接口配置';
  $('.api-test-panel-head h3').textContent = active ? '流程测试与输出' : '测试与响应';
  $('#check-test').textContent = active ? '测试完整流程' : '测试接口';
  $('#check-save-enable').textContent = active ? '保存并启用流程' : '保存并启用';
  if (!active) return;
  $('#api-editor-title').textContent = '编辑登录前置流程';
  $('#api-editor-description').textContent = '步骤按顺序执行，共享 Cookie 和变量；最后验证通过后发布 token。';
  $('#api-editor-save-hint').textContent = authFlowEditor.flow.enabled ? '保存草稿将停用流程及引用它的接口' : '草稿不会参与自动巡检';
  $('#auth-flow-steps').innerHTML = authFlowEditor.steps.map((step, index) => {
    const result = authFlowEditor.result?.checks?.find(item => item.id === step.id);
    const status = result ? ({passed:'通过', failed:'失败', skipped:'未执行'}[result.status] || '') : '待测试';
    return `<button type="button" class="auth-step ${index === authFlowEditor.current ? 'active' : ''}" data-index="${index}" aria-current="${index === authFlowEditor.current ? 'step' : 'false'}"><span>${String(index+1).padStart(2,'0')}</span><i><b>${escapeHtml(step.name || '新步骤')}</b><small>${escapeHtml((step.extract || []).map(rule => rule.variable).join('、') || '验证业务状态')}</small></i><em>${status}</em></button>`;
  }).join('');
  $('#auth-flow-steps').querySelectorAll('button').forEach(button => button.addEventListener('click', () => selectAuthStep(Number(button.dataset.index))));
  $('#auth-step-up').disabled = authFlowEditor.current === 0;
  $('#auth-step-down').disabled = authFlowEditor.current === authFlowEditor.steps.length - 1;
  $('#auth-step-remove').disabled = authFlowEditor.steps.length <= 1;
  if (authFlowBusy) document.querySelectorAll('#auth-flow-steps button, #auth-flow-step-actions button').forEach(button => { button.disabled = true; });
}

function openAuthFlow(id=null) {
  if (!configDocument) return;
  const existing = (configDocument.config.api_auth_flows || []).find(flow => flow.id === id);
  const flow = cloneJson(existing || {id:'', name:'', enabled:false, step_ids:[], outputs:{token:'suposTicket'}});
  const steps = existing ? flow.step_ids.map(sid => cloneJson(configDocument.config.checks.find(check => check.id === sid))) : [
    {...blankCheck(), id:`login-${Date.now()}`, name:'登录请求', category:'登录前置', session_setup:true},
  ];
  authFlowEditor = {flow, steps, current:0, originalFlowId:existing?.id || null, originalIds:[...(existing?.step_ids || [])], result:null};
  $('#auth-flow-id').value = flow.id;
  $('#auth-flow-id').readOnly = !!existing;
  $('#auth-flow-name').value = flow.name;
  $('#auth-flow-outputs').value = pretty(flow.outputs);
  $('#auth-flow-browser-entry').value = flow.browser_entry_url || '';
  populateCheckEditor(steps[0], configDocument.config.checks.findIndex(check => check.id === steps[0].id), !existing);
  apiEditorInitialSnapshot = apiEditorSnapshot();
  apiEditorDirty = false;
  (existing ? $('#auth-flow-name') : $('#auth-flow-id')).focus();
}

function normalizeAuthStep(step) {
  const result = {...step, id:step.id.trim(), name:(step.name || '').trim(), category:(step.category || '').trim(),
    method:step.method || 'POST', expected_status:step.expected_status ?? 200,
    response_type:step.response_type || 'json', follow_redirects:step.follow_redirects !== false,
    severity:step.severity || 'P2', alert_enabled:!!step.alert_enabled,
    headers:step.headers || {}, body:step.body ?? null, assertions:step.assertions || [], extract:step.extract || []};
  if (result.body_encoding !== 'form') delete result.body_encoding;
  if (result.timeout_seconds == null) delete result.timeout_seconds;
  return result;
}

function authFlowDraft(enabled, validate=false) {
  const steps = cloneJson(authFlowEditor.steps).map(normalizeAuthStep);
  steps[authFlowEditor.current] = checkDraft(false, validate);
  const flow = {...cloneJson(authFlowEditor.flow), id:$('#auth-flow-id').value.trim(), name:$('#auth-flow-name').value.trim(), enabled,
    step_ids:steps.map(step => step.id), outputs:parseEditor('#auth-flow-outputs','输出变量映射',{})};
  const browserEntry = $('#auth-flow-browser-entry').value.trim();
  if (browserEntry) flow.browser_entry_url = browserEntry;
  else delete flow.browser_entry_url;
  if (validate && (!/^[a-z0-9][a-z0-9_-]{1,63}$/.test(flow.id) || !flow.name)) throw new Error('请填写有效的流程 ID 和流程名称');
  if (validate && (configDocument.config.api_auth_flows || []).some(item => item.id === flow.id && item.id !== authFlowEditor.originalFlowId)) throw new Error('登录前置流程 ID 已存在，请使用不同的 ID');
  steps.forEach((step, index) => {
    step.enabled = enabled;
    step.type = 'api';
    step.session_setup = true;
    step.login_precheck = index === steps.length - 1;
    delete step.auth_flow_id;
  });
  return {flow, steps};
}

function flushAuthStep() {
  const draft = authFlowDraft(false, false);
  authFlowEditor.steps = draft.steps;
  authFlowEditor.flow = {...draft.flow, enabled:authFlowEditor.flow.enabled};
}

function displayAuthStep() {
  const initial = apiEditorInitialSnapshot, tested = apiEditorTestedSnapshot, returnFocus = drawerReturnFocus;
  const step = authFlowEditor.steps[authFlowEditor.current];
  populateCheckEditor(step, configDocument.config.checks.findIndex(check => check.id === step.id), !authFlowEditor.originalIds.includes(step.id));
  apiEditorInitialSnapshot = initial;
  apiEditorTestedSnapshot = tested;
  drawerReturnFocus = returnFocus;
  if (authFlowEditor.result) {
    renderAuthFlowResult(authFlowEditor.result, false);
    setApiEditorTestState(authFlowEditor.result.status === 'passed' ? 'passed' : 'failed');
  }
  syncApiEditorDirtyState();
  $('#check-name').focus();
}

function selectAuthStep(index) {
  if (authFlowBusy || index === authFlowEditor.current) return;
  try { flushAuthStep(); authFlowEditor.current = index; displayAuthStep(); }
  catch (error) { notice(error.message, 'error'); }
}

function addAuthStep() {
  if (authFlowBusy) return;
  try {
    flushAuthStep();
    authFlowEditor.steps.push({...blankCheck(), id:`login-step-${Date.now()}`, name:'新登录步骤', category:'登录前置', session_setup:true});
    authFlowEditor.current = authFlowEditor.steps.length - 1;
    authFlowEditor.result = null;
    displayAuthStep();
  } catch (error) { notice(error.message, 'error'); }
}

function moveAuthStep(delta) {
  if (authFlowBusy) return;
  const index = authFlowEditor.current, next = index + delta;
  if (next < 0 || next >= authFlowEditor.steps.length) return;
  try {
    flushAuthStep();
    [authFlowEditor.steps[index],authFlowEditor.steps[next]] = [authFlowEditor.steps[next],authFlowEditor.steps[index]];
    authFlowEditor.current = next;
    authFlowEditor.result = null;
    displayAuthStep();
  } catch (error) { notice(error.message, 'error'); }
}

async function removeAuthStep() {
  if (authFlowBusy || authFlowEditor.steps.length <= 1) return;
  const confirmed = await showConfirm({type:'warning', title:'移除当前登录步骤？', message:'保存流程后该步骤将一并移除，请检查后续变量依赖。', confirmText:'移除步骤', cancelText:'取消'});
  if (!confirmed || !authFlowEditor) return;
  try {
    flushAuthStep();
    authFlowEditor.steps.splice(authFlowEditor.current,1);
    authFlowEditor.current = Math.min(authFlowEditor.current,authFlowEditor.steps.length-1);
    authFlowEditor.result = null;
    displayAuthStep();
  } catch (error) { notice(error.message, 'error'); }
}

function renderAuthFlowResult(result, markTest=true) {
  const passed = result.status === 'passed';
  const failure = result.checks.find(check => check.status === 'failed');
  $('#check-test-result').className = 'api-test-result';
  $('#check-test-result').innerHTML = `<div class="api-test-summary"><div class="api-test-summary-row"><div><b>${passed ? '登录前置验证通过' : '登录前置验证失败'}</b><small>临时测试，不写入巡检报告或告警</small></div><span class="badge ${passed ? 'good' : 'bad'}">${passed ? '通过' : '失败'}</span></div>${failure ? `<p class="api-test-reason">${escapeHtml(failure.name)}：${escapeHtml(failure.reason || '执行失败')}</p>` : ''}</div><section class="api-test-group"><h4>步骤执行结果</h4>${result.checks.map((check,index) => `<details class="auth-step-result" ${check.status === 'failed' ? 'open' : ''}><summary><b>${index+1}. ${escapeHtml(check.name)}</b><span class="badge ${check.status === 'passed' ? 'good' : check.status === 'failed' ? 'bad' : 'neutral'}">${({passed:'通过',failed:'失败',skipped:'未执行'})[check.status]}</span></summary><p>HTTP ${escapeHtml(check.evidence?.http_status ?? '—')} · ${escapeHtml(formatDuration(check.duration_ms || 0))}</p>${check.reason ? `<p class="api-test-reason">${escapeHtml(check.reason)}</p>` : ''}${(check.extracted_variables || []).map(variable => `<p><code>${escapeHtml(variable.name)}</code> · ${variable.present ? '已获取 · 已脱敏' : '未获取'}</p>`).join('')}${(check.assertions || []).map(assertion => `<p>${assertion.passed ? '通过' : '失败'} · ${escapeHtml(assertion.path || '')}</p>`).join('')}<pre class="api-test-evidence">${escapeHtml(pretty(check.evidence || {}))}</pre></details>`).join('')}</section><section class="api-test-group"><h4>流程输出</h4>${result.outputs.map(output => `<div class="api-test-item"><i><b>${escapeHtml(output.name)} ← ${escapeHtml(output.source)}</b><small>${escapeHtml(output.value)}</small></i></div>`).join('')}<p class="field-hint">输出仅在全部步骤通过后供本轮业务请求使用；测试不会保存 token。</p></section>`;
  if (markTest) {
    setApiEditorTestState(passed ? 'passed' : 'failed');
    apiEditorTestedSnapshot = apiEditorSnapshot();
  }
  renderAuthEditorControls();
}

async function testAuthFlow() {
  let draft;
  try { draft = authFlowDraft(false,true); }
  catch (error) { notice(error.message,'error'); return; }
  authFlowEditor.steps = draft.steps;
  setCheckEditorBusy(true);
  setApiEditorTestState('running');
  $('#check-test-result').className = 'api-test-empty';
  $('#check-test-result').innerHTML = '<b>正在测试完整登录流程</b><p>从第一步重新建立会话，依次提取票据并验证身份…</p>';
  try {
    const result = await api('/api/api-auth-flows/test', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(draft)});
    authFlowEditor.result = result;
    renderAuthFlowResult(result);
    notice(result.status === 'passed' ? '完整流程验证通过，可以保存并启用' : '登录流程失败，请查看失败步骤', result.status === 'passed' ? 'success' : 'error');
  } catch (error) {
    setApiEditorTestState('failed');
    $('#check-test-result').innerHTML = `<div class="api-test-summary"><p class="api-test-reason">${escapeHtml(error.message)}</p></div>`;
    notice(error.message,'error');
  } finally { setCheckEditorBusy(false); renderAuthEditorControls(); }
}

async function persistAuthFlow(enabled) {
  try {
    const draft = authFlowDraft(enabled,true);
    const activeUiDependents = configDocument.config.checks.filter(check => check.enabled && check.auth_dependency?.api_flow_id === draft.flow.id);
    if (!enabled && activeUiDependents.length) throw new Error(`请先停用引用此流程的 UI 场景：${activeUiDependents.map(check => check.name || check.id).join('、')}`);
    if (enabled && (authFlowEditor.result?.status !== 'passed' || apiEditorTestedSnapshot !== apiEditorSnapshot())) throw new Error('请先对当前配置完整测试通过，再启用流程');
    const ids = new Set([...authFlowEditor.originalIds,...draft.flow.step_ids]);
    const checks = configDocument.config.checks.filter(check => !ids.has(check.id));
    checks.unshift(...draft.steps);
    let disabledDependents = 0;
    if (!enabled) checks.forEach(check => { if (check.auth_flow_id === draft.flow.id && check.enabled) { check.enabled = false; disabledDependents += 1; } });
    const flows = (configDocument.config.api_auth_flows || []).filter(flow => flow.id !== authFlowEditor.originalFlowId);
    flows.push(draft.flow);
    setCheckEditorBusy(true);
    await persistApiChecks(checks,flows);
    closeCheckEditor(true);
    notice(enabled ? '登录前置流程已整体启用' : `登录前置草稿已保存${disabledDependents ? `，已停用 ${disabledDependents} 个关联接口` : ''}`,'success');
  } catch (error) { notice(error.message,'error'); }
  finally { setCheckEditorBusy(false); }
}

async function deleteAuthFlow(id) {
  const dependents = configDocument.config.checks.filter(check => check.auth_flow_id === id || check.auth_dependency?.api_flow_id === id);
  if (dependents.length) { notice(`请先解除 ${dependents.map(check => check.name).join('、')} 对此流程的引用`,'error'); return; }
  const flow = configDocument.config.api_auth_flows.find(item => item.id === id);
  if (!await showConfirm({type:'warning',title:'删除登录前置流程？',message:`将删除“${flow.name}”及其中全部步骤。`,confirmText:'删除流程',cancelText:'取消'})) return;
  try {
    await persistApiChecks(configDocument.config.checks.filter(check => !flow.step_ids.includes(check.id)),configDocument.config.api_auth_flows.filter(item => item.id !== id));
    notice('登录前置流程已删除','success');
  } catch (error) { notice(error.message,'error'); }
}

function blankCheck() {
  return {
    id: '', name: '', category: '', method: 'POST', path: '',
    headers: {}, body: {}, expected_status: 200, assertions: [], extract: [],
    timeout_seconds: 10, alert_enabled: false,
    enabled: false, severity: 'P2',
  };
}

function setFieldHint(selector, message, kind='') {
  const hint = $(selector);
  hint.textContent = message;
  hint.className = `field-hint ${kind}`.trim();
}

function normalizeCheckIdInput() {
  const input = $('#check-id');
  const raw = input.value.trim();
  const normalized = raw
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1-$2')
    .replace(/([a-z0-9])([A-Z])/g, '$1-$2')
    .replace(/[^A-Za-z0-9_-]+/g, '-')
    .replace(/[-_]{2,}/g, '-')
    .replace(/^[-_]+|[-_]+$/g, '')
    .toLowerCase();
  input.value = normalized;
  if (raw && normalized !== raw) {
    setFieldHint('#check-id-hint', `已自动转换为 ${normalized || '无效 ID'}`, normalized ? 'good' : 'bad');
  } else {
    setFieldHint('#check-id-hint', '使用小写字母、数字、短横线或下划线。');
  }
  return normalized;
}

function normalizeCheckPathInput(existingOrigin=null) {
  const input = $('#check-path');
  const raw = input.value.trim();
  if (!raw) return {path: raw, origin: existingOrigin};
  if (!/^[A-Za-z][A-Za-z0-9+.-]*:/.test(raw)) {
    if (!raw.startsWith('/') || raw.startsWith('//') || raw.includes('#')) {
      throw new Error('请求路径必须以 / 开头，且不能包含 # 片段');
    }
    input.value = raw;
    setFieldHint('#check-path-hint', existingOrigin ? `请求来源：${existingOrigin}` : '使用当前系统基础地址。');
    return {path: raw, origin: existingOrigin};
  }

  let url;
  try { url = new URL(raw); }
  catch { throw new Error('请求地址不是有效的 HTTP(S) URL'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash) {
    throw new Error('请求地址仅支持无账号信息、无 # 片段的 HTTP(S) URL');
  }
  const baseOrigin = new URL(configDocument.config.base_url).origin;
  const allowedOrigins = new Set([baseOrigin, ...(configDocument.config.allowed_origins || [])].map(value => {
    try { return new URL(value).origin; }
    catch { return value.replace(/\/$/, ''); }
  }));
  if (!allowedOrigins.has(url.origin)) {
    throw new Error(`接口来源 ${url.origin} 不在当前系统允许范围内`);
  }
  const path = `${url.pathname}${url.search}`;
  const origin = url.origin === baseOrigin ? null : url.origin;
  input.value = path;
  setFieldHint('#check-path-hint', origin
    ? `已识别授权来源 ${origin}，保存路径 ${path}`
    : `已识别当前系统地址，保存路径 ${path}`, 'good');
  return {path, origin};
}

function apiEditorSnapshot() {
  if (authFlowEditor) {
    try { return JSON.stringify(authFlowDraft(false)); }
    catch { return JSON.stringify({steps:authFlowEditor.steps, meta:[$('#auth-flow-id').value, $('#auth-flow-name').value, $('#auth-flow-outputs').value], fields:[...$('#check-form').querySelectorAll('input,select,textarea')].map(f => f.type === 'checkbox' ? f.checked : f.value)}); }
  }
  const fields = [...$('#check-form').querySelectorAll('input[id], select[id], textarea[id]')]
    .filter(field => field.id !== 'check-index')
    .map(field => [field.id, field.type === 'checkbox' ? field.checked : field.value]);
  return JSON.stringify(fields);
}

function setApiEditorTestState(state='idle') {
  const states = {
    idle: ['尚未测试', 'neutral'], running: ['测试中', 'accent'],
    passed: ['测试通过', 'good'], failed: ['测试失败', 'bad'],
    changed: ['测试后已修改', 'neutral'],
  };
  const [label, tone] = states[state] || states.idle;
  $('#api-editor-test-state').textContent = label;
  $('#api-editor-test-state').className = `badge ${tone}`;
}

function jsonFieldStatus(selector, allowEmpty=false, expectedType='any') {
  const raw = $(selector).value.trim();
  if (!raw && allowEmpty) return true;
  try {
    const value = JSON.parse(raw);
    if (expectedType === 'object') return !!value && !Array.isArray(value) && typeof value === 'object';
    if (expectedType === 'array') return Array.isArray(value);
    return true;
  }
  catch { return false; }
}

function updateApiEditorCompletion() {
  const status = {
    'api-section-basic': !!$('#check-path').value.trim() && !!$('#check-expected-status').value,
    'api-section-request': jsonFieldStatus('#check-headers', true, 'object') && jsonFieldStatus('#check-body', true),
    'api-section-validation': jsonFieldStatus('#check-assertions', true, 'array') && jsonFieldStatus('#check-extract', true, 'array'),
    'api-section-alerts': true,
  };
  let completed = 0;
  document.querySelectorAll('.api-section-link').forEach(button => {
    const done = !!status[button.dataset.apiSection];
    button.classList.toggle('is-complete', done);
    if (done) completed += 1;
  });
  $('#api-editor-completion').textContent = `${completed} / 4 已完成`;
}

function syncApiEditorDirtyState() {
  if ($('#api-editor-layer').classList.contains('hidden')) return;
  const snapshot = apiEditorSnapshot();
  apiEditorDirty = snapshot !== apiEditorInitialSnapshot;
  const hint = $('#api-editor-save-hint');
  hint.textContent = authFlowEditor?.flow.enabled ? `${apiEditorDirty ? '有未保存的修改 · ' : ''}保存草稿将停用流程及引用它的接口` : apiEditorDirty ? '有未保存的修改' : '草稿不会参与自动巡检';
  hint.classList.toggle('is-dirty', apiEditorDirty);
  if (apiEditorTestedSnapshot && snapshot !== apiEditorTestedSnapshot) setApiEditorTestState('changed');
  updateApiEditorCompletion();
}

function resetApiTestResult() {
  $('#check-test-result').className = 'api-test-empty';
  $('#check-test-result').innerHTML = '<span>◎</span><b>等待测试</b><p>完成必要配置后点击“测试接口”，结果将在这里展示。</p>';
  setApiEditorTestState('idle');
  apiEditorTestedSnapshot = '';
}

function renderApiTestResult(result) {
  const target = $('#check-test-result');
  const check = result.check;
  const passed = result.status === 'passed' && check?.status === 'passed';
  const sessionChecks = result.session_checks || [];
  const failure = check?.reason || sessionChecks.find(item => item.status !== 'passed')?.reason || '接口测试未通过';
  const evidence = check?.evidence || {};
  const sessionHtml = sessionChecks.length ? `<section class="api-test-group"><h4>会话准备</h4>${sessionChecks.map(item => `<div class="api-test-item ${item.status === 'passed' ? '' : 'failed'}"><span>${item.status === 'passed' ? '✓' : '×'}</span><i><b>${escapeHtml(item.name || item.id)}</b><small>${item.status === 'passed' ? `已完成 · ${formatDuration(item.duration_ms)}` : escapeHtml(item.reason || '执行失败')}</small></i></div>`).join('')}</section>` : '';
  const assertionHtml = check?.assertions?.length ? `<section class="api-test-group"><h4>业务断言</h4>${check.assertions.map(item => {
    const detail = `${item.op || 'assert'}${Object.prototype.hasOwnProperty.call(item, 'expected') ? ` · 预期 ${JSON.stringify(item.expected)}` : ''}${Object.prototype.hasOwnProperty.call(item, 'actual') ? ` · 实际 ${JSON.stringify(item.actual)}` : ''}`;
    return `<div class="api-test-item ${item.passed ? '' : 'failed'}"><span>${item.passed ? '✓' : '×'}</span><i><b>${escapeHtml(item.path || '业务断言')}</b><small>${escapeHtml(detail)}</small></i></div>`;
  }).join('')}</section>` : '<section class="api-test-group"><h4>业务断言</h4><div class="api-test-item"><span>–</span><i><b>未配置业务断言</b><small>本次测试仅验证 HTTP 状态和响应格式。</small></i></div></section>';
  const evidenceText = Object.keys(evidence).length ? JSON.stringify(evidence, null, 2) : '未生成响应证据';
  target.className = '';
  target.innerHTML = `<div class="api-test-summary"><div class="api-test-summary-row"><div><b>${passed ? '接口测试通过' : '接口测试失败'}</b><small>${escapeHtml(check?.name || '会话准备')} · 本次结果未写入报告或告警</small></div><span class="badge ${passed ? 'good' : 'bad'}">${passed ? '通过' : '失败'}</span></div>${passed ? '' : `<p class="api-test-reason">${escapeHtml(failure)}</p>`}</div>${check ? `<div class="api-test-metrics"><div class="api-test-metric"><span>HTTP 状态</span><b>${escapeHtml(evidence.http_status ?? '—')}</b></div><div class="api-test-metric"><span>执行耗时</span><b>${escapeHtml(formatDuration(check.duration_ms))}</b></div><div class="api-test-metric"><span>响应大小</span><b>${escapeHtml(evidence.response_bytes != null ? `${evidence.response_bytes} B` : '—')}</b></div><div class="api-test-metric"><span>Content-Type</span><b title="${escapeHtml(evidence.content_type || '—')}">${escapeHtml(evidence.content_type || '—')}</b></div></div>` : ''}${sessionHtml}${check ? assertionHtml : ''}<section class="api-test-group"><h4>响应证据</h4><pre class="api-test-evidence">${escapeHtml(evidenceText)}</pre></section>`;
  setApiEditorTestState(passed ? 'passed' : 'failed');
  apiEditorTestedSnapshot = apiEditorSnapshot();
}

function populateCheckEditor(check, index, isNew=false) {
  drawerReturnFocus = document.activeElement;
  $('#check-index').value = String(index);
  $('#api-editor-title').textContent = isNew ? '新增 API 巡检' : `编辑 API 巡检 · ${check.name}`;
  $('#api-editor-description').textContent = isNew
    ? '先保存为停用草稿，测试通过后再启用。'
    : `当前状态：${check.enabled ? '已启用' : '已停用'}。保存草稿会将其停用。`;
  const reasons = isNew ? [] : apiCheckEnablementReasons(check);
  $('#api-editor-blockers').classList.toggle('hidden', !reasons.length);
  $('#api-editor-blockers').textContent = reasons.length
    ? `启用前需处理：${reasons.join('；')}。修正后保存草稿，系统会重新校验，再测试并启用。` : '';
  $('#check-id').value = check.id;
  $('#check-id').readOnly = !isNew;
  $('#check-name').value = check.name || '';
  $('#check-category').value = check.category || '';
  $('#check-method').value = check.method || 'POST';
  $('#check-path').value = check.origin ? `${check.origin}${check.path || ''}` : check.path || '';
  $('#check-encoding').value = check.body_encoding || 'json';
  $('#check-response-type').value = check.response_type || 'json';
  $('#check-follow-redirects').checked = check.follow_redirects !== false;
  $('#check-auth-flow').innerHTML = '<option value="">不引用登录流程</option>' + (configDocument.config.api_auth_flows || []).map(flow => `<option value="${escapeHtml(flow.id)}">${escapeHtml(flow.name)}${flow.enabled ? '' : '（未启用）'}</option>`).join('');
  $('#check-auth-flow').value = check.auth_flow_id || '';
  renderAuthEditorControls();
  $('#check-timeout').value = check.timeout_seconds ?? '';
  $('#check-expected-status').value = check.expected_status ?? 200;
  $('#check-severity').value = check.severity || 'P2';
  $('#check-alert-enabled').checked = !!check.alert_enabled;
  $('#check-headers').value = isNew ? '' : pretty(check.headers || {});
  $('#check-body').value = isNew ? '' : pretty(check.body ?? null);
  $('#check-assertions').value = isNew ? '' : pretty(check.assertions || []);
  $('#check-extract').value = isNew ? '' : pretty(check.extract || []);
  setFieldHint('#check-id-hint', isNew
    ? '支持输入 camelCase，保存时自动转换为小写短横线格式。'
    : '检查项 ID 创建后不可修改。');
  setFieldHint('#check-path-hint', check.origin
    ? `请求来源：${check.origin}`
    : '当前系统同源 URL 会自动转换为站内路径。');
  resetApiTestResult();
  $('#api-editor-layer').classList.remove('hidden');
  $('#api-editor-layer').setAttribute('aria-hidden', 'false');
  document.body.classList.add('api-editor-open');
  $('#api-editor-form-scroll').scrollTop = 0;
  document.querySelectorAll('.api-section-link').forEach((button, buttonIndex) => button.classList.toggle('active', buttonIndex === 0));
  apiEditorInitialSnapshot = apiEditorSnapshot();
  apiEditorDirty = false;
  $('#api-editor-save-hint').textContent = authFlowEditor?.flow.enabled ? '保存草稿将停用流程及引用它的接口' : '草稿不会参与自动巡检';
  $('#api-editor-save-hint').classList.remove('is-dirty');
  updateApiEditorCompletion();
  (isNew ? $('#check-id') : $('#check-name')).focus();
}

function openCheckEditor(index) {
  authFlowEditor = null;
  const check = configDocument?.config?.checks?.[index];
  if (!check) return;
  populateCheckEditor(check, index);
}

function openNewCheckEditor() {
  authFlowEditor = null;
  if (!configDocument) {
    notice('配置尚未载入，请稍后重试', 'error');
    return;
  }
  populateCheckEditor(blankCheck(), -1, true);
}

function closeCheckEditor(force=false) {
  if ($('#api-editor-layer').classList.contains('hidden')) return;
  if (apiEditorDirty && !force) {
    showConfirm({
      type:'warning', title:'放弃未保存的修改？',
      message:'关闭编辑器后，本次修改和测试结果将不会保留。',
      confirmText:'放弃修改', cancelText:'继续编辑',
    }).then(confirmed => { if (confirmed) closeCheckEditor(true); });
    return;
  }
  $('#api-editor-layer').classList.add('hidden');
  $('#api-editor-layer').setAttribute('aria-hidden', 'true');
  document.body.classList.remove('api-editor-open');
  authFlowEditor = null;
  apiEditorInitialSnapshot = '';
  apiEditorTestedSnapshot = '';
  apiEditorDirty = false;
  drawerReturnFocus?.focus?.();
  drawerReturnFocus = null;
}

function parseEditor(selector, label, emptyValue) {
  const raw = $(selector).value.trim();
  if (!raw && emptyValue !== undefined) return cloneJson(emptyValue);
  try { return JSON.parse(raw); }
  catch { throw new Error(`${label}不是有效 JSON`); }
}

function checkDraft(enabled, validate=true) {
  const index = Number($('#check-index').value);
  const existing = authFlowEditor ? authFlowEditor.steps[authFlowEditor.current] : index >= 0 ? configDocument?.config?.checks?.[index] : null;
  normalizeCheckIdInput();
  const normalizedRequest = normalizeCheckPathInput(existing?.origin || null);
  if (validate) validateForm($('#check-form'));
  const check = cloneJson(existing || blankCheck());
  check.id = $('#check-id').value.trim();
  const duplicate = authFlowEditor ? authFlowEditor.steps.some((item, itemIndex) => itemIndex !== authFlowEditor.current && item.id === check.id) || configDocument.config.checks.some(item => !authFlowEditor.originalIds.includes(item.id) && item.id === check.id) : configDocument.config.checks.some((item, itemIndex) => itemIndex !== index && item.id === check.id);
  if (duplicate) throw new Error(`检查项 ID 已存在：${check.id}`);
  check.name = $('#check-name').value.trim();
  check.category = $('#check-category').value.trim();
  check.method = $('#check-method').value;
  check.path = normalizedRequest.path;
  if (normalizedRequest.origin) check.origin = normalizedRequest.origin;
  else delete check.origin;
  check.expected_status = Number($('#check-expected-status').value);
  check.response_type = $('#check-response-type').value;
  check.follow_redirects = $('#check-follow-redirects').checked;
  if (!authFlowEditor && $('#check-auth-flow').value) check.auth_flow_id = $('#check-auth-flow').value;
  else delete check.auth_flow_id;
  check.enabled = enabled;
  check.severity = $('#check-severity').value;
  check.alert_enabled = $('#check-alert-enabled').checked;
  check.headers = parseEditor('#check-headers', '请求头', {});
  if (!check.headers || Array.isArray(check.headers) || typeof check.headers !== 'object') {
    throw new Error('请求头必须是 JSON 对象，例如 {"Authorization":"Bearer ${ticket}"}');
  }
  check.body = ['GET','HEAD'].includes(check.method) ? parseEditor('#check-body', '请求体', null) : parseEditor('#check-body', '请求体', {});
  check.assertions = parseEditor('#check-assertions', '业务断言', []);
  check.extract = parseEditor('#check-extract', '响应变量提取', []);
  if (!Array.isArray(check.assertions)) throw new Error('业务断言必须是 JSON 数组');
  if (!Array.isArray(check.extract)) throw new Error('响应变量提取必须是 JSON 数组');
  if ($('#check-encoding').value === 'form') check.body_encoding = 'form';
  else delete check.body_encoding;
  const timeout = $('#check-timeout').value;
  if (timeout) check.timeout_seconds = Number(timeout);
  else delete check.timeout_seconds;
  return check;
}

function setCheckEditorBusy(busy) {
  authFlowBusy = busy;
  document.querySelectorAll('#check-form input, #check-form select, #check-form textarea').forEach(field => { field.disabled = busy; });
  document.querySelectorAll('#auth-flow-steps button').forEach(button => { button.disabled = busy; });
  ['#check-save-draft', '#check-test', '#check-save-enable', '#check-cancel', '#api-editor-close', '#auth-step-add', '#auth-step-up', '#auth-step-down', '#auth-step-remove'].forEach(selector => {
    $(selector).disabled = busy;
  });
}

async function persistCheck(enabled) {
  if (authFlowEditor) return persistAuthFlow(enabled);
  try {
    setCheckEditorBusy(true);
    const index = Number($('#check-index').value);
    const config = cloneJson(configDocument.config);
    const check = checkDraft(enabled);
    if (index >= 0) config.checks[index] = check;
    else {
      config.checks.push(check);
      lastCreatedCheckId = check.id;
    }
    await persistApiChecks(config.checks);
    if (index < 0) setTimeout(() => { lastCreatedCheckId = null; }, 1800);
    apiEditorInitialSnapshot = apiEditorSnapshot();
    apiEditorDirty = false;
    closeCheckEditor(true);
    notice(`${enabled ? '已保存并启用' : '已保存草稿'}：${check.name}`);
  } catch (error) {
    lastCreatedCheckId = null;
    notice(error.message, 'error');
  } finally {
    setCheckEditorBusy(false);
  }
}

async function saveCheck(event) {
  event.preventDefault();
  await persistCheck(true);
}

async function testCheck() {
  if (authFlowEditor) return testAuthFlow();
  let draft;
  try { draft = checkDraft(true); }
  catch (error) { notice(error.message, 'error'); return; }
  const target = $('#check-test-result');
  target.className = 'api-test-empty';
  target.innerHTML = '<span>◌</span><b>正在测试接口</b><p>正在建立会话、执行请求并验证业务断言…</p>';
  setApiEditorTestState('running');
  try {
    setCheckEditorBusy(true);
    const result = await api('/api/api-checks/test', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({check: draft}),
    });
    renderApiTestResult(result);
    notice(result.status === 'passed' ? '接口测试通过，结果已显示在右侧' : '接口测试未通过，请查看右侧详情', result.status === 'passed' ? 'success' : 'error');
  } catch (error) {
    setApiEditorTestState('failed');
    target.className = 'api-test-empty';
    target.innerHTML = `<span>!</span><b>无法执行测试</b><p>${escapeHtml(error.message)}</p>`;
    notice(error.message, 'error');
  } finally {
    setCheckEditorBusy(false);
  }
}

function persistReportViewState() {
  Object.assign(reportViewStates[currentReportKind], {
    reports: cachedReports,
    selectedReport,
    selectedReportData,
    checkFilter: reportCheckFilter,
    search: $('#report-search').value,
    status: $('#report-status-filter').value,
    trigger: $('#report-trigger-filter').value,
  });
}

function restoreReportViewState() {
  const state = reportViewStates[currentReportKind];
  cachedReports = state.reports;
  selectedReport = state.selectedReport;
  selectedReportData = state.selectedReportData;
  reportCheckFilter = state.checkFilter;
  $('#report-search').value = state.search;
  $('#report-status-filter').value = state.status;
  $('#report-trigger-filter').value = state.trigger;
  document.querySelectorAll('[data-report-check-filter]').forEach(button => button.classList.toggle('active', button.dataset.reportCheckFilter === reportCheckFilter));
}

function syncReportKindChrome() {
  const apiReport = currentReportKind === 'api';
  const labels = apiReport ? {
    eyebrow:'接口维度 · 独立数据口径', title:'API 巡检历史报告',
    description:'聚焦接口可用性、响应性能与断言失败，快速定位后端异常。',
    total:'接口通过率', totalHint:'当前留存报告内的接口结果',
    rate:'平均响应', rateHint:'按 API 检查项加权统计',
    failed:'失败接口', failedHint:'当前留存范围累计',
    performance:'P95 响应', performanceHint:'最近一轮 API 性能',
    detailKind:'API REPORT', detailHeading:'接口健康度与诊断证据', caption:'选择一轮 API 巡检查看接口证据',
  } : {
    eyebrow:'用户旅程维度 · 独立数据口径', title:'UI 场景历史报告',
    description:'按业务场景复盘页面步骤、截图与失败现场，快速还原用户路径。',
    total:'场景通过率', totalHint:'当前留存报告内的场景结果',
    rate:'平均场景耗时', rateHint:'按 UI 场景加权统计',
    failed:'失败步骤', failedHint:'当前留存范围累计',
    performance:'截图证据', performanceHint:'当前留存范围累计',
    detailKind:'UI REPORT', detailHeading:'场景步骤与关键截图', caption:'选择一轮 UI 巡检查看场景证据',
  };
  $('#reports').dataset.reportKind = currentReportKind;
  $('#report-eyebrow').textContent = labels.eyebrow;
  $('#report-page-title').textContent = labels.title;
  $('#report-page-description').textContent = labels.description;
  $('#report-total-label').textContent = labels.total;
  $('#report-total-hint').textContent = labels.totalHint;
  $('#report-rate-label').textContent = labels.rate;
  $('#report-rate-hint').textContent = labels.rateHint;
  $('#report-failed-label').textContent = labels.failed;
  $('#report-failed-hint').textContent = labels.failedHint;
  $('#report-performance-label').textContent = labels.performance;
  $('#report-performance-hint').textContent = labels.performanceHint;
  $('#report-range').textContent = `${apiReport ? 'API' : 'UI'} 最近 30 轮`;
  $('#report-detail-kind').textContent = labels.detailKind;
  $('#report-detail-kind').className = `report-detail-kind ${currentReportKind}`;
  $('#report-detail-heading').textContent = labels.detailHeading;
  if (!selectedReportData) $('#report-caption').textContent = labels.caption;
  document.querySelectorAll('[data-report-kind]').forEach(button => {
    const active = button.dataset.reportKind === currentReportKind;
    button.classList.toggle('active', active);
    if (button.getAttribute('role') === 'tab') button.setAttribute('aria-selected', String(active));
  });
  if (!$('#reports').classList.contains('hidden')) $('#page-name').textContent = apiReport ? 'API 巡检报告' : 'UI 场景报告';
}

function clearReportDetail() {
  selectedReport = null;
  selectedReportData = null;
  reportCheckFilter = 'all';
  $('#download-report').classList.add('hidden');
  $('#report-detail-actions').classList.add('hidden');
  $('#report-detail').className = 'empty';
  $('#report-detail').textContent = `尚未选择 ${currentReportKind === 'api' ? 'API' : 'UI'} 报告`;
  syncReportKindChrome();
}

function setReportKind(kind) {
  if (!['api', 'ui'].includes(kind)) return;
  if (kind !== currentReportKind) {
    persistReportViewState();
    currentReportKind = kind;
    restoreReportViewState();
  }
  syncReportKindChrome();
  renderReports();
  if (selectedReportData) renderReportDetail();
  else clearReportDetail();
  if ($('#reports').classList.contains('hidden')) showView('reports');
  else if (location.protocol !== 'file:') loadReports();
}

async function loadReports() {
  const kind = currentReportKind;
  try {
    const reports = await api(`/api/reports/${kind}`);
    reportViewStates[kind].reports = reports;
    if (kind !== currentReportKind) return;
    cachedReports = reports;
    if (selectedReport && !cachedReports.some(item => item.run_id === selectedReport)) clearReportDetail();
    renderReports();
    if (selectedReportData) renderReportDetail();
    else if (selectedReport && cachedReports.some(item => item.run_id === selectedReport)) selectReport(selectedReport);
    else if (cachedReports.length) selectReport(cachedReports[0].run_id);
    else clearReportDetail();
  } catch(error) { notice(error.message, 'error'); }
}

function renderReportMetrics() {
  const passedItems = cachedReports.reduce((sum, item) => sum + count(item.counts?.passed), 0);
  const failedItems = cachedReports.reduce((sum, item) => sum + count(item.counts?.failed), 0);
  const skippedItems = cachedReports.reduce((sum, item) => sum + count(item.counts?.skipped), 0);
  const totalItems = passedItems + failedItems + skippedItems;
  const passRate = totalItems ? `${(passedItems / totalItems * 100).toFixed(1)}%` : '—';
  const totalDuration = cachedReports.reduce((sum, item) => sum + count(item.duration_ms), 0);
  const averageDuration = totalItems ? formatDuration(totalDuration / totalItems) : '—';
  const latest = cachedReports[0] || {};
  if (currentReportKind === 'api') {
    $('#report-total-count').textContent = passRate;
    $('#report-success-rate').textContent = averageDuration;
    $('#report-failed-count').textContent = String(failedItems);
    $('#report-scheduled-count').textContent = cachedReports.length ? formatDuration(latest.p95_duration_ms) : '—';
  } else {
    const failedSteps = cachedReports.reduce((sum, item) => sum + count(item.failed_step_count), 0);
    const screenshots = cachedReports.reduce((sum, item) => sum + count(item.screenshot_count), 0);
    $('#report-total-count').textContent = passRate;
    $('#report-success-rate').textContent = averageDuration;
    $('#report-failed-count').textContent = String(failedSteps);
    $('#report-scheduled-count').textContent = String(screenshots);
  }
  const failedRuns = cachedReports.filter(item => item.status === 'failed').length;
  $('#reports-summary').textContent = `${cachedReports.length} 份独立报告 · ${failedRuns ? `${failedRuns} 份异常` : '运行稳定'}`;
}

function renderReports() {
  const query = $('#report-search').value.trim().toLocaleLowerCase('zh-CN');
  const status = $('#report-status-filter').value;
  const trigger = $('#report-trigger-filter').value;
  const reports = cachedReports.filter(item => (!query || String(item.run_id || '').toLocaleLowerCase('zh-CN').includes(query)) && (!status || item.status === status) && (!trigger || item.trigger === trigger));
  renderReportMetrics();
  $('#report-list-summary').textContent = `显示 ${reports.length} / ${cachedReports.length} 轮 · ${currentReportKind === 'api' ? '仅 API' : '仅 UI'} · 按时间倒序`;
  $('#report-filter-reset').classList.toggle('hidden', !(query || status || trigger));
  const list = $('#report-list');
  list.className = reports.length ? 'report-list' : 'report-list empty';
  list.innerHTML = reports.length ? reports.map(item => {
    const passedCount = count(item.counts?.passed);
    const failedCount = count(item.counts?.failed);
    const skippedCount = count(item.counts?.skipped);
    const badgeClass = item.status === 'passed' ? 'good' : item.status === 'failed' ? 'bad' : 'neutral';
    return `<button class="report-item ${selectedReport === item.run_id ? 'selected' : ''}" data-status="${escapeHtml(item.status || '')}" data-id="${escapeHtml(item.run_id)}"><span class="report-item-top"><b>${escapeHtml(item.run_id)}</b><span class="badge ${badgeClass}">${statusText(item.status)}</span></span><span class="report-item-kind ${currentReportKind}">${currentReportKind === 'api' ? 'API RUN' : 'UI JOURNEY'}</span><span class="report-item-meta">${item.trigger === 'scheduled' ? '定时执行' : '手动执行'} · ${escapeHtml(timeText(item.started_at))}</span><span class="report-item-counts"><em class="ok">${passedCount} 通过</em><em class="${failedCount ? 'fail' : ''}">${failedCount} 失败</em>${skippedCount ? `<em>${skippedCount} 跳过</em>` : ''}</span></button>`;
  }).join('') : `没有符合筛选条件的${currentReportKind === 'api' ? ' API 巡检' : ' UI 场景'}报告`;
  list.querySelectorAll('[data-id]').forEach(button => button.addEventListener('click', () => selectReport(button.dataset.id)));
  persistReportViewState();
}

async function selectReport(id) {
  const kind = currentReportKind;
  try {
    const report = await api(`/api/reports/${kind}/${encodeURIComponent(id)}`);
    if (kind !== currentReportKind) return;
    selectedReport = id;
    selectedReportData = report;
    reportCheckFilter = 'all';
    document.querySelectorAll('[data-report-check-filter]').forEach(button => button.classList.toggle('active', button.dataset.reportCheckFilter === 'all'));
    $('#report-caption').textContent = `${environmentText(report.environment)} · ${timeText(report.started_at)}`;
    $('#download-report').classList.remove('hidden');
    $('#report-detail-actions').classList.remove('hidden');
    renderReportDetail();
    persistReportViewState();
    syncReportDeepLink(id);
    document.querySelectorAll('.report-item').forEach(button => button.classList.toggle('selected', button.dataset.id === id));
  } catch(error) { notice(error.message, 'error'); }
}

function openRequestedReport() {
  const linked = requestedReportDeepLink();
  if (!linked || !systems.some(item => item.system_id === linked.system)) return;
  currentReportKind = linked.kind;
  restoreReportViewState();
  selectedReport = linked.run;
  selectedReportData = null;
  syncReportKindChrome();
  showView('reports');
}

function renderScreenshotButton(url, label, step=null, evidenceLabel='步骤截图') {
  const title = step ? `步骤 ${String(step.sequence ?? '—').padStart(2, '0')} · ${step.description || step.id || '未命名步骤'}` : label;
  const action = step ? [...$('#ui-step-action').options].find(option => option.value === step.action)?.textContent || step.action || '待配置' : '';
  const details = step ? `${action} · ${statusText(step.status)} · ${formatDuration(step.duration_ms)} · ${evidenceLabel}` : evidenceLabel;
  return `<button class="screenshot-preview-trigger" type="button" data-image-preview="${escapeHtml(url)}" data-preview-title="${escapeHtml(title)}" data-preview-details="${escapeHtml(details)}" aria-label="${escapeHtml(`预览截图：${label}`)}" aria-haspopup="dialog" title="点击放大截图"><img src="${escapeHtml(url)}" loading="lazy" alt="${escapeHtml(label)}"></button>`;
}

let imagePreviewReturnFocus = null;
let imagePreviewItems = [];
let imagePreviewIndex = 0;
function openImagePreview(trigger) {
  const dialog = $('#image-preview-dialog');
  imagePreviewReturnFocus = trigger;
  const group = trigger.closest('.ui-test-steps, .ui-step-list');
  const triggers = group ? [...group.querySelectorAll('[data-image-preview]')] : [trigger];
  imagePreviewItems = triggers.map(item => ({
    url:item.dataset.imagePreview,
    label:item.querySelector('img').alt,
    title:item.dataset.previewTitle,
    details:item.dataset.previewDetails,
  }));
  imagePreviewIndex = triggers.indexOf(trigger);
  renderImagePreview();
  document.body.classList.add('image-preview-open');
  if (!dialog.open) dialog.showModal();
}

function renderImagePreview() {
  const item = imagePreviewItems[imagePreviewIndex];
  if (!item) return;
  const image = $('#image-preview-image');
  $('#image-preview-title').textContent = item.title || item.label || '截图预览';
  $('#image-preview-details').textContent = item.details || '步骤截图';
  $('#image-preview-position').textContent = `${imagePreviewIndex + 1} / ${imagePreviewItems.length}`;
  $('#image-preview-prev').disabled = imagePreviewIndex === 0;
  $('#image-preview-next').disabled = imagePreviewIndex === imagePreviewItems.length - 1;
  $('#image-preview-error').classList.add('hidden');
  image.classList.remove('hidden');
  image.alt = item.label;
  image.src = item.url;
}

function moveImagePreview(offset) {
  const next = imagePreviewIndex + offset;
  if (next < 0 || next >= imagePreviewItems.length) return;
  imagePreviewIndex = next;
  renderImagePreview();
  const focused = document.activeElement;
  if (focused === $('#image-preview-prev') && focused.disabled) $('#image-preview-next').focus();
  if (focused === $('#image-preview-next') && focused.disabled) $('#image-preview-prev').focus();
}

function renderArtifactPreview(runId, artifact, label, className='', step=null) {
  if (!artifact?.artifact_id) return '';
  const url = artifactUrl(runId, artifact.artifact_id);
  return `<figure class="step-screenshot ${escapeHtml(className)}">${renderScreenshotButton(url, label, step, className === 'is-failure' ? '失败整页证据' : '步骤截图')}<figcaption>${escapeHtml(label)} · ${escapeHtml(Math.ceil(count(artifact.bytes) / 1024))} KB</figcaption></figure>`;
}

function renderUiSteps(report, item) {
  const steps = (item.steps || []).map(step => {
    const assertion = step.assertion
      ? `<div class="step-assertion ${step.assertion.passed ? 'ok' : 'fail'}">${step.assertion.passed ? '✓' : '✕'} ${escapeHtml(step.assertion.type || '断言')}${step.assertion.expected === undefined ? '' : ` · 预期 ${escapeHtml(JSON.stringify(step.assertion.expected))}`}${step.assertion.actual === undefined ? '' : ` · 实际 ${escapeHtml(JSON.stringify(step.assertion.actual))}`}</div>`
      : '';
    const screenshots = renderArtifactPreview(report.run_id, step.screenshot, `${step.sequence}. ${step.description}`, '', step)
      + renderArtifactPreview(report.run_id, step.failure_screenshot, `${step.sequence}. 失败整页证据`, 'is-failure', step);
    return `<article class="ui-step is-${escapeHtml(step.status || 'failed')}"><div class="ui-step-head"><span class="ui-step-index">${escapeHtml(step.sequence || '—')}</span><span><b>${escapeHtml(step.description || step.id)}</b><small>${escapeHtml(step.action || '')} · ${formatDuration(step.duration_ms)}</small></span><span class="badge ${step.status === 'passed' ? 'good' : 'bad'}">${statusText(step.status)}</span></div>${step.reason ? `<p class="step-reason">${escapeHtml(classificationText(step.classification))} · ${escapeHtml(step.reason)}</p>` : ''}${assertion}${screenshots || '<div class="step-missing-evidence">未生成截图证据</div>'}</article>`;
  }).join('');
  const evidence = item.evidence || {};
  const diagnostics = [
    ...(evidence.console_errors || []).map(value => `控制台：${value}`),
    ...(evidence.failed_requests || []).map(value => `请求失败：${value}`),
  ];
  const trace = evidence.trace?.artifact_id
    ? `<a class="trace-link" href="${escapeHtml(artifactUrl(report.run_id, evidence.trace.artifact_id))}" download>下载失败 Trace</a>`
    : '';
  const page = `<div class="ui-evidence-meta">页面：${escapeHtml(evidence.page_title || '—')} · ${escapeHtml(evidence.page_url || '—')} · ${count(evidence.screenshot_count)} 张步骤截图 ${trace}</div>`;
  const diagnosticHtml = diagnostics.length
    ? `<details class="ui-diagnostics"><summary>浏览器诊断 ${diagnostics.length} 条</summary>${diagnostics.map(value => `<div>${escapeHtml(value)}</div>`).join('')}</details>`
    : '';
  return page + `<div class="ui-step-list">${steps || '<div class="empty">没有 UI 步骤结果</div>'}</div>` + diagnosticHtml;
}

function renderReportDetail() {
  const report = selectedReportData;
  if (!report) return;
  const detail = $('#report-detail');
  detail.className = '';
  const kind = report.report_kind || currentReportKind;
  const retry = report.retry || {};
  const retryText = retry.attempt_count > 1
    ? `${retry.attempt_count} 次${retry.recovered ? ' · 重跑恢复' : retry.exhausted ? ' · 已耗尽' : ''}`
    : '1 次';
  const typeSummary = kind === 'api'
    ? `<span><small>接口通过</small><b class="ok">${report.counts?.passed ?? 0} / ${(report.checks || []).length}</b></span><span><small>平均 / P95</small><b>${formatDuration(report.average_duration_ms)} / ${formatDuration(report.p95_duration_ms)}</b></span>`
    : `<span><small>场景 / 步骤</small><b>${(report.checks || []).length} / ${count(report.step_count)}</b></span><span><small>截图 / 失败步骤</small><b class="${count(report.failed_step_count) ? 'fail' : ''}">${count(report.screenshot_count)} / ${count(report.failed_step_count)}</b></span>`;
  const summary = `<div class="report-summary"><span><small>运行状态</small><b class="${report.status === 'passed' ? 'ok' : 'fail'}">${statusText(report.status)}</b></span><span><small>触发方式</small><b>${report.trigger === 'scheduled' ? '定时执行' : '手动执行'}</b></span><span><small>尝试次数</small><b>${escapeHtml(retryText)}</b></span><span><small>配置版本</small><b>${escapeHtml(report.config_version || '—')}</b></span>${typeSummary}</div>`;
  const availableChecks = report.checks || [];
  const filteredChecks = availableChecks.filter(item => reportCheckFilter === 'all' || item.status === reportCheckFilter);
  const checks = filteredChecks.map(item => {
    const evidence = item.evidence || {};
    const assertions = (item.assertions || []).map(rule => `<div class="${rule.passed ? 'ok' : 'fail'}">${rule.passed ? '✓' : '✕'} ${escapeHtml(rule.path)} · ${escapeHtml(rule.op)}${rule.expected === undefined ? '' : ` · 预期 ${escapeHtml(JSON.stringify(rule.expected))}`}${rule.actual === undefined ? '' : ` · 实际 ${escapeHtml(JSON.stringify(rule.actual))}`}</div>`).join('');
    const serverDetail = evidence.server_code === undefined && !evidence.server_message ? '' : ` · 服务端 ${evidence.server_code === undefined ? '' : escapeHtml(evidence.server_code)}${evidence.server_message ? ` ${escapeHtml(evidence.server_message)}` : ''}`;
    const expanded = item.status === 'failed' ? ' open' : '';
    const body = kind === 'ui'
      ? renderUiSteps(report, item)
      : `<div class="evidence">HTTP ${evidence.http_status ?? '—'}${serverDetail} · 请求 ID ${escapeHtml(evidence.request_id || '—')} · 响应 SHA-256 ${escapeHtml(evidence.response_sha256 || '—')}</div>${assertions ? `<div class="assertions">${assertions}</div>` : '<div class="assertions">暂无结构化断言</div>'}`;
    return `<details class="check-result is-${escapeHtml(item.status || 'skipped')}"${expanded}><summary><span class="check-result-heading"><i aria-hidden="true"></i><span><b>${escapeHtml(item.name)}</b><small>${escapeHtml(item.method || (kind === 'ui' ? 'UI' : ''))} ${escapeHtml(item.path || '')}</small></span></span><span class="check-result-summary"><em>${formatDuration(item.duration_ms)}</em><span class="badge ${item.status === 'passed' ? 'good' : item.status === 'failed' ? 'bad' : 'neutral'}">${statusText(item.status)}</span></span></summary><div class="check-result-body"><p>${item.classification ? `分类：${escapeHtml(classificationText(item.classification))}` : kind === 'ui' ? 'UI 用户视角证据' : 'API 业务断言证据'}${item.reason ? ` · ${escapeHtml(item.reason)}` : ''}</p>${body}</div></details>`;
  }).join('');
  const filterLabel = ({failed:'失败', skipped:'跳过'})[reportCheckFilter] || '全部';
  const empty = availableChecks.length
    ? `<div class="empty report-filter-empty">本轮没有${filterLabel === '全部' ? '' : filterLabel}检查项</div>`
    : `<div class="empty report-filter-empty">${escapeHtml(report.error || '本轮没有检查明细')}</div>`;
  detail.innerHTML = summary + `<div class="report-check-caption"><span>${filterLabel}${kind === 'ui' ? '场景' : '接口'}</span><small>${filteredChecks.length} / ${availableChecks.length} 项</small></div>` + (checks || empty);
}

function classificationText(value) {
  return ({
    network_unreachable:'网络不可达',
    authentication_failed:'登录认证失败',
    authorization_denied:'权限不足',
    module_unavailable:'业务模块不可用',
    dependency_unhealthy:'下游依赖异常',
    data_precondition_missing:'前置数据不满足',
    assertion_failed:'业务断言失败',
    automation_contract_changed:'自动化契约已变化',
    timeout:'请求超时',
  })[value] || value || '未分类';
}

function renderIncidents() {
  const query = $('#incident-search').value.trim().toLocaleLowerCase('zh-CN');
  const status = $('#incident-status-filter').value;
  const severity = $('#incident-severity-filter').value;
  const incidents = cachedIncidents.filter(item => {
    const haystack = `${item.check_name || ''} ${item.check_id || ''} ${item.classification || ''} ${classificationText(item.classification)} ${item.reason || ''}`.toLocaleLowerCase('zh-CN');
    return (!query || haystack.includes(query)) && (!status || item.status === status) && (!severity || item.severity === severity);
  });
  $('#incident-filter-result').textContent = `显示 ${incidents.length} / ${cachedIncidents.length} 项`;
  $('#incident-filter-reset').classList.toggle('hidden', !(query || status || severity));
  $('#incidents-body').innerHTML = incidents.length ? incidents.map(item => `<tr class="incident-row ${item.status === 'open' ? 'is-open' : 'is-resolved'}"><td><span class="badge ${item.status === 'open' ? 'bad' : 'good'}">${item.status === 'open' ? '告警中' : '已恢复'}</span></td><td><b>${escapeHtml(item.check_name)}</b><br><small>${escapeHtml(item.check_id)}</small></td><td><span class="severity severity-${escapeHtml(String(item.severity || '').toLocaleLowerCase())}">${escapeHtml(item.severity || '—')}</span></td><td><b class="classification-label">${escapeHtml(classificationText(item.classification))}</b><br><small title="${escapeHtml(item.reason || '')}">${escapeHtml(item.reason || '—')}</small></td><td>${escapeHtml(timeText(item.first_failed_at))}</td><td>${escapeHtml(timeText(item.resolved_at))}</td></tr>`).join('') : '<tr><td colspan="6">没有符合筛选条件的告警事件</td></tr>';
}

function renderNotifications() {
  const eventText = {alert:'告警', reminder:'持续提醒', recovery:'恢复', success:'巡检成功'};
  const statusLabel = {pending:'待发送', retry:'重试中', sent:'已发送', failed:'发送失败'};
  $('#notifications-body').innerHTML = cachedNotifications.length ? cachedNotifications.map(item => {
    const eventType = Object.hasOwn(eventText, item.event_type) ? item.event_type : 'unknown';
    const eventLabel = eventText[item.event_type] || item.event_type || '未知事件';
    return `<tr class="notification-row is-${escapeHtml(item.status || 'pending')}"><td><span class="notification-event event-${eventType}" title="${escapeHtml(eventLabel)}"><span>${escapeHtml(eventLabel)}</span></span></td><td><span class="badge ${item.status === 'sent' ? 'good' : item.status === 'failed' ? 'bad' : 'neutral'}">${escapeHtml(statusLabel[item.status] || item.status)}</span></td><td>${count(item.attempt_count)}</td><td>${escapeHtml(timeText(item.created_at))}</td><td>${item.sent_at ? escapeHtml(timeText(item.sent_at)) : escapeHtml(item.last_error || '—')}</td></tr>`;
  }).join('') : '<tr><td colspan="5">暂无通知记录</td></tr>';
}

async function loadIncidents() {
  try {
    [cachedIncidents, cachedNotifications] = await Promise.all([api('/api/incidents'), api('/api/notifications')]);
    const open = cachedIncidents.filter(item => item.status === 'open').length;
    const recovered = cachedIncidents.length - open;
    const pending = cachedNotifications.filter(item => item.status === 'pending' || item.status === 'retry').length;
    const failed = cachedNotifications.filter(item => item.status === 'failed').length;
    $('#incident-summary').textContent = `${open} 个未恢复 · ${cachedIncidents.length} 个事件`;
    $('#incident-summary').className = `badge ${open ? 'bad' : 'good'}`;
    $('#incident-open-count').textContent = String(open);
    $('#incident-recovered-count').textContent = String(recovered);
    $('#notification-pending-count').textContent = String(pending);
    $('#notification-failed-count').textContent = String(failed);
    $('#incident-event-tab-count').textContent = String(cachedIncidents.length);
    $('#incident-delivery-tab-count').textContent = String(cachedNotifications.length);
    $('#nav-alert-count').textContent = String(open);
    $('#nav-alert-count').classList.toggle('hidden', open === 0);
    renderIncidents();
    renderNotifications();
  } catch (error) { notice(error.message, 'error'); }
}

async function saveOperations() {
  try {
    await persistSettings(environmentDraft(), credentialDraft());
    notice('调度与告警配置已保存');
  } catch (error) { notice(error.message, 'error'); }
}

async function testNotification() {
  const button = $('#test-notification');
  button.disabled = true;
  try {
    await api('/api/notifications/test', {method:'POST'});
    notice('测试通知已发送');
    await loadIncidents();
  } catch (error) { notice(`测试通知失败：${error.message}`, 'error'); }
  finally { button.disabled = false; }
}

async function startRun(targets = selectedRunTargets) {
  const button = $('#run');
  button.disabled = true;
  button.classList.add('is-launching');
  button.querySelector('span').textContent = '正在启动…';
  button.setAttribute('aria-busy', 'true');
  try {
    const result = await api('/api/runs', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({targets}),
    });
    notice(`${runTargetsLabel(result.targets || targets)} 巡检已启动：${result.run_id}`);
    await loadSummary();
    showView('overview');
  } catch(error) { notice(error.message, 'error'); await loadSummary(); }
  finally {
    button.classList.remove('is-launching');
    if (!button.classList.contains('is-running')) {
      button.querySelector('span').textContent = `执行 ${runTargetsLabel(selectedRunTargets)}`;
      button.removeAttribute('aria-busy');
    }
  }
}

function requestRun(targets = selectedRunTargets) {
  if (currentSummary?.active_run_id || runTargetCount(currentSummary, targets) === 0) return;
  selectRunTargets(targets);
  const system = currentSystem();
  const targetLabel = runTargetsLabel(targets);
  const checkCount = runTargetCount(currentSummary, targets);
  showConfirm({
    type: currentSummary?.environment === 'production' ? 'warning' : 'info',
    title: `确认执行 ${targetLabel} 巡检？`,
    message: currentSummary?.environment === 'production'
      ? '当前为正式环境，将按已保存的配置执行巡检。'
      : `将对当前系统执行已启用的 ${targetLabel} 检查。`,
    meta: [
      {label:'当前系统', value:system?.display_name || selectedSystem || '—'},
      {label:'运行环境', value:$('#environment').textContent || currentSummary?.environment || '—'},
      {label:'执行范围', value:targetLabel},
      {label:'检查项', value:`${checkCount} 项检查`},
    ],
    confirmText: '确认执行',
  }).then(confirmed => { if (confirmed) startRun(targets); });
}

async function saveEnvironment(event) {
  event.preventDefault();
  try {
    validateForm($('#environment-form'));
    await persistSettings(environmentDraft(), credentialDraft());
    notice('系统配置已保存');
  } catch (error) { notice(error.message, 'error'); }
}

async function runPreflight() {
  const button = $('#config-preflight');
  const progress = showProgress({title:'正在执行登录预检', message:'正在使用已保存的配置建立 API/UI 登录会话，请稍候…'});
  button.disabled = true;
  try {
    const result = await api('/api/settings/preflight', {method:'POST'});
    const passed = result.status === 'passed';
    progress.update({
      type: passed ? 'success' : 'error',
      title: passed ? '登录预检通过' : '登录预检失败',
      message: passed ? `登录会话验证通过，末项耗时 ${result.check.duration_ms} ms。` : result.check.reason || result.check.classification || '未知原因',
    });
  } catch (error) {
    progress.update({type:'error', title:'登录预检失败', message:error.message});
  } finally { button.disabled = false; }
}

async function validateAdvanced() {
  try {
    const config = parseEditor('#advanced-config', '完整配置');
    const result = await api('/api/config/validate', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({config})});
    notice(`配置有效，已启用 ${result.enabled_checks} 项`);
  } catch (error) { notice(error.message, 'error'); }
}

async function saveAdvanced() {
  try {
    const config = parseEditor('#advanced-config', '完整配置');
    await persistFullConfig(config, credentialDraft());
    notice('高级 JSON 配置已保存');
  } catch (error) { notice(error.message, 'error'); }
}

function downloadJson(value, filename) {
  const blob = new Blob([JSON.stringify(value, null, 2)], {type:'application/json'});
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  link.click();
  URL.revokeObjectURL(link.href);
}

async function exportConfig() {
  try {
    const exported = await api('/api/config/export');
    downloadJson(exported, `srm-config-${exported.config_version}.json`);
  } catch (error) { notice(error.message, 'error'); }
}

async function importMetersphere(file) {
  if (!file) return;
  try {
    const content = await file.text();
    await api('/api/api-checks/import', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({content, version:configDocument.api_version})});
    await loadConfig();
    notice('MeterSphere 场景已导入为停用草稿，请在 API 巡检列表中核对');
    showView('api-checks');
  } catch (error) { notice(error.message, 'error'); }
  finally { $('#metersphere-file').value = ''; }
}

function toggleSidebar() {
  const collapsed = document.documentElement.dataset.sidebar === 'collapsed';
  const next = collapsed ? 'expanded' : 'collapsed';
  document.documentElement.dataset.sidebar = next;
  $('#sidebar-toggle').setAttribute('aria-label', next === 'collapsed' ? '展开侧边栏' : '折叠侧边栏');
  $('#sidebar-toggle').setAttribute('title', next === 'collapsed' ? '展开侧边栏' : '折叠侧边栏');
  try { localStorage.setItem('srm-sidebar', next); } catch { /* 保持当前会话状态 */ }
}

function openSystemMenu() {
  $('#system-switcher-menu').classList.remove('hidden');
  $('#system-switcher-trigger').setAttribute('aria-expanded', 'true');
  const active = $('#system-options').querySelector('[aria-selected="true"]');
  active?.focus();
}

function closeSystemMenu(restoreFocus=false) {
  if ($('#system-switcher-menu').classList.contains('hidden')) return;
  $('#system-switcher-menu').classList.add('hidden');
  $('#system-switcher-trigger').setAttribute('aria-expanded', 'false');
  if (restoreFocus) $('#system-switcher-trigger').focus();
}

function toggleSystemMenu() {
  $('#system-switcher-menu').classList.contains('hidden') ? openSystemMenu() : closeSystemMenu(true);
}

function openMobileMenu() {
  $('#sidebar').classList.add('mobile-open');
  $('#mobile-backdrop').classList.remove('hidden');
  document.body.classList.add('drawer-open');
}

function closeMobileMenu() {
  $('#sidebar').classList.remove('mobile-open');
  $('#mobile-backdrop').classList.add('hidden');
  if ($('#command-layer').classList.contains('hidden')) document.body.classList.remove('drawer-open');
}

function selectSettingsTab(name) {
  document.querySelectorAll('[data-settings-tab]').forEach(button => {
    const active = button.dataset.settingsTab === name;
    button.classList.toggle('active', active);
    button.setAttribute('aria-selected', String(active));
  });
  document.querySelectorAll('[data-settings-panel]').forEach(panel => panel.classList.toggle('hidden', panel.dataset.settingsPanel !== name));
}

function selectIncidentTab(name) {
  document.querySelectorAll('[data-incident-tab]').forEach(button => {
    const active = button.dataset.incidentTab === name;
    button.classList.toggle('active', active);
    button.setAttribute('aria-selected', String(active));
  });
  document.querySelectorAll('[data-incident-panel]').forEach(panel => panel.classList.toggle('hidden', panel.dataset.incidentPanel !== name));
}

function syncScheduleFields() {
  const enabled = $('#schedule-enabled').checked;
  const interval = $('#schedule-mode').value === 'interval';
  $('#schedule-mode').disabled = !enabled;
  $('#schedule-interval').disabled = !enabled || !interval;
  $('#schedule-daily-times').disabled = !enabled || interval;
  $('#schedule-timezone').disabled = !enabled;
  $('#schedule-grace').disabled = !enabled;
  $('#schedule-target-api').disabled = !enabled;
  $('#schedule-target-ui').disabled = !enabled;
  document.querySelectorAll('.schedule-dependent').forEach(label => label.classList.toggle('is-dependent-disabled', !enabled));
}

function syncRunRetryFields() {
  const enabled = $('#run-retry-enabled').checked;
  $('#run-retry-max').disabled = !enabled;
  $('#run-retry-delay').disabled = !enabled;
  document.querySelectorAll('.retry-dependent').forEach(label => label.classList.toggle('is-dependent-disabled', !enabled));
}

function syncAlertFields() {
  const enabled = $('#alerts-enabled').checked;
  ['#alerts-notify-success', '#alerts-severity', '#alerts-failure-threshold', '#alerts-recovery-threshold', '#alerts-repeat', '#alerts-report-base-url', '#alerts-webhook', '#alerts-dingtalk-secret'].forEach(selector => {
    $(selector).disabled = !enabled;
  });
  document.querySelectorAll('.alert-dependent').forEach(label => label.classList.toggle('is-dependent-disabled', !enabled));
}

function commandEntries() {
  const pages = [
    {label:'运行总览', meta:'页面', view:'overview', icon:'⌂'},
    {label:'巡检项', meta:'页面', view:'checks', icon:'✓'},
    {label:'API 巡检报告', meta:'报告中心', view:'reports', reportKind:'api', icon:'API'},
    {label:'UI 场景报告', meta:'报告中心', view:'reports', reportKind:'ui', icon:'UI'},
    {label:'告警中心', meta:'页面', view:'incidents', icon:'!'},
    {label:'API 巡检', meta:'页面', view:'api-checks', icon:'API'},
    {label:'UI 场景', meta:'页面', view:'ui-scenes', icon:'UI'},
    {label:'系统设置', meta:'页面', view:'settings', icon:'⚙'},
    {label:'帮助中心', meta:'使用指南 · 操作说明 · 常见问题', view:'help', icon:'?'},
  ];
  const checks = cachedChecks.map(item => ({label:item.name, meta:item.category || '巡检项', view:item.type === 'ui' ? 'ui-scenes' : 'api-checks', icon:item.type === 'ui' ? 'UI' : 'API'}));
  const reports = cachedReports.slice(0, 10).map(item => ({label:item.run_id, meta:`${statusText(item.status)} · ${timeText(item.started_at)}`, view:'reports', report:item.run_id, icon:'R'}));
  return [...pages, ...checks, ...reports];
}

function renderCommandResults() {
  const query = $('#command-input').value.trim().toLocaleLowerCase('zh-CN');
  const entries = commandEntries().filter(item => !query || `${item.label} ${item.meta}`.toLocaleLowerCase('zh-CN').includes(query)).slice(0, 16);
  $('#command-results').innerHTML = entries.length
    ? `<div class="command-group-label">搜索结果</div>${entries.map((item, index) => `<button class="command-item" type="button" data-command-index="${index}"><i>${escapeHtml(item.icon)}</i><span>${escapeHtml(item.label)}</span><small>${escapeHtml(item.meta)}</small></button>`).join('')}`
    : '<div class="command-empty">没有匹配的页面、检查项或报告</div>';
  $('#command-results').querySelectorAll('[data-command-index]').forEach(button => button.addEventListener('click', () => {
    const item = entries[Number(button.dataset.commandIndex)];
    closeCommand();
    if (item.reportKind) setReportKind(item.reportKind);
    else showView(item.view);
    if (item.report) selectReport(item.report);
  }));
}

function openCommand() {
  closeSystemMenu();
  $('#command-layer').classList.remove('hidden');
  $('#command-layer').setAttribute('aria-hidden', 'false');
  document.body.classList.add('drawer-open');
  $('#command-input').value = '';
  renderCommandResults();
  $('#command-input').focus();
}

function closeCommand() {
  if ($('#command-layer').classList.contains('hidden')) return;
  $('#command-layer').classList.add('hidden');
  $('#command-layer').setAttribute('aria-hidden', 'true');
  if (!$('#sidebar').classList.contains('mobile-open')) document.body.classList.remove('drawer-open');
  $('#command-trigger').focus();
}

document.querySelectorAll('.nav').forEach(button => button.addEventListener('click', () => {
  if (button.classList.contains('check-nav-parent')) {
    const checksVisible = !$('#checks').classList.contains('hidden');
    if (checksVisible) setCheckNavExpanded(button.getAttribute('aria-expanded') !== 'true');
    else showView('checks');
    return;
  }
  if (button.classList.contains('report-nav-parent')) {
    const reportsVisible = !$('#reports').classList.contains('hidden');
    if (reportsVisible) setReportNavExpanded(button.getAttribute('aria-expanded') !== 'true');
    else showView('reports');
    return;
  }
  showView(button.dataset.view);
}));
document.querySelectorAll('[data-target]').forEach(button => button.addEventListener('click', () => showView(button.dataset.target)));
document.querySelectorAll('[data-check-kind]').forEach(button => button.addEventListener('click', () => setCheckKind(button.dataset.checkKind)));
document.querySelectorAll('[data-report-kind]').forEach(button => button.addEventListener('click', () => setReportKind(button.dataset.reportKind)));
document.querySelectorAll('[data-settings-tab]').forEach(button => button.addEventListener('click', () => selectSettingsTab(button.dataset.settingsTab)));
document.querySelectorAll('#environment-form input, #environment-form select, [data-settings-panel="operations"] input, [data-settings-panel="operations"] select, #advanced-config').forEach(field => {
  field.addEventListener('input', () => { if (configDocument) setSettingsDirty(true); });
  field.addEventListener('change', () => { if (configDocument) setSettingsDirty(true); });
});
document.querySelectorAll('[data-incident-tab]').forEach(button => button.addEventListener('click', () => selectIncidentTab(button.dataset.incidentTab)));
document.querySelectorAll('[data-analytics-range]').forEach(button => button.addEventListener('click', () => {
  analyticsRange = button.dataset.analyticsRange;
  document.querySelectorAll('[data-analytics-range]').forEach(item => {
    const active = item === button;
    item.classList.toggle('active', active);
    item.setAttribute('aria-checked', String(active));
  });
  if (currentSummary) renderAnalytics(currentSummary.analytics || {runs:[]});
}));
$('#analytics-compare').addEventListener('change', () => { if (currentSummary) renderAnalytics(currentSummary.analytics || {runs:[]}); });
$('#sidebar-toggle').addEventListener('click', toggleSidebar);
$('#mobile-menu').addEventListener('click', openMobileMenu);
$('#mobile-backdrop').addEventListener('click', closeMobileMenu);
$('#system-switcher-trigger').addEventListener('click', toggleSystemMenu);
$('#system-switcher-trigger').addEventListener('keydown', event => {
  if (event.key === 'ArrowDown') {
    event.preventDefault();
    openSystemMenu();
  }
});
$('#system-options').addEventListener('keydown', event => {
  if (!['ArrowDown', 'ArrowUp'].includes(event.key)) return;
  event.preventDefault();
  const options = [...$('#system-options').querySelectorAll('.system-option')];
  const current = options.indexOf(document.activeElement);
  const next = event.key === 'ArrowDown' ? (current + 1) % options.length : (current - 1 + options.length) % options.length;
  options[next]?.focus();
});
document.addEventListener('click', event => { if (!event.target.closest('.context-switcher')) closeSystemMenu(); });
$('#command-trigger').addEventListener('click', openCommand);
$('#command-backdrop').addEventListener('click', closeCommand);
$('#command-input').addEventListener('input', renderCommandResults);
$('#check-search').addEventListener('input', renderChecks);
$('#check-category-filter').addEventListener('change', renderChecks);
$('#check-status-filter').addEventListener('change', renderChecks);
$('#check-filter-reset').addEventListener('click', () => {
  $('#check-search').value = '';
  $('#check-category-filter').value = '';
  $('#check-status-filter').value = '';
  renderChecks();
  $('#check-search').focus();
});
$('#report-search').addEventListener('input', renderReports);
$('#report-status-filter').addEventListener('change', renderReports);
$('#report-trigger-filter').addEventListener('change', renderReports);
$('#report-filter-reset').addEventListener('click', () => {
  $('#report-search').value = '';
  $('#report-status-filter').value = '';
  $('#report-trigger-filter').value = '';
  renderReports();
  $('#report-search').focus();
});
document.querySelectorAll('[data-report-check-filter]').forEach(button => button.addEventListener('click', () => {
  reportCheckFilter = button.dataset.reportCheckFilter;
  document.querySelectorAll('[data-report-check-filter]').forEach(item => item.classList.toggle('active', item === button));
  renderReportDetail();
  persistReportViewState();
}));
$('#incident-search').addEventListener('input', renderIncidents);
$('#incident-status-filter').addEventListener('change', renderIncidents);
$('#incident-severity-filter').addEventListener('change', renderIncidents);
$('#incident-filter-reset').addEventListener('click', () => {
  $('#incident-search').value = '';
  $('#incident-status-filter').value = '';
  $('#incident-severity-filter').value = '';
  renderIncidents();
  $('#incident-search').focus();
});
$('#api-check-search').addEventListener('input', renderApiChecks);
$('#api-check-category').addEventListener('change', renderApiChecks);
$('#api-check-status').addEventListener('change', renderApiChecks);
$('#api-check-enable').addEventListener('click', enableSelectedApiChecks);
$('#api-check-select-all').addEventListener('change', event => {
  $('#api-checks-body').querySelectorAll('.api-check-select').forEach(checkbox => {
    if (event.target.checked) selectedApiCheckIds.add(checkbox.dataset.id);
    else selectedApiCheckIds.delete(checkbox.dataset.id);
  });
  syncApiCheckSelection();
});
$('#api-check-reset').addEventListener('click', () => {
  $('#api-check-search').value = '';
  $('#api-check-category').value = '';
  $('#api-check-status').value = '';
  renderApiChecks();
  $('#api-check-search').focus();
});
$('#ui-scene-search').addEventListener('input', renderUiScenes);
$('#ui-scene-status').addEventListener('change', renderUiScenes);
$('#ui-scene-add').addEventListener('click', () => openUiSceneEditor());
$('#ui-editor-close').addEventListener('click', closeUiSceneEditor);
$('#ui-step-add').addEventListener('click', addUiStep);
$('#ui-step-up').addEventListener('click', () => moveUiStep(-1));
$('#ui-step-down').addEventListener('click', () => moveUiStep(1));
$('#ui-step-duplicate').addEventListener('click', duplicateUiStep);
$('#ui-step-delete').addEventListener('click', deleteUiStep);
$('#ui-scene-save-draft').addEventListener('click', () => saveUiScene(false));
$('#ui-scene-test-through').addEventListener('click', () => testUiScene(true));
$('#ui-scene-test-full').addEventListener('click', () => testUiScene(false));
$('#ui-scene-save-enable').addEventListener('click', () => saveUiScene(true));
document.querySelectorAll('#ui-editor-layer input, #ui-editor-layer select').forEach(field => {
  field.addEventListener('input', () => {
    if (!uiEditorDraft) return;
    if (field.id === 'ui-scene-id') field.value = normalizeUiId(field.value);
    commitUiStepForm();
    invalidateUiVerification();
    renderUiStepList();
    if (field.id === 'ui-step-action' || field.id === 'ui-locator-type' || field.id === 'ui-scene-login-precheck') syncUiStepFields();
  });
  field.addEventListener('change', () => {
    if (!uiEditorDraft) return;
    commitUiStepForm();
    invalidateUiVerification();
    renderUiStepList();
    syncUiStepFields();
  });
});
$('#schedule-enabled').addEventListener('change', syncScheduleFields);
$('#schedule-mode').addEventListener('change', syncScheduleFields);
$('#run-retry-enabled').addEventListener('change', syncRunRetryFields);
$('#alerts-enabled').addEventListener('change', syncAlertFields);
$('#theme-toggle').addEventListener('click', () => {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem('srm-theme', next); } catch { /* 浏览器禁用本地存储时仍可临时切换 */ }
  syncThemeButton();
});
syncThemeButton();
function closeUserMenu(returnFocus=false) {
  $('#user-menu-popover').classList.add('hidden');
  $('#user-menu-trigger').setAttribute('aria-expanded', 'false');
  if (returnFocus) $('#user-menu-trigger').focus();
}
$('#user-menu-trigger').addEventListener('click', () => {
  const willOpen = $('#user-menu-popover').classList.contains('hidden');
  $('#user-menu-popover').classList.toggle('hidden', !willOpen);
  $('#user-menu-trigger').setAttribute('aria-expanded', String(willOpen));
  if (willOpen) $('#logout').focus();
});
$('#logout').addEventListener('click', async () => {
  $('#logout').disabled = true;
  try { await api('/api/auth/logout', {method:'POST'}); }
  catch (error) { if (!String(error.message).includes('失效')) notice(error.message, 'error'); }
  finally { location.replace('/login'); }
});
document.addEventListener('click', event => { if (!event.target.closest('.user-menu')) closeUserMenu(); });
document.addEventListener('click', event => {
  const trigger = event.target.closest('[data-image-preview]');
  if (trigger) openImagePreview(trigger);
});
$('#image-preview-close').addEventListener('click', () => $('#image-preview-dialog').close());
$('#image-preview-prev').addEventListener('click', () => moveImagePreview(-1));
$('#image-preview-next').addEventListener('click', () => moveImagePreview(1));
$('#image-preview-dialog').addEventListener('keydown', event => {
  if (!['ArrowLeft', 'ArrowRight'].includes(event.key) || event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return;
  event.preventDefault();
  event.stopPropagation();
  moveImagePreview(event.key === 'ArrowLeft' ? -1 : 1);
});
$('#image-preview-dialog').addEventListener('click', event => {
  if (event.target !== event.currentTarget) return;
  const bounds = event.currentTarget.getBoundingClientRect();
  if (event.clientX < bounds.left || event.clientX > bounds.right
      || event.clientY < bounds.top || event.clientY > bounds.bottom) event.currentTarget.close();
});
$('#image-preview-dialog').addEventListener('close', () => {
  document.body.classList.remove('image-preview-open');
  $('#image-preview-image').removeAttribute('src');
  if (imagePreviewReturnFocus?.isConnected) imagePreviewReturnFocus.focus({preventScroll:true});
  imagePreviewReturnFocus = null;
  imagePreviewItems = [];
  imagePreviewIndex = 0;
});
$('#image-preview-image').addEventListener('error', () => {
  if (!$('#image-preview-dialog').open) return;
  $('#image-preview-image').classList.add('hidden');
  $('#image-preview-error').classList.remove('hidden');
});
$('#refresh').addEventListener('click', async () => {
  await loadSystems();
  await Promise.all([loadSummary(), loadChecks()]);
  if (!$('#reports').classList.contains('hidden')) loadReports();
  if (!$('#incidents').classList.contains('hidden')) loadIncidents();
  if (!$('#settings').classList.contains('hidden')) loadConfig();
  if (!$('#api-checks').classList.contains('hidden')) loadConfig();
  if (!$('#ui-scenes').classList.contains('hidden')) loadUiWorkspace();
});
$('#system-select').addEventListener('change', event => switchSystem(event.target.value).catch(error => notice(error.message, 'error')));
$('#run').addEventListener('click', () => requestRun());
$('#run-menu-trigger').addEventListener('click', event => {
  event.stopPropagation();
  const menu = $('#run-menu-popover');
  const open = menu.classList.contains('hidden');
  menu.classList.toggle('hidden', !open);
  $('#run-menu-trigger').setAttribute('aria-expanded', String(open));
});
document.querySelectorAll('[data-run-targets]').forEach(option => option.addEventListener('click', () => {
  if (option.disabled) return;
  const targets = option.dataset.runTargets.split(',');
  $('#run-menu-popover').classList.add('hidden');
  $('#run-menu-trigger').setAttribute('aria-expanded', 'false');
  requestRun(targets);
}));
document.addEventListener('click', event => {
  if (!event.target.closest('.run-menu')) {
    $('#run-menu-popover').classList.add('hidden');
    $('#run-menu-trigger').setAttribute('aria-expanded', 'false');
  }
});
$('#message-dialog').addEventListener('close', () => {
  const item = activeMessage;
  if (!item) return;
  clearTimeout(messageTimer);
  const confirmed = $('#message-dialog').returnValue === 'confirm';
  activeMessage = null;
  item.resolve(confirmed);
  if (item.options.mode === 'confirm') item.returnFocus?.focus?.();
  queueMicrotask(presentNextMessage);
});
$('#message-dialog').addEventListener('cancel', event => {
  if (activeMessage && !activeMessage.options.dismissible) event.preventDefault();
});
$('#environment-form').addEventListener('submit', saveEnvironment);
$('#config-reload').addEventListener('click', loadConfig);
$('#config-preflight').addEventListener('click', runPreflight);
$('#save-operations').addEventListener('click', saveOperations);
$('#test-notification').addEventListener('click', testNotification);
$('#add-check').addEventListener('click', openNewCheckEditor);
$('#add-auth-flow').addEventListener('click', () => openAuthFlow());
$('#check-auth-flow').addEventListener('change', () => {
  if (authFlowEditor) return;
  try {
    const headers = parseEditor('#check-headers', '请求头', {});
    if (!headers || Array.isArray(headers) || typeof headers !== 'object') return;
    if ($('#check-auth-flow').value && !Object.keys(headers).some(key => key.toLowerCase() === 'authorization')) headers.Authorization = 'Bearer ${token}';
    else if (!$('#check-auth-flow').value && headers.Authorization === 'Bearer ${token}') delete headers.Authorization;
    $('#check-headers').value = pretty(headers);
    syncApiEditorDirtyState();
  } catch { /* Keep invalid JSON in place for the user to repair. */ }
});
$('#auth-step-add').addEventListener('click', addAuthStep);
$('#auth-step-up').addEventListener('click', () => moveAuthStep(-1));
$('#auth-step-down').addEventListener('click', () => moveAuthStep(1));
$('#auth-step-remove').addEventListener('click', removeAuthStep);
$('#check-form').addEventListener('submit', saveCheck);
$('#check-save-draft').addEventListener('click', () => persistCheck(false));
$('#check-test').addEventListener('click', testCheck);
$('#check-id').addEventListener('blur', normalizeCheckIdInput);
$('#check-path').addEventListener('blur', () => {
  try { normalizeCheckPathInput(); }
  catch (error) { notice(error.message, 'error'); }
});
document.querySelectorAll('#check-form input, #check-form select, #check-form textarea').forEach(field => {
  field.addEventListener('input', syncApiEditorDirtyState);
  field.addEventListener('change', syncApiEditorDirtyState);
});
document.querySelectorAll('.api-section-link').forEach(button => button.addEventListener('click', () => {
  const target = document.getElementById(button.dataset.apiSection);
  if (!target) return;
  target.scrollIntoView({behavior:'smooth', block:'start'});
  document.querySelectorAll('.api-section-link').forEach(item => item.classList.toggle('active', item === button));
}));
$('#api-editor-form-scroll').addEventListener('scroll', event => {
  const scroller = event.currentTarget;
  const sections = [...scroller.querySelectorAll('[data-api-config-section]')];
  let active = sections[0];
  for (const section of sections) {
    if (section.offsetTop - scroller.scrollTop <= 52) active = section;
  }
  document.querySelectorAll('.api-section-link').forEach(button => button.classList.toggle('active', button.dataset.apiSection === active?.id));
});
$('#api-editor-close').addEventListener('click', () => closeCheckEditor());
$('#check-cancel').addEventListener('click', () => closeCheckEditor());
document.addEventListener('keydown', event => {
  if ($('#image-preview-dialog').open) return;
  if ((event.metaKey || event.ctrlKey) && event.key.toLocaleLowerCase() === 'k') {
    event.preventDefault();
    $('#command-layer').classList.contains('hidden') ? openCommand() : closeCommand();
    return;
  }
  if (event.key === 'Escape') {
    closeUserMenu(true);
    closeSystemMenu(true);
    closeCheckEditor();
    closeUiSceneEditor();
    closeCommand();
    closeMobileMenu();
  }
});
$('#validate-config').addEventListener('click', validateAdvanced);
$('#save-advanced').addEventListener('click', saveAdvanced);
$('#export-config').addEventListener('click', exportConfig);
$('#import-metersphere').addEventListener('click', () => $('#metersphere-file').click());
$('#metersphere-file').addEventListener('change', event => importMetersphere(event.target.files?.[0]));
$('#download-report').addEventListener('click', async () => {
  if (!selectedReport) return;
  const report = await api(`/api/reports/${currentReportKind}/${encodeURIComponent(selectedReport)}`);
  const blob = new Blob([JSON.stringify(report, null, 2)], {type:'application/json'});
  const link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = `${currentReportKind}-${selectedReport}.json`; link.click(); URL.revokeObjectURL(link.href);
});
syncCheckKindChrome();
syncReportKindChrome();
// Pause decorative scanning while the tab is in the background.
const syncHealthRadarVisibility = () => $('#health-card').classList.toggle('radar-paused', document.hidden);
document.addEventListener('visibilitychange', syncHealthRadarVisibility);
syncHealthRadarVisibility();
if (location.protocol === 'file:') {
  $('#environment').textContent = '本地预览';
  $('#refresh').disabled = true;
  $('#run').disabled = true;
  notice('当前是文件预览模式，只能查看界面。请在项目目录运行 python3 app.py，然后打开 http://127.0.0.1:8091/。', 'warning');
} else {
  loadAuthSession()
    .then(loadSystems)
    .then(() => openRequestedReport())
    .then(() => Promise.all([loadSummary(), loadChecks()]))
    .catch(error => notice(error.message, 'error'));
}
setInterval(() => { if (activeRun) { loadSummary().then(() => { if (!activeRun) loadReports(); }); } }, 2000);

// 帮助内容与实际工作区共用导航；阅读和搜索均不触发巡检或修改配置。
(() => {
  const link = (view, label, tab = '') => `<button class="help-inline-link" type="button" data-help-view="${view}"${tab ? ` data-help-settings="${tab}"` : ''}>${label}<span aria-hidden="true"> ↗</span></button>`;
  const note = (title, body) => `<aside class="help-callout"><span aria-hidden="true">i</span><div><b>${title}</b><p>${body}</p></div></aside>`;
  const steps = items => `<ol class="help-steps">${items.map(([title, body]) => `<li><div><h4>${title}</h4><p>${body}</p></div></li>`).join('')}</ol>`;
  const table = (headers, rows) => `<div class="help-table-wrap"><table><thead><tr>${headers.map(text => `<th>${text}</th>`).join('')}</tr></thead><tbody>${rows.map(row => `<tr>${row.map(text => `<td>${text}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
  const code = (caption, value) => `<figure class="help-code"><figcaption>${caption}</figcaption><pre><code>${escapeHtml(value)}</code></pre></figure>`;
  const docs = [
    {
      id:'start', number:'01', title:'快速入门', subtitle:'完成第一次巡检', icon:'start', time:'约 3 分钟',
      intro:'用一条完整的工作流，把系统配置、巡检执行和结果复盘串起来。首次使用，建议从这里开始。',
      sections:[
        {id:'flow', title:'巡检的完整路径', html:'<div class="help-flow"><span><i>01</i>选择系统</span><b>→</b><span><i>02</i>配置与验证</span><b>→</b><span><i>03</i>执行巡检</span><b>→</b><span><i>04</i>查看证据</span></div><p>平台支持 GSRM、SRM 和 New SRM。API 检查验证接口响应与业务断言，UI 场景验证页面操作与可见结果；两类报告独立展示。</p>'},
        {id:'first-run', title:'5 步完成第一次巡检', html:steps([
          ['选择目标系统', '点击顶部“当前系统”，选择需要巡检的系统。确认环境标签；每套系统的账号、配置、报告和告警相互独立。'],
          ['保存环境与巡检账号', `进入${link('settings','系统设置','environment')}，核对基础地址、超时、报告留存与账号信息。控制台登录账号和被巡检系统的业务账号分别使用。密码留空表示保留原值。`],
          ['核对巡检项并验证', `在${link('api-checks','API 巡检')}或${link('ui-scenes','UI 场景')}维护检查项。先保存停用草稿并测试，确认路径、参数和断言，再启用。系统设置中的“预检已保存配置”只验证登录与会话。`],
          ['手动执行一轮巡检', '使用顶部执行按钮旁的下拉菜单，选择“仅 API”“仅 UI”或“API + UI”，再点击执行按钮。组合运行依次执行 API、UI，一个阶段失败不会阻止另一阶段。'],
          ['复盘报告与诊断证据', `前往${link('reports','报告中心')}选择相应报告类型和运行记录。API 报告查看断言与失败原因；UI 报告查看步骤、耗时和截图。确认手动执行正常后，再配置自动调度。`],
        ])},
        {id:'ready', title:'什么时候开启自动巡检？', html:'<p>先让手动巡检通过，再确认告警渠道可用，最后启用调度。这样能更快区分配置问题与业务故障。</p>'+note('推荐顺序', '保存 Webhook → 发送测试通知 → 启用告警 → 启用调度。调度与告警的开关、执行范围和阈值都以当前系统设置为准。')+`<div class="help-next-action">${link('settings','前往系统设置','environment')}<button class="help-inline-link" type="button" data-help-topic="schedule">阅读调度与告警指南 →</button></div>`},
      ],
    },
    {
      id:'workspace', number:'02', title:'认识工作区', subtitle:'导航与多系统管理', icon:'workspace', time:'约 2 分钟',
      intro:'左侧导航组织日常工作，顶部系统切换器决定操作范围。理解这两个层次，就能快速找到需要的功能。',
      sections:[
        {id:'navigation', title:'各页面分别用来做什么？', html:table(['功能入口','用途'],[
          ['运行总览','查看所选周期的健康度、通过率、耗时趋势、模块结果与待处理异常。'],
          ['巡检项','按 API / UI 查看当前系统清单、业务模块与启用状态；用于快速核对覆盖范围。'],
          ['报告中心','API 与 UI 独立查看历史报告，按运行标识、结果和触发方式筛选，并下载选中报告的 JSON。'],
          ['告警中心','查看故障事件、恢复记录，以及 Webhook 通知的投递状态与错误。'],
          ['API 巡检 / UI 场景','分别编辑接口配置与页面步骤，保存草稿、测试并启用。'],
          ['系统设置','维护环境、业务账号、调度、失败重跑、告警及高级配置。'],
        ])},
        {id:'systems', title:'多系统切换与数据归属', html:'<p>点击顶部系统名称切换 GSRM、SRM 或 New SRM。系统间独立保存配置、凭据、历史报告、任务锁与告警事件。切换后，请再次核对顶部系统名称与环境标签。</p>'+note('配置何时生效？','正在执行的巡检使用启动时的配置快照。保存的新配置从下一轮执行开始生效。')},
        {id:'shortcuts', title:'更高效地使用控制台', html:'<ul><li><b>全局搜索：</b>点击顶部搜索框，或按 macOS 的 ⌘ K / Windows 的 Ctrl K，查找页面、检查项和报告。</li><li><b>阅读模式：</b>右上角月亮 / 太阳按钮切换深浅主题；左侧折叠按钮可为内容留出更多空间。</li><li><b>筛选：</b>清单和报告页可按关键词、模块或状态缩小范围，使用“清除筛选”恢复完整列表。</li><li><b>登录会话：</b>控制台会话从登录时起默认 30 分钟失效，持续操作不会延长有效期。过期后重新登录即可。</li></ul>'},
      ],
    },
    {
      id:'api', number:'03', title:'API 巡检配置', subtitle:'请求、变量与业务断言', icon:'api', time:'约 4 分钟',
      intro:'让接口“可访问”只是第一步。通过业务断言明确成功条件，再用响应变量把登录和后续业务操作连接起来。',
      sections:[
        {id:'request', title:'新建与配置请求', html:steps([
          ['填写基础信息', '进入“API 巡检”并点击“新建 API 巡检”。填写 ID、名称、模块、请求方法和严重级别。ID 支持 camelCase，保存时会转换为小写短横线格式。'],
          ['设置请求入口', '填写请求路径或完整 URL、预期 HTTP 状态码与超时。同源完整 URL 会转换为站内路径；请使用实际接口定义核对地址。'],
          ['配置 Headers 与 Body', '请求头填写 JSON 对象；请求体按接口要求选择 JSON 或表单编码。变量使用 ${变量名} 引用前序提取值或系统凭据，不把密码直接写入请求配置。'],
          ['添加断言与变量提取', '设置业务成功条件；登录接口按协议提取 ticket 或 token，后续接口引用同名变量。不同系统的登录协议与成功码可能不同。'],
        ])},
        {id:'assertions', title:'业务断言与响应提取', html:'<p>HTTP 200 表示请求获得了预期响应，并不一定表示业务成功。断言使用 JSONPath 定位字段，再通过操作符检查其值。下面以 GSRM 的成功码和消息为例，其他接口应按真实响应调整。</p>'+code('业务断言 · JSON', '[\n  {"path": "$.code", "op": "equals", "value": 100000000},\n  {"path": "$.message", "op": "equals", "value": "操作成功"}\n]')+table(['常用操作符','检查含义'],[['equals','字段值与预期相等'],['present / nonempty','字段存在 / 字段非空'],['contains','结果包含指定内容'],['greater_than / type_is','数值大于预期 / 类型符合预期']])+code('响应变量提取 · 示例字段需按实际响应调整', '[\n  {"variable": "ticket", "path": "$.ticket"}\n]')+'<p>提取后，可在请求头中使用 <code>Bearer ${ticket}</code>。票据只在当前轮次内存中传递，不写入报告。</p>'},
        {id:'enable', title:'保存草稿、测试与启用', html:'<p>“保存草稿”保存停用配置，不参与自动巡检。登录前置流程在一个页面按顺序编排请求，通过“测试完整流程”验证后整体启用，流程输出可通过 ${token} 引用。“测试接口”使用当前编辑内容，并先执行所选登录前置；未选择流程时使用已有会话准备项；测试结果出现在右侧，不写入正式报告、不触发告警。</p><p>确认参数和断言已核实后，可“保存并启用”。仍含待确认参数的检查项不能启用；业务接口需要配置断言，HEAD 和预期 204/205/304 响应可只检查 HTTP 状态。</p>'+note('MeterSphere 导入','从 API 巡检页导入场景 JSON，生成停用草稿。逐项核对 URL、请求体、变量和业务断言，验证后再启用。')+link('api-checks','前往 API 巡检')},
      ],
    },
    {
      id:'ui', number:'04', title:'UI 场景编排', subtitle:'登录前置、步骤与截图', icon:'ui', time:'约 4 分钟',
      intro:'按真实用户的操作路径编排页面检查。每一步都有动作、断言与截图，让结果可以被复核。',
      sections:[
        {id:'scene', title:'创建场景与登录前置', html:steps([
          ['新建场景', '进入“UI 场景”，点击“新建场景”，填写 ID、名称、模块及页面入口。编辑器左侧为步骤时间线，中间为动作字段，右侧为测试与证据。'],
          ['配置登录场景', '登录流程勾选“可作为登录前置”。加入能够真正判断登录成功的断言，并标记为登录成功断言；例如断言 URL 已离开登录页面。'],
          ['关联业务场景', '在业务场景的“运行前置条件”中选择已启用的登录场景。登录和业务步骤共享同一浏览器上下文；同一登录场景在一个 UI 阶段中只执行一次。'],
        ])},
        {id:'actions', title:'步骤动作与定位器', html:table(['动作','使用场景'],[['goto','打开站内路径或与 UI 基础地址同源的完整 URL'],['click / fill / select','页面交互、填写表单、选择选项'],['wait_visible','等待元素出现，避免页面尚未完成加载时检查'],['assert_visible / assert_text','检查元素可见性与文字内容'],['assert_count / assert_url','检查元素数量与页面地址']])+'<p>定位器优先使用 test_id、角色与名称、label、placeholder 或可见文本。必要时使用简短 CSS；不支持任意 JavaScript 或 XPath。</p>'+note('敏感输入','账号与密码必须使用完整的 ${VARIABLE} 凭据引用，例如 ${SRM_UI_PASSWORD}，并勾选敏感输入 / 截图遮罩。可为其他业务敏感信息配置截图遮罩。')},
        {id:'test', title:'测试与保存启用', html:'<p>调试时使用“测试到当前步骤”；完成全部编排后执行“完整测试”。未测试或测试未通过，也可以“保存并启用”。完整测试通过后显示“已验证”；修改步骤或登录关联后，验证状态会失效，但仍可保存并启用。</p><p>临时测试证据不进入正式报告。正式巡检中，每个已启用步骤生成截图，失败步骤额外生成整页截图；失败重跑重新创建浏览器会话。</p>'+note('运行前检查','UI 巡检需要可用的 Playwright 和浏览器运行时。界面会显示运行环境状态。场景按配置执行页面交互并生成截图证据。')+link('ui-scenes','前往 UI 场景')},
      ],
    },
    {
      id:'reports', number:'05', title:'执行与报告', subtitle:'读懂结果，定位异常', icon:'reports', time:'约 3 分钟',
      intro:'先确认执行范围，再结合报告中的状态、断言和证据判断原因。一次运行的失败与一个告警事件并不是同一概念。',
      sections:[
        {id:'run', title:'手动执行与失败重跑', html:'<p>顶部下拉菜单选择仅 API、仅 UI 或 API + UI，执行按钮会随选择更新。没有启用的对应检查项时，无法执行该范围。同一系统一次只运行一轮；调度和手动执行共用任务锁。</p><p>组合巡检按 API → UI 分阶段执行。启用失败重跑时，只重跑失败阶段，不重复已经成功的另一阶段。重跑期间任务继续持锁，中间失败不单独生成正式报告或触发告警，最终结果才进入报告与告警流程。</p>'+note('重跑次数以设置为准','在“系统设置 → 调度与告警”查看是否启用重跑、最大次数和等待时间。执行中的等待可能来自阶段重跑，请结合当前状态判断。')},
        {id:'read', title:'阅读 API 与 UI 报告', html:'<p>进入报告中心，先切换“API 巡检”或“UI 场景”，再按运行标识、结果、手动 / 定时触发筛选。选择左侧历史记录，右侧展示该轮详情，可筛选全部、失败或跳过项。</p>'+table(['状态','含义与下一步'],[['通过','本轮检查满足已配置的成功条件；通过不代表未配置的业务规则也已验证。'],['失败','请求、断言或页面步骤未达到预期。查看失败分类和具体证据，再核对配置或业务状态。'],['跳过','通常是登录 / 依赖检查未通过。优先排查前置失败，避免把跳过误判为业务接口故障。']])+'<p>API 报告重点关注接口耗时、断言预期与失败原因；UI 报告沿步骤时间线查看动作、断言和截图。顶部“下载 JSON”下载当前选中的类型化报告。</p>'+link('reports','前往报告中心')},
        {id:'diagnose', title:'建议的异常排查顺序', html:steps([['先检查前置登录','确认当前系统的业务账号、登录路径、票据提取与 UI 登录依赖正常。'],['再核对失败证据','API 对照 HTTP 状态与业务断言；UI 对照失败截图、定位器、页面地址与加载情况。'],['区分业务异常与配置变化','接口字段、成功码或页面结构变化可能使检查契约失效。核实真实响应或页面后更新配置并重新测试。'],['最后查看告警投递','巡检失败达到配置阈值后才形成事件；事件形成与通知成功投递需要分别确认。']])},
      ],
    },
    {
      id:'schedule', number:'06', title:'调度与告警', subtitle:'持续巡检与故障通知', icon:'schedule', time:'约 3 分钟',
      intro:'在手动巡检验证完成后，用调度保持持续检查，用阈值与恢复规则减少重复消息。',
      sections:[
        {id:'schedule', title:'配置定时调度', html:'<p>进入“系统设置 → 调度与告警”，选择固定间隔或每日固定时间，设置调度时区和 API / UI 执行范围。确认保存后，内置调度器按当前系统配置执行。</p><p>上一轮未结束时，计划轮次会作为重叠跳过。服务重启后，只会在漏跑宽限期内补跑一次；超过宽限期则记录为漏跑。调度依赖服务进程持续运行，进程完全停止时无法执行巡检或发送停机告警。</p>'+link('settings','前往调度与告警','operations')},
        {id:'thresholds', title:'理解告警与恢复规则', html:table(['配置项','作用'],[['连续失败阈值','检查项连续失败达到阈值后打开故障事件。'],['重复提醒周期','故障持续期间按周期提醒，避免每次巡检都发送相同消息。'],['连续恢复阈值','已经打开的事件连续通过达到阈值后，发送恢复通知。'],['成功通知','开启后，每次最终成功的巡检都会通知，包括手动和定时执行。']])+'<p>登录失败引起的后续跳过项不会单独告警。在“告警中心 → 故障事件”查看事件是否仍未恢复，在“通知投递”查看发送状态。Webhook 投递失败时会自动退避重试，最多 5 次。</p>'},
        {id:'notification', title:'Webhook、钉钉与报告链接', html:'<p>保存 Webhook 后，先在告警中心“发送测试通知”，确认投递成功。Webhook 和加签密钥作为敏感配置保存，读取时不返回其明文。</p><p>使用钉钉自定义机器人时，可配置加签密钥。要在通知中打开完整报告，请填写“巡检平台访问地址”：它应是浏览器可访问的本控制台地址，例如 <code>https://inspection.example.com</code>，而不是被巡检 SRM 的业务地址。</p>'+note('报告访问仍需登录','通知链接携带系统、报告类型和运行标识。未登录时先认证，再回到对应报告；未配置平台访问地址时，通知降级为不带报告按钮的 Markdown 消息。')+link('incidents','前往告警中心')},
      ],
    },
    {
      id:'faq', number:'07', title:'常见问题', subtitle:'快速排查使用中的疑问', icon:'faq', time:'按需查阅',
      intro:'从最常见的现象出发，逐项核对配置与证据。展开问题即可查看处理建议。',
      sections:[
        {id:'config', title:'账号与配置', faq:[
          ['登录控制台的账号可以直接用于 SRM 巡检吗？','两者独立。控制台账号用于访问管理页面，巡检业务账号需要在每套系统设置中单独配置。UI 登录与接口登录不一致时，使用独立的 UI 用户名和密码。'],
          ['密码框为什么是空的？保存会清空原密码吗？','读取配置不会返回密码。已有密码时，留空保存表示不修改；只有填写新值并保存才会更新。请核对页面上的已配置状态。'],
          ['为什么检查项不能启用？','API 先核对待确认参数和业务断言。UI 不要求测试通过即可保存并启用，但场景配置和前置登录关联必须有效。'],
          ['提示配置版本冲突怎么办？','说明同一份配置已经被其他操作更新。先记录本次未保存的修改，重新载入最新配置，核对差异后再编辑和保存，避免覆盖他人的修改。'],
        ]},
        {id:'execution', title:'执行与报告', faq:[
          ['执行按钮不可用，或者本轮没有检查结果？','先确认顶部系统和执行范围，检查对应类型是否有启用项，以及当前系统是否已有运行中的任务。停用草稿不会参与巡检。'],
          ['为什么 HTTP 200 仍然显示失败？','HTTP 状态符合预期后，还需要通过业务断言、响应解析或变量提取。打开 API 报告查看具体失败原因，对照真实响应核对成功码、消息和 JSONPath。'],
          ['很多检查项同时显示跳过，应该先排查哪里？','先查看登录预检或 UI 登录前置是否失败。依赖登录的业务检查会被跳过，优先修复账号、会话、票据提取或页面定位问题。'],
          ['为什么 UI 场景修改后显示待验证？','测试通过后修改了任一步骤或登录关联，原验证会失效。仍可直接保存并启用；重新完整测试通过后，场景会恢复“已验证”状态。'],
          ['测试接口或测试场景后，历史报告里为什么没有记录？','编辑器测试使用临时结果，不写入正式报告、不触发告警。需要先保存并启用，再通过顶部执行按钮运行正式巡检。'],
          ['页面加载超时或 UI 定位失败怎么办？','查看失败截图，核对页面地址、可见文字、定位器与超时。优先使用稳定的 test_id 或语义定位器；确认页面有实际可见内容。UI 环境不可用时，请联系维护人员检查浏览器运行时。'],
        ]},
        {id:'alerts', title:'通知与访问', faq:[
          ['巡检失败了，为什么没有收到告警？','检查系统告警和检查项告警是否启用、是否达到连续失败阈值，以及是否处于重复提醒周期。再到告警中心查看事件和投递状态；登录导致的后续跳过不会单独告警。'],
          ['通知投递失败应该检查什么？','在“通知投递”查看错误与尝试次数。核对 Webhook、钉钉加签密钥和服务器网络，再发送测试通知验证。修改凭据后需保存配置。'],
          ['钉钉通知没有报告按钮，或链接无法打开？','核对“巡检平台访问地址”是否配置为浏览器可访问的控制台地址。未配置时不会显示报告按钮；打开报告需要有效的控制台登录会话。'],
          ['操作中突然跳转登录页，是什么原因？','控制台会话默认从登录起 30 分钟失效，操作不会延长有效期。重新登录后继续；未保存的编辑内容可能需要重新填写。'],
        ]},
      ],
    },
  ];
  const icons = {
    start:'<path d="m13 3-9 11h7l-1 7 10-12h-7l1-6Z"/>',
    workspace:'<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
    api:'<path d="M8 8 4 12l4 4M16 8l4 4-4 4M14 4l-4 16"/>',
    ui:'<rect x="3" y="4" width="18" height="14" rx="2"/><path d="M8 21h8M12 18v3M7 9h4M7 13h8"/>',
    reports:'<path d="M5 3h10l4 4v14H5ZM14 3v5h5M9 12h6M9 16h6"/>',
    schedule:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    faq:'<circle cx="12" cy="12" r="9"/><path d="M9.5 9a2.5 2.5 0 1 1 4 2c-1.5 1-1.5 1-1.5 3M12 17h.01"/>',
  };
  let activeTopic = 'start';
  let sectionObserver;
  const reducedMotion = () => matchMedia('(prefers-reduced-motion: reduce)').matches;
  const plainText = html => {
    const container = document.createElement('div');
    container.innerHTML = html;
    return container.textContent.replace(/\s+/g, ' ').trim();
  };
  const sectionHtml = section => section.html || section.faq.map(([question, answer]) => `<details class="help-faq"><summary>${question}<span aria-hidden="true">＋</span></summary><p>${answer}</p></details>`).join('');
  // 建立一次纯文本索引，搜索不插入或解释用户输入的 HTML。
  const searchIndex = docs.flatMap(doc => doc.sections.map(section => ({doc, section, text:plainText(sectionHtml(section))})));
  $('#help-topics').innerHTML = docs.map(doc => `<button type="button" class="help-topic" data-help-topic="${doc.id}"><svg viewBox="0 0 24 24" aria-hidden="true">${icons[doc.icon]}</svg><span><b>${doc.title}</b><small>${doc.subtitle}</small></span><em>${doc.number}</em></button>`).join('');

  function renderTopic(id, {scroll = false, focus = false} = {}) {
    const doc = docs.find(item => item.id === id);
    if (!doc) return;
    activeTopic = id;
    $('#help-search').value = '';
    $('#help-search-results').classList.add('hidden');
    $('#help-library').classList.remove('hidden');
    $('#help-topics').querySelectorAll('[data-help-topic]').forEach(button => {
      const active = button.dataset.helpTopic === id;
      button.classList.toggle('active', active);
      if (active) button.setAttribute('aria-current','page');
      else button.removeAttribute('aria-current');
    });
    const index = docs.indexOf(doc);
    $('#help-article').innerHTML = `<header class="help-article-head"><div class="help-article-meta"><span class="help-kicker">CHAPTER ${doc.number} / 07</span><span>${doc.time}</span></div><h2 id="help-article-title" tabindex="-1">${doc.title}</h2><p>${doc.intro}</p><div class="help-article-tags"><span>使用说明</span><span>${doc.subtitle}</span></div></header>${doc.sections.map((section, i) => `<section class="help-doc-section" id="help-${doc.id}-${section.id}" aria-labelledby="help-heading-${doc.id}-${section.id}"><h3 id="help-heading-${doc.id}-${section.id}" tabindex="-1"><span>${String(i + 1).padStart(2,'0')}</span>${section.title}</h3>${sectionHtml(section)}</section>`).join('')}<nav class="help-article-pagination" aria-label="相邻章节">${index ? `<button type="button" data-help-topic="${docs[index - 1].id}"><small>← 上一篇</small><b>${docs[index - 1].title}</b></button>` : '<span></span>'}${index < docs.length - 1 ? `<button type="button" data-help-topic="${docs[index + 1].id}"><small>下一篇 →</small><b>${docs[index + 1].title}</b></button>` : '<span></span>'}</nav>`;
    $('#help-toc-links').innerHTML = doc.sections.map((section, i) => `<a class="${i === 0 ? 'active' : ''}" href="#help-${doc.id}-${section.id}">${section.title}</a>`).join('');
    sectionObserver?.disconnect();
    if ('IntersectionObserver' in window) {
      sectionObserver = new IntersectionObserver(entries => {
        const visible = entries.filter(entry => entry.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
        if (visible) $('#help-toc-links').querySelectorAll('a').forEach(item => item.classList.toggle('active', item.hash === `#${visible.target.id}`));
      }, {rootMargin:'-100px 0px -55% 0px'});
      $('#help-article').querySelectorAll('.help-doc-section').forEach(section => sectionObserver.observe(section));
    }
    if (scroll) $('#help-library').scrollIntoView({behavior:reducedMotion() ? 'instant' : 'smooth', block:'start'});
    if (focus) document.getElementById('help-article-title').focus({preventScroll:true});
  }

  function searchHelp() {
    const query = $('#help-search').value.trim().toLocaleLowerCase('zh-CN');
    if (!query) {
      $('#help-search-results').classList.add('hidden');
      $('#help-library').classList.remove('hidden');
      return;
    }
    const terms = query.split(/\s+/);
    const results = searchIndex.filter(({doc, section, text}) => terms.every(term => `${doc.title} ${doc.subtitle} ${section.title} ${text}`.toLocaleLowerCase('zh-CN').includes(term)));
    $('#help-library').classList.add('hidden');
    $('#help-search-results').classList.remove('hidden');
    $('#help-result-count').textContent = `“${$('#help-search').value.trim()}” · 找到 ${results.length} 个相关章节`;
    $('#help-result-list').innerHTML = results.length ? results.map(({doc, section, text}) => {
      const matchAt = text.toLocaleLowerCase('zh-CN').indexOf(terms[0]);
      const start = Math.max(0, matchAt - 24);
      const snippet = `${start ? '…' : ''}${text.slice(start, start + 110)}${text.length > start + 110 ? '…' : ''}`;
      return `<button class="help-result" type="button" data-help-topic="${doc.id}" data-help-section="${section.id}"><span class="help-result-chapter">${doc.title} / ${doc.number}</span><b>${section.title}<i aria-hidden="true">↗</i></b><span>${escapeHtml(snippet)}</span></button>`;
    }).join('') : '<div class="help-no-results"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="10" cy="10" r="6"/><path d="m15 15 5 5M8 10h4"/></svg><h3>暂时没有找到相关内容</h3><p>试试更简短的关键词，如“登录”“截图”或“通知”，<br>也可以返回指南，按章节浏览。</p></div>';
  }

  $('#help').addEventListener('click', event => {
    const topic = event.target.closest('[data-help-topic]');
    if (topic) {
      renderTopic(topic.dataset.helpTopic, {scroll:!topic.dataset.helpSection, focus:true});
      if (topic.dataset.helpSection) {
        const section = document.getElementById(`help-${activeTopic}-${topic.dataset.helpSection}`);
        section.querySelectorAll('details').forEach(item => { item.open = true; });
        section.scrollIntoView({behavior:reducedMotion() ? 'instant' : 'smooth', block:'start'});
        section.querySelector('h3').focus({preventScroll:true});
      }
      return;
    }
    const view = event.target.closest('[data-help-view]');
    if (view) {
      showView(view.dataset.helpView);
      if (view.dataset.helpSettings) selectSettingsTab(view.dataset.helpSettings);
      document.querySelector(`.nav[data-view="${view.dataset.helpView}"]`)?.focus({preventScroll:true});
      window.scrollTo({top:0, behavior:reducedMotion() ? 'instant' : 'smooth'});
    }
  });
  $('#help-toc-links').addEventListener('click', event => {
    const anchor = event.target.closest('a');
    if (!anchor) return;
    event.preventDefault();
    const section = document.getElementById(anchor.hash.slice(1));
    section.scrollIntoView({behavior:reducedMotion() ? 'instant' : 'smooth', block:'start'});
    section.querySelector('h3').focus({preventScroll:true});
    $('#help-toc-links').querySelectorAll('a').forEach(item => item.classList.toggle('active', item === anchor));
  });
  $('#help-search').addEventListener('input', searchHelp);
  $('#help-search').addEventListener('keydown', event => {
    if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); renderTopic(activeTopic); }
    if (event.key === 'Enter') { event.preventDefault(); $('#help-result-list button')?.focus(); }
  });
  $('#help-search-clear').addEventListener('click', () => { renderTopic(activeTopic); $('#help-search').focus(); });
  renderTopic(activeTopic);
})();
