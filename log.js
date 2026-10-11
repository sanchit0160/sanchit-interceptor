/**
 * Sanchit Interceptor — Master Workbench Controller
 * Copyright (c) 2026 Sanchit. All rights reserved.
 *
 * Coordinates:
 * - Proxy HTTP History & Live Streaming
 * - .sanchit & .burp File Import / Export / Analysis
 * - Proxy Intercept (Pause / Edit / Drop / Forward)
 * - Repeater Tool (Tabbed crafter & CORS-bypassing runner)
 * - Decoder & JWT Inspector
 * - Target Site Map & Scope Engine
 * - Comparer Diff Tool
 * - Resizable Dividers & Hex View
 */

import {
  getAllRequests, getRequest, putRequest, bulkPutRequests,
  clearAllRequests, deleteRequest, countRequests,
  saveRepeaterTab, getAllRepeaterTabs, deleteRepeaterTab,
  getAllWebSocketFrames, clearAllWebSocketFrames,
  setMeta, getMeta,
} from './db.js';

import {
  parseRawHttpRequest, parseRawHttpResponse,
  formatRawHttpRequest, formatRawHttpResponse,
} from './core/http-parser.js';

import {
  createSanchitProject, parseSanchitProject, downloadSanchitFile,
} from './core/sanchit-format.js';

import {
  parseBurpXml, exportBurpXml, safeBase64Decode, safeBase64Encode,
} from './core/burp-xml-parser.js';

import {
  parseHar, exportHar,
} from './core/har-parser.js';

import {
  urlEncode, urlDecode, base64Encode, base64Decode,
  hexEncode, hexDecode, htmlEncode, htmlDecode,
  inspectJwt, computeHash, detectFormat,
} from './core/crypto-utils.js';

import {
  computeDiff, diffWords, formatHexDumpLines,
} from './core/diff-engine.js';

// ============================================================
// State
// ============================================================

const state = {
  all: [],
  filtered: [],
  selectedId: null,
  activeView: 'proxy',
  activeProxySub: 'history',
  activeDetailTab: 'req-headers',
  filters: {
    search: '',
    method: '',
    status: '',
    mime: '',
    host: '',
    scopeOnly: false,
  },
  scopeRules: [], // array of strings (patterns/regex)
  hosts: new Set(),
  attached: false,
  attachedTabId: null,
  interceptEnabled: false,
  pausedRequests: [],
  currentPausedId: null,
  repeaterTabs: [],
  activeRepeaterTabId: null,
  repeaterActiveTab: 'pretty',
  wsFrames: [],
  sort: { col: 'seq', dir: 'asc' },
  comparer: {
    mode: 'words',
    view: 'side-by-side',
    diffResult: null,
    diffIndices: [],
    currentDiffIdx: -1,
    inputsMinimized: false,
  },
};

// ============================================================
// DOM Helpers
// ============================================================

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

// ============================================================
// Initialization
// ============================================================

async function init() {
  setupNavigation();
  setupFilters();
  setupActions();
  setupRepeater();
  setupDecoder();
  setupTargetAndScope();
  setupIntercept();
  setupImportModal();
  setupDividers();
  setupComparer();
  setupKeyboardShortcuts();
  setupSortingHeaders();
  setupContextMenu();

  await loadScopeRules();
  await loadRepeaterTabs();
  await reloadRequests();
  await refreshStatus();

  // Listen to background messages
  chrome.runtime.onMessage.addListener(handleRuntimeMessage);

  setInterval(refreshStatus, 4000);
  console.info('[Sanchit Interceptor] Workbench ready ·', state.all.length, 'requests loaded · © 2026 Sanchit');
}

// ============================================================
// Navigation (Primary & Sub-Tabs)
// ============================================================

function setupNavigation() {
  $$('.nav-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      const view = tab.dataset.view;
      switchView(view);
    });
  });

  $$('.sub-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      const sub = tab.dataset.sub;
      switchProxySub(sub);
    });
  });
}

function switchView(viewName) {
  state.activeView = viewName;
  $$('.nav-tab').forEach(t => t.classList.toggle('active', t.dataset.view === viewName));
  $$('.workbench-view').forEach(v => {
    v.classList.toggle('active', v.id === `view${capitalize(viewName)}`);
  });

  if (viewName === 'target') {
    renderSitemapTree();
  } else if (viewName === 'repeater') {
    if (!state.repeaterTabs.length) createNewRepeaterTab();
    renderRepeaterTabs();
  } else if (viewName === 'comparer') {
    updateComparerItemDropdowns();
  }
}

function switchProxySub(subName) {
  state.activeProxySub = subName;
  $$('.sub-tab').forEach(t => t.classList.toggle('active', t.dataset.sub === subName));
  $('#subProxyHistory').classList.toggle('active', subName === 'history');
  $('#subProxyIntercept').classList.toggle('active', subName === 'intercept');
  $('#subProxyWebsockets').classList.toggle('active', subName === 'websockets');

  if (subName === 'websockets') {
    reloadWebSockets();
  }
}

function capitalize(s) {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : '';
}

// ============================================================
// Requests Loading & Filtering
// ============================================================

async function reloadRequests() {
  state.all = await getAllRequests();
  rebuildHosts();
  applyFilters();
  updateComparerItemDropdowns();
}

function rebuildHosts() {
  const set = new Set();
  for (const r of state.all) {
    if (r.host) set.add(r.host);
  }
  state.hosts = set;
  const select = $('#fHost');
  const curr = select.value;
  const sorted = [...set].sort();
  select.innerHTML = '<option value="">All Hosts</option>' +
    sorted.map(h => `<option value="${esc(h)}"${h === curr ? ' selected' : ''}>${esc(h)}</option>`).join('');
}

function applyFilters() {
  const f = state.filters;
  const q = f.search.trim().toLowerCase();

  state.filtered = state.all.filter(r => {
    if (f.method && r.method !== f.method) return false;
    if (f.status) {
      const sc = statusClass(r.status_code);
      if (sc !== f.status) return false;
    }
    if (f.mime && r.mime_group !== f.mime) return false;
    if (f.host && r.host !== f.host) return false;

    // Scope check
    if (f.scopeOnly && !isItemInScope(r.url, r.host)) {
      return false;
    }

    // Deep Search: searches url, host, headers, AND REQUEST/RESPONSE BODIES!
    if (q) {
      const hay = [
        r.url,
        r.host,
        r.path,
        r.method,
        r.mime_group,
        String(r.status_code || ''),
        r.notes || '',
        ...Object.keys(r.request.headers || {}),
        ...Object.values(r.request.headers || {}),
        ...Object.keys(r.response.headers || {}),
        ...Object.values(r.response.headers || {}),
        r.request.body || '',
        r.response.body || '',
      ].join('\n').toLowerCase();
      if (!hay.includes(q)) return false;
    }

    return true;
  });

  // Apply column sorting
  const sortCol = state.sort.col;
  const mult = state.sort.dir === 'asc' ? 1 : -1;
  state.filtered.sort((a, b) => {
    let valA, valB;
    switch (sortCol) {
      case 'seq': valA = a.seq || 0; valB = b.seq || 0; break;
      case 'time': valA = new Date(a.initiated_at).getTime() || 0; valB = new Date(b.initiated_at).getTime() || 0; break;
      case 'method': valA = a.method || ''; valB = b.method || ''; break;
      case 'status': valA = a.status_code || 0; valB = b.status_code || 0; break;
      case 'host': valA = a.host || ''; valB = b.host || ''; break;
      case 'path': valA = a.path || ''; valB = b.path || ''; break;
      case 'mime': valA = a.mime_group || ''; valB = b.mime_group || ''; break;
      case 'size': valA = a.response?.body_size || 0; valB = b.response?.body_size || 0; break;
      case 'dur': valA = a.duration_ms || 0; valB = b.duration_ms || 0; break;
      case 'notes': valA = a.notes || ''; valB = b.notes || ''; break;
      default: valA = a.seq || 0; valB = b.seq || 0;
    }
    if (typeof valA === 'string') return valA.localeCompare(valB) * mult;
    return (valA - valB) * mult;
  });

  renderTable();
  updateCounts();
}

function updateCounts() {
  $('#countTotal').textContent = String(state.all.length);
  $('#countShown').textContent = String(state.filtered.length);
}

// ============================================================
// Table Rendering & Selection
// ============================================================

function renderTable() {
  const tableBody = $('#tableBody');
  if (!state.filtered.length) {
    tableBody.innerHTML = `<div class="empty-msg" style="padding:40px; text-align:center; color:var(--text-3);">
      ${state.all.length ? 'No requests match current filters.' : 'No traffic captured yet.<br>Click "Attach" or "Load File" to begin.'}
    </div>`;
    return;
  }

  const frag = document.createDocumentFragment();
  for (const r of state.filtered) {
    const row = document.createElement('div');
    row.className = 'table-row' + (r.id === state.selectedId ? ' selected' : '');
    row.dataset.id = r.id;
    if (r.highlight) row.dataset.highlight = r.highlight;

    const sc = statusClass(r.status_code);
    row.innerHTML =
      `<div class="col col-seq">${r.seq}</div>` +
      `<div class="col col-time">${fmtTime(r.initiated_at)}</div>` +
      `<div class="col col-method" data-m="${esc(r.method)}">${esc(r.method)}</div>` +
      `<div class="col col-status" data-s="${sc}">${r.status_code || '—'}</div>` +
      `<div class="col col-host">${esc(r.host)}</div>` +
      `<div class="col col-path" title="${esc(r.url)}">${esc(shortPath(r.path))}</div>` +
      `<div class="col col-mime">${esc(r.mime_group)}</div>` +
      `<div class="col col-size">${fmtBytes(r.response?.body_size)}</div>` +
      `<div class="col col-dur">${fmtDuration(r.duration_ms)}</div>` +
      `<div class="col col-notes">${esc(r.notes || '')}</div>`;

    row.addEventListener('click', () => selectRow(r.id));
    row.addEventListener('dblclick', () => sendSelectedToRepeater());
    row.addEventListener('contextmenu', (e) => onRowContextMenu(e, r));
    frag.appendChild(row);
  }

  tableBody.innerHTML = '';
  tableBody.appendChild(frag);

  if ($('#fAutoScroll').checked && state.filtered.length && !state.selectedId) {
    tableBody.scrollTop = tableBody.scrollHeight;
  }
}

async function selectRow(id) {
  state.selectedId = id;
  $$('.table-row').forEach(el => el.classList.toggle('selected', el.dataset.id === id));
  const record = await getRequest(id);
  if (!record) return;
  renderDetail(record);
}

// ============================================================
// Detail Inspector Rendering
// ============================================================

function renderDetail(r) {
  $('#detailEmpty').classList.add('hidden');
  $('#detailContent').classList.remove('hidden');

  const methodEl = $('#detailMethod');
  methodEl.textContent = r.method;
  methodEl.dataset.m = r.method;
  $('#detailUrl').textContent = r.url;

  const sc = r.status_code ? `status-${statusClass(r.status_code)}` : '';
  $('#detailMeta').innerHTML = [
    `<span class="m-pill m-status ${sc}"><span class="m-dot"></span>${r.status_code || '—'} ${esc(r.status_text || '')}</span>`,
    `<span class="m-pill m-dur" title="Duration">⚡ ${fmtDuration(r.duration_ms) || '—'}</span>`,
    `<span class="m-pill m-size" title="Response Size">📦 ${fmtBytes(r.response?.body_size) || '0 B'}</span>`,
    `<span class="m-pill m-mime" title="MIME Group">${esc(r.mime_group || 'other')}</span>`,
    `<span class="m-pill m-proto" title="Protocol">${esc(r.scheme?.toUpperCase() || 'HTTP')}</span>`,
    `<span class="m-pill m-time" title="Initiated Time">🕒 ${fmtTime(r.initiated_at)}</span>`,
  ].join('');

  renderInspectorTab(r);
}

function renderInspectorTab(r) {
  const tab = state.activeDetailTab;
  const detailBody = $('#detailBody');
  detailBody.innerHTML = '';

  switch (tab) {
    case 'req-headers':
      detailBody.appendChild(renderKvSection('Request Headers', r.request.headers));
      break;
    case 'req-body':
      renderBodyView(detailBody, r.request.body, r.request.body_mime, 'Request Body');
      break;
    case 'raw-req':
      renderRawRequestView(detailBody, r);
      break;
    case 'res-headers':
      detailBody.appendChild(renderKvSection('Response Headers', r.response.headers));
      break;
    case 'res-body':
      renderBodyView(detailBody, r.response.body, r.response.body_mime, 'Response Body', r.response.body_encoding);
      break;
    case 'raw-res':
      renderRawResponseView(detailBody, r);
      break;
    case 'cookies':
      renderCookiesView(detailBody, r);
      break;
    case 'timing':
      renderTimingView(detailBody, r);
      break;
    case 'raw':
      renderRawView(detailBody, r);
      break;
    case 'hex':
      renderHexView(detailBody, r.response.body || r.request.body || '');
      break;
    case 'render':
      renderHtmlPreview(detailBody, r.response.body);
      break;
    default:
      detailBody.appendChild(renderKvSection('Request Headers', r.request.headers));
  }
}

function renderKvSection(title, obj) {
  const wrap = document.createElement('div');
  const t = document.createElement('div');
  t.className = 'section-title';
  t.textContent = title;
  wrap.appendChild(t);

  const keys = Object.keys(obj || {});
  if (!keys.length) {
    const empty = document.createElement('div');
    empty.className = 'empty-msg';
    empty.textContent = 'No headers.';
    wrap.appendChild(empty);
    return wrap;
  }

  const table = document.createElement('table');
  table.className = 'kv-table';
  for (const k of keys) {
    const v = obj[k];
    const tr = document.createElement('tr');
    tr.innerHTML = `<td class="k">${esc(k)}</td><td class="v">${esc(Array.isArray(v) ? v.join('\n') : v)}</td>`;
    table.appendChild(tr);
  }
  wrap.appendChild(table);
  return wrap;
}

function renderBodyView(container, body, mime, label, encoding = 'text') {
  if (!body) {
    container.innerHTML = `<div class="empty-msg">No ${esc(label.toLowerCase())} data.</div>`;
    return;
  }

  const header = document.createElement('div');
  header.style.marginBottom = '8px';
  header.innerHTML = `<span class="badge" style="background:var(--surface-3); padding:2px 8px; border-radius:4px; font-size:11px;">${fmtBytes(body.length)}</span> ${mime ? `<span class="badge" style="background:var(--surface-3); padding:2px 8px; border-radius:4px; font-size:11px; margin-left:4px;">${esc(mime)}</span>` : ''}`;
  container.appendChild(header);

  const pre = document.createElement('pre');
  pre.className = 'body-block';

  // Pretty JSON format
  if ((mime && mime.includes('json')) || /^\s*[\{\[]/.test(body)) {
    try {
      const parsed = JSON.parse(body);
      pre.textContent = JSON.stringify(parsed, null, 2);
      container.appendChild(pre);
      return;
    } catch (_) {}
  }

  pre.textContent = body;
  container.appendChild(pre);
}

function renderCookiesView(container, r) {
  const reqCookies = r.request.cookies || [];
  const resCookies = r.response.cookies || [];

  const wrap = document.createElement('div');
  wrap.innerHTML = `<div class="section-title">Request Cookies (${reqCookies.length})</div>`;
  if (!reqCookies.length) {
    wrap.innerHTML += '<div class="empty-msg">No request cookies.</div>';
  } else {
    const table = document.createElement('table');
    table.className = 'kv-table';
    for (const c of reqCookies) {
      table.innerHTML += `<tr><td class="k">${esc(c.name)}</td><td class="v">${esc(c.value)}</td></tr>`;
    }
    wrap.appendChild(table);
  }

  wrap.innerHTML += `<div class="section-title" style="margin-top:16px;">Response Set-Cookie (${resCookies.length})</div>`;
  if (!resCookies.length) {
    wrap.innerHTML += '<div class="empty-msg">No Set-Cookie headers.</div>';
  } else {
    const table = document.createElement('table');
    table.className = 'kv-table';
    for (const c of resCookies) {
      table.innerHTML += `<tr><td class="k">${esc(c.name)}</td><td class="v">${esc(c.value)}</td></tr>`;
    }
    wrap.appendChild(table);
  }

  container.appendChild(wrap);
}

function renderTimingView(container, r) {
  const t = r.timing || {};
  const rows = [
    ['Blocked', t.blocked || 0],
    ['DNS', t.dns || 0],
    ['Connect', t.connect || 0],
    ['SSL', t.ssl || 0],
    ['Send', t.send || 0],
    ['Wait', t.wait || 0],
    ['Receive', t.receive || 0],
    ['Total Duration', r.duration_ms || 0],
  ];

  const wrap = document.createElement('div');
  wrap.innerHTML = '<div class="section-title">Timing Breakdown</div>';
  const table = document.createElement('table');
  table.className = 'kv-table';
  for (const [k, v] of rows) {
    table.innerHTML += `<tr><td class="k">${esc(k)}</td><td class="v">${fmtDuration(v)}</td></tr>`;
  }
  wrap.appendChild(table);
  container.appendChild(wrap);
}

function renderRawRequestView(container, r) {
  const rawReq = formatRawHttpRequest({
    method: r.method,
    path: r.path,
    query: r.query,
    headers: r.request.headers,
    body: r.request.body,
    host: r.host,
  });

  const lines = rawReq ? rawReq.split('\n').length : 0;
  const bytes = new TextEncoder().encode(rawReq || '').length;

  const wrap = document.createElement('div');
  wrap.className = 'raw-view-container';

  const head = document.createElement('div');
  head.className = 'raw-view-head';
  head.innerHTML = `
    <div class="raw-view-title">
      <span class="raw-method-badge" data-m="${esc(r.method)}">${esc(r.method)}</span>
      <span class="raw-title-text">Raw HTTP Request</span>
      <span class="raw-stat-pill">${lines} lines</span>
      <span class="raw-stat-pill">${fmtBytes(bytes)}</span>
    </div>
    <div class="raw-view-actions">
      <button class="btn btn-secondary btn-xs btn-copy-raw" title="Copy raw HTTP request to clipboard">
        Copy Request
      </button>
    </div>
  `;

  const copyBtn = head.querySelector('.btn-copy-raw');
  copyBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(rawReq).then(() => {
      copyBtn.textContent = 'Copied!';
      setTimeout(() => { copyBtn.textContent = 'Copy Request'; }, 1500);
    });
  });

  const pre = document.createElement('pre');
  pre.className = 'body-block raw-http-pre';
  pre.textContent = rawReq;

  wrap.appendChild(head);
  wrap.appendChild(pre);
  container.appendChild(wrap);
}

function renderRawResponseView(container, r) {
  const rawRes = formatRawHttpResponse({
    status: r.status_code,
    statusText: r.status_text,
    headers: r.response.headers,
    body: r.response.body,
  });

  const lines = rawRes ? rawRes.split('\n').length : 0;
  const bytes = new TextEncoder().encode(rawRes || '').length;
  const sc = r.status_code ? `status-${statusClass(r.status_code)}` : '';

  const wrap = document.createElement('div');
  wrap.className = 'raw-view-container';

  const head = document.createElement('div');
  head.className = 'raw-view-head';
  head.innerHTML = `
    <div class="raw-view-title">
      <span class="m-pill m-status ${sc}"><span class="m-dot"></span>${r.status_code || '—'} ${esc(r.status_text || '')}</span>
      <span class="raw-title-text">Raw HTTP Response</span>
      <span class="raw-stat-pill">${lines} lines</span>
      <span class="raw-stat-pill">${fmtBytes(bytes)}</span>
    </div>
    <div class="raw-view-actions">
      <button class="btn btn-secondary btn-xs btn-copy-raw" title="Copy raw HTTP response to clipboard">
        Copy Response
      </button>
    </div>
  `;

  const copyBtn = head.querySelector('.btn-copy-raw');
  copyBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(rawRes).then(() => {
      copyBtn.textContent = 'Copied!';
      setTimeout(() => { copyBtn.textContent = 'Copy Response'; }, 1500);
    });
  });

  const pre = document.createElement('pre');
  pre.className = 'body-block raw-http-pre';
  pre.textContent = rawRes;

  wrap.appendChild(head);
  wrap.appendChild(pre);
  container.appendChild(wrap);
}

function renderRawView(container, r) {
  renderRawRequestView(container, r);
  const sep = document.createElement('div');
  sep.style.height = '14px';
  container.appendChild(sep);
  renderRawResponseView(container, r);
}

function renderHexView(container, str) {
  const wrap = document.createElement('div');
  wrap.innerHTML = '<div class="section-title">Hex Dump View</div>';
  const pre = document.createElement('pre');
  pre.className = 'body-block';
  pre.style.fontFamily = 'var(--font-mono)';
  pre.style.fontSize = '11px';

  const bytes = new TextEncoder().encode(str);
  const lines = [];
  const chunk = 16;

  for (let i = 0; i < bytes.length && i < 16384; i += chunk) {
    const slice = bytes.subarray(i, i + chunk);
    const offset = i.toString(16).padStart(8, '0');
    const hexParts = [];
    let asciiPart = '';

    for (let j = 0; j < chunk; j++) {
      if (j < slice.length) {
        const b = slice[j];
        hexParts.push(b.toString(16).padStart(2, '0'));
        asciiPart += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
      } else {
        hexParts.push('  ');
      }
    }

    const hexFormatted = hexParts.slice(0, 8).join(' ') + '  ' + hexParts.slice(8).join(' ');
    lines.push(`${offset}  ${hexFormatted}  |${asciiPart}|`);
  }

  if (bytes.length > 16384) {
    lines.push(`... [Truncated: Showing first 16 KB of ${fmtBytes(bytes.length)}]`);
  }

  pre.textContent = lines.join('\n');
  wrap.appendChild(pre);
  container.appendChild(wrap);
}

function renderHtmlPreview(container, html) {
  if (!html) {
    container.innerHTML = '<div class="empty-msg">No HTML body to render.</div>';
    return;
  }
  const iframe = document.createElement('iframe');
  iframe.style.width = '100%';
  iframe.style.height = '420px';
  iframe.style.border = '1px solid var(--border)';
  iframe.style.borderRadius = '6px';
  iframe.style.background = '#fff';
  iframe.sandbox = 'allow-same-origin';
  iframe.srcdoc = html;
  container.appendChild(iframe);
}

// ============================================================
// Actions & Export / Import Handlers
// ============================================================

function setupActions() {
  // Detail Inspector Tab switching
  $$('.detail-tabs .tab').forEach(t => {
    t.addEventListener('click', () => {
      $$('.detail-tabs .tab').forEach(x => x.classList.toggle('active', x === t));
      state.activeDetailTab = t.dataset.tab;
      if (state.selectedId) {
        getRequest(state.selectedId).then(r => { if (r) renderInspectorTab(r); });
      }
    });
  });

  // Attach / Detach buttons
  $('#attachBtn').addEventListener('click', async () => {
    const res = await chrome.runtime.sendMessage({ type: 'attach' });
    if (!res || !res.ok) alert('Attach failed: ' + (res?.error || 'unknown'));
    refreshStatus();
  });

  $('#detachBtn').addEventListener('click', async () => {
    await chrome.runtime.sendMessage({ type: 'detach' });
    refreshStatus();
  });

  // Clear button
  $('#clearBtn').addEventListener('click', async () => {
    if (!confirm('Clear all HTTP history and captured records?')) return;
    await chrome.runtime.sendMessage({ type: 'clear' });
    state.all = [];
    state.filtered = [];
    state.selectedId = null;
    $('#detailEmpty').classList.remove('hidden');
    $('#detailContent').classList.add('hidden');
    renderTable();
    updateCounts();
  });

  // Quick Action Buttons
  $('#actionSendRepeater').addEventListener('click', sendSelectedToRepeater);
  $('#actionSendComparer').addEventListener('click', sendSelectedToComparer);
  $('#actionCopyUrl').addEventListener('click', copySelectedUrl);
  $('#actionCopyCurl').addEventListener('click', copySelectedCurl);
  $('#actionAddNote').addEventListener('click', addNoteToSelected);

  // Export Dropdown menu toggle
  $('#exportMenuBtn').addEventListener('click', (e) => {
    e.stopPropagation();
    $('#exportMenu').classList.toggle('hidden');
  });
  document.addEventListener('click', () => $('#exportMenu').classList.add('hidden'));

  // Export options
  $('#saveSanchitBtn').addEventListener('click', exportSanchitFile);
  $('#exportSanchitItem').addEventListener('click', exportSanchitFile);
  $('#exportBurpXmlItem').addEventListener('click', exportBurpXmlFile);
  $('#exportHarItem').addEventListener('click', exportHarFile);
  $('#exportJsonItem').addEventListener('click', exportJsonFile);

  // Load File button
  $('#loadFileBtn').addEventListener('click', () => {
    $('#importModal').classList.remove('hidden');
  });
}

// ============================================================
// .sanchit & .burp Export Engines
// ============================================================

async function exportSanchitFile() {
  const all = await getAllRequests();
  const repeaterTabs = await getAllRepeaterTabs();
  const scope = state.scopeRules;

  const project = createSanchitProject({
    projectName: `BurpLite Project - ${new Date().toLocaleDateString()}`,
    requests: all,
    repeaterTabs: repeaterTabs,
    scopeRules: { include: scope, exclude: [] },
  });

  downloadSanchitFile(project);
}

async function exportBurpXmlFile() {
  const all = await getAllRequests();
  const xml = exportBurpXml(all);
  const blob = new Blob([xml], { type: 'application/xml' });
  const filename = `burp-items-${Date.now()}.burp`;
  downloadBlob(blob, filename);
}

async function exportHarFile() {
  const all = await getAllRequests();
  const harObj = exportHar(all);
  const blob = new Blob([JSON.stringify(harObj, null, 2)], { type: 'application/json' });
  downloadBlob(blob, `capture-${Date.now()}.har`);
}

async function exportJsonFile() {
  const all = await getAllRequests();
  const blob = new Blob([JSON.stringify(all, null, 2)], { type: 'application/json' });
  downloadBlob(blob, `burplite-raw-${Date.now()}.json`);
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

// ============================================================
// Universal File Importer (.sanchit, .burp, .har, .json)
// ============================================================

function setupImportModal() {
  const modal = $('#importModal');
  const dropzone = $('#fileDropzone');
  const fileInput = $('#fileInput');

  $('#modalCloseBtn').addEventListener('click', () => modal.classList.add('hidden'));
  $('#chooseFileBtn').addEventListener('click', () => fileInput.click());

  fileInput.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (file) handleImportFile(file);
  });

  // Drag and drop events
  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('dragover');
  });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    if (file) handleImportFile(file);
  });

  // Global window drag and drop
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', (e) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (file && (file.name.endsWith('.sanchit') || file.name.endsWith('.burp') || file.name.endsWith('.xml') || file.name.endsWith('.har') || file.name.endsWith('.json'))) {
      modal.classList.remove('hidden');
      handleImportFile(file);
    }
  });
}

async function handleImportFile(file) {
  const progress = $('#importProgress');
  const progressFill = $('#importProgressFill');
  const statusText = $('#importStatusText');
  progress.classList.remove('hidden');
  progressFill.style.width = '30%';
  statusText.textContent = `Reading ${file.name}...`;

  try {
    const text = await file.text();
    progressFill.style.width = '60%';
    statusText.textContent = 'Parsing file structure...';

    const isReplace = $('input[name="importMode"]:checked').value === 'replace';
    let importedRequests = [];
    let importedSource = '';

    // Auto-detect file format
    if (file.name.endsWith('.sanchit') || text.includes('SANCHIT_BURP_PROJECT_V1')) {
      const parsed = parseSanchitProject(text);
      importedRequests = parsed.requests;
      importedSource = `.sanchit Project (${parsed.projectName})`;
      if (parsed.repeaterTabs && parsed.repeaterTabs.length) {
        for (const t of parsed.repeaterTabs) await saveRepeaterTab(t);
        await loadRepeaterTabs();
      }
    } else if (file.name.endsWith('.burp') || file.name.endsWith('.xml') || text.includes('<items') || text.includes('<item>')) {
      const parsed = parseBurpXml(text);
      importedRequests = parsed.requests;
      importedSource = 'Burp Suite XML (.burp)';
    } else if (file.name.endsWith('.har') || text.includes('"log"') && text.includes('"entries"')) {
      const parsed = parseHar(text);
      importedRequests = parsed.requests;
      importedSource = 'HAR 1.2 File';
    } else {
      // JSON fallback
      try {
        const json = JSON.parse(text);
        if (Array.isArray(json)) {
          importedRequests = json;
          importedSource = 'Raw JSON Requests';
        } else if (json.entries && Array.isArray(json.entries)) {
          importedRequests = json.entries;
          importedSource = 'BurpLite Session JSON';
        }
      } catch (_) {
        throw new Error('Unsupported or corrupted file format');
      }
    }

    if (!importedRequests.length) {
      throw new Error('No HTTP requests found in the selected file');
    }

    progressFill.style.width = '85%';
    statusText.textContent = `Saving ${importedRequests.length} requests into database...`;

    if (isReplace) {
      await clearAllRequests();
    }

    await bulkPutRequests(importedRequests);

    progressFill.style.width = '100%';
    statusText.textContent = `Successfully loaded ${importedRequests.length} requests from ${importedSource}!`;

    setTimeout(async () => {
      $('#importModal').classList.add('hidden');
      progress.classList.add('hidden');
      progressFill.style.width = '0%';
      await reloadRequests();
      switchView('proxy');
      switchProxySub('history');
      alert(`Loaded ${importedRequests.length} requests from ${importedSource}`);
    }, 600);

  } catch (err) {
    statusText.textContent = 'Import failed: ' + err.message;
    progressFill.style.width = '100%';
    progressFill.style.background = 'var(--danger)';
    console.error('[BurpLite] Import error', err);
  }
}

// ============================================================
// Repeater Engine
// ============================================================

function setupRepeater() {
  $('#repeaterNewTabBtn').addEventListener('click', createNewRepeaterTab);
  $('#repeaterSendBtn').addEventListener('click', sendRepeaterRequest);

  $$('.repeater-res-tabs .tab').forEach(t => {
    t.addEventListener('click', () => {
      $$('.repeater-res-tabs .tab').forEach(x => x.classList.toggle('active', x === t));
      state.repeaterActiveTab = t.dataset.rtab;
      renderCurrentRepeaterResponse();
    });
  });
}

async function loadRepeaterTabs() {
  const tabs = await getAllRepeaterTabs();
  state.repeaterTabs = tabs;
  $('#repeaterBadge').textContent = String(tabs.length);
  if (tabs.length && !state.activeRepeaterTabId) {
    state.activeRepeaterTabId = tabs[0].id;
  }
}

function createNewRepeaterTab(initialData = null) {
  const id = `rep_${Date.now()}`;
  const count = state.repeaterTabs.length + 1;
  const tab = {
    id,
    name: initialData?.name || `Tab ${count}`,
    url: initialData?.url || 'https://httpbin.org/get',
    requestText: initialData?.requestText || 'GET /get HTTP/1.1\r\nHost: httpbin.org\r\nUser-Agent: BurpLite/2.0\r\nAccept: */*\r\n\r\n',
    responseData: null,
  };

  state.repeaterTabs.push(tab);
  state.activeRepeaterTabId = id;
  saveRepeaterTab(tab);
  $('#repeaterBadge').textContent = String(state.repeaterTabs.length);
  renderRepeaterTabs();
}

function renderRepeaterTabs() {
  const list = $('#repeaterTabsList');
  list.innerHTML = '';

  for (const t of state.repeaterTabs) {
    const tabEl = document.createElement('div');
    tabEl.className = 'r-tab' + (t.id === state.activeRepeaterTabId ? ' active' : '');
    tabEl.innerHTML = `<span>${esc(t.name)}</span><span class="r-tab-close">×</span>`;
    
    tabEl.addEventListener('click', (e) => {
      if (e.target.classList.contains('r-tab-close')) {
        closeRepeaterTab(t.id);
      } else {
        selectRepeaterTab(t.id);
      }
    });

    list.appendChild(tabEl);
  }

  loadActiveRepeaterTabIntoEditor();
}

function selectRepeaterTab(id) {
  state.activeRepeaterTabId = id;
  renderRepeaterTabs();
}

async function closeRepeaterTab(id) {
  state.repeaterTabs = state.repeaterTabs.filter(t => t.id !== id);
  await deleteRepeaterTab(id);
  $('#repeaterBadge').textContent = String(state.repeaterTabs.length);
  if (state.activeRepeaterTabId === id) {
    state.activeRepeaterTabId = state.repeaterTabs.length ? state.repeaterTabs[0].id : null;
  }
  if (!state.repeaterTabs.length) {
    createNewRepeaterTab();
  } else {
    renderRepeaterTabs();
  }
}

function loadActiveRepeaterTabIntoEditor() {
  const tab = state.repeaterTabs.find(t => t.id === state.activeRepeaterTabId);
  if (!tab) return;

  $('#repeaterTargetUrl').value = tab.url;
  $('#repeaterReqEditor').value = tab.requestText;
  renderCurrentRepeaterResponse();
}

async function sendRepeaterRequest() {
  const tab = state.repeaterTabs.find(t => t.id === state.activeRepeaterTabId);
  if (!tab) return;

  const targetUrl = $('#repeaterTargetUrl').value.trim();
  const rawText = $('#repeaterReqEditor').value;
  tab.url = targetUrl;
  tab.requestText = rawText;
  await saveRepeaterTab(tab);

  const parsed = parseRawHttpRequest(rawText);
  let effectiveUrl = targetUrl || parsed.fullUrl;
  if (!effectiveUrl) {
    alert('Please specify a valid Target URL');
    return;
  }

  const sendBtn = $('#repeaterSendBtn');
  sendBtn.textContent = 'Sending...';
  sendBtn.disabled = true;

  try {
    const res = await chrome.runtime.sendMessage({
      type: 'repeater-send',
      request: {
        url: effectiveUrl,
        method: parsed.method,
        headers: parsed.headers,
        body: parsed.body,
      }
    });

    tab.responseData = res;
    await saveRepeaterTab(tab);
    renderCurrentRepeaterResponse();
  } catch (err) {
    alert('Failed to execute request: ' + err.message);
  } finally {
    sendBtn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg> Send`;
    sendBtn.disabled = false;
  }
}

function renderCurrentRepeaterResponse() {
  const tab = state.repeaterTabs.find(t => t.id === state.activeRepeaterTabId);
  const statusBadge = $('#repeaterStatusBadge');
  const durBadge = $('#repeaterDurBadge');
  const sizeBadge = $('#repeaterSizeBadge');
  const resBlock = $('#repeaterResBlock');

  if (!tab || !tab.responseData) {
    statusBadge.textContent = '—';
    durBadge.textContent = '— ms';
    sizeBadge.textContent = '— B';
    resBlock.textContent = 'Click "Send" to issue request and inspect response.';
    return;
  }

  const res = tab.responseData;
  statusBadge.textContent = `${res.statusCode || 'ERR'} ${res.statusText || ''}`;
  durBadge.textContent = `${res.durationMs || 0} ms`;
  sizeBadge.textContent = fmtBytes(res.sizeBytes || 0);

  const activeTab = state.repeaterActiveTab;
  if (activeTab === 'pretty') {
    const body = res.body || '';
    try {
      const parsed = JSON.parse(body);
      resBlock.textContent = JSON.stringify(parsed, null, 2);
    } catch (_) {
      resBlock.textContent = body;
    }
  } else if (activeTab === 'raw') {
    resBlock.textContent = formatRawHttpResponse({
      status: res.statusCode,
      statusText: res.statusText,
      headers: res.headers,
      body: res.body,
    });
  } else if (activeTab === 'headers') {
    const lines = Object.entries(res.headers || {}).map(([k, v]) => `${k}: ${v}`);
    resBlock.textContent = lines.join('\n');
  } else if (activeTab === 'render') {
    const wrap = $('#repeaterResWrap');
    wrap.innerHTML = '';
    renderHtmlPreview(wrap, res.body);
  }
}

function sendSelectedToRepeater() {
  if (!state.selectedId) return;
  getRequest(state.selectedId).then(r => {
    if (!r) return;
    const rawReq = formatRawHttpRequest({
      method: r.method,
      path: r.path,
      query: r.query,
      headers: r.request.headers,
      body: r.request.body,
      host: r.host,
    });

    createNewRepeaterTab({
      name: `${r.method} ${shortPath(r.path)}`,
      url: r.url,
      requestText: rawReq,
    });

    switchView('repeater');
  });
}

// ============================================================
// Decoder Engine & JWT Inspector
// ============================================================

function setupDecoder() {
  const input = $('#decoderInput');
  const output = $('#decoderOutput');
  const badgesWrap = $('#detectedFormatsBadges');

  input.addEventListener('input', () => {
    const text = input.value;
    const hints = detectFormat(text);
    badgesWrap.innerHTML = hints.map(h => `<span class="badge" style="background:var(--accent-soft); color:var(--accent-text); padding:2px 7px; border-radius:4px; font-size:10.5px; text-transform:uppercase;">${h}</span>`).join(' ');

    // Check JWT
    const jwt = inspectJwt(text);
    const jwtPanel = $('#decoderJwtPanel');
    if (jwt && jwt.isValidJwt) {
      jwtPanel.classList.remove('hidden');
      $('#jwtHeaderCode').textContent = JSON.stringify(jwt.header, null, 2);
      $('#jwtPayloadCode').textContent = JSON.stringify(jwt.payload, null, 2);
      const expBanner = $('#jwtExpiryBanner');
      if (jwt.claims.expiration) {
        expBanner.className = 'jwt-expiry-banner ' + (jwt.claims.expiration.isExpired ? 'expired' : 'valid');
        expBanner.textContent = jwt.claims.expiration.description + ` (${jwt.claims.expiration.iso})`;
      } else {
        expBanner.className = 'jwt-expiry-banner';
        expBanner.textContent = 'No "exp" claim present in token';
      }
    } else {
      jwtPanel.classList.add('hidden');
    }
  });

  // Action Buttons
  $$('.decoder-transforms-bar button').forEach(btn => {
    btn.addEventListener('click', async () => {
      const action = btn.dataset.action;
      const text = input.value;
      let res = '';

      try {
        switch (action) {
          case 'url-dec': res = urlDecode(text); break;
          case 'url-enc': res = urlEncode(text, true); break;
          case 'b64-dec': res = base64Decode(text); break;
          case 'b64-enc': res = base64Encode(text); break;
          case 'hex-dec': res = hexDecode(text); break;
          case 'hex-enc': res = hexEncode(text); break;
          case 'html-dec': res = htmlDecode(text); break;
          case 'html-enc': res = htmlEncode(text); break;
          case 'hash-md5': res = await computeHash('MD5', text); break;
          case 'hash-sha1': res = await computeHash('SHA-1', text); break;
          case 'hash-sha256': res = await computeHash('SHA-256', text); break;
        }
        output.value = res;
      } catch (err) {
        output.value = 'Error: ' + err.message;
      }
    });
  });

  $('#copyDecoderOutputBtn').addEventListener('click', () => {
    navigator.clipboard.writeText(output.value);
    $('#copyDecoderOutputBtn').textContent = 'Copied!';
    setTimeout(() => $('#copyDecoderOutputBtn').textContent = 'Copy', 1000);
  });
}

// ============================================================
// Target & Scope Engine
// ============================================================

function setupTargetAndScope() {
  $('#addScopeRuleBtn').addEventListener('click', () => {
    const val = $('#newScopeRuleInput').value.trim();
    if (!val) return;
    addScopeRule(val);
    $('#newScopeRuleInput').value = '';
  });

  $('#refreshSitemapBtn').addEventListener('click', renderSitemapTree);
}

async function loadScopeRules() {
  const rules = await getMeta('scopeRules', []);
  state.scopeRules = rules;
  renderScopeRules();
}

async function addScopeRule(rule) {
  if (state.scopeRules.includes(rule)) return;
  state.scopeRules.push(rule);
  await setMeta('scopeRules', state.scopeRules);
  renderScopeRules();
  applyFilters();
}

async function removeScopeRule(rule) {
  state.scopeRules = state.scopeRules.filter(r => r !== rule);
  await setMeta('scopeRules', state.scopeRules);
  renderScopeRules();
  applyFilters();
}

function renderScopeRules() {
  const wrap = $('#scopeRulesList');
  if (!state.scopeRules.length) {
    wrap.innerHTML = '<span style="color:var(--text-3); font-size:11.5px;">No active scope rules. Traffic to all hosts is accepted.</span>';
    return;
  }
  wrap.innerHTML = state.scopeRules.map(r => `
    <span class="scope-pill">
      <span>${esc(r)}</span>
      <span class="scope-remove" data-rule="${esc(r)}">×</span>
    </span>
  `).join('');

  $$('.scope-remove', wrap).forEach(btn => {
    btn.addEventListener('click', () => removeScopeRule(btn.dataset.rule));
  });
}

function isItemInScope(url, host) {
  if (!state.scopeRules.length) return true;
  for (const rule of state.scopeRules) {
    if (rule.startsWith('*.')) {
      const base = rule.slice(2);
      if (host === base || host.endsWith('.' + base)) return true;
    } else if (url.includes(rule) || host.includes(rule)) {
      return true;
    }
  }
  return false;
}

function renderSitemapTree() {
  const treeContainer = $('#sitemapTree');
  const hosts = [...state.hosts].sort();
  if (!hosts.length) {
    treeContainer.innerHTML = '<div class="empty-msg">No hosts in site map yet.</div>';
    return;
  }

  treeContainer.innerHTML = hosts.map(h => `
    <div class="tree-node" data-host="${esc(h)}">
      <span>🌐</span> <span>${esc(h)}</span>
    </div>
  `).join('');

  $$('.tree-node', treeContainer).forEach(node => {
    node.addEventListener('click', () => {
      $$('.tree-node').forEach(x => x.classList.remove('selected'));
      node.classList.add('selected');
      showHostOverview(node.dataset.host);
    });
  });
}

function showHostOverview(host) {
  const hostRequests = state.all.filter(r => r.host === host);
  const card = $('#targetHostDetails');
  const inScope = isItemInScope(`https://${host}/`, host);

  card.innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
      <h3 style="margin:0; font-size:14px; color:var(--accent);">${esc(host)}</h3>
      <button class="btn btn-secondary btn-xs" id="toggleScopeHostBtn">
        ${inScope ? 'Remove from Scope' : 'Add to Scope'}
      </button>
    </div>
    <p>Captured Requests: <b>${hostRequests.length}</b></p>
    <div style="max-height:240px; overflow-y:auto;">
      <table class="kv-table">
        ${hostRequests.slice(0, 50).map(r => `
          <tr>
            <td class="k" style="width:70px;">${r.method}</td>
            <td class="v">${esc(r.path)}</td>
          </tr>
        `).join('')}
      </table>
    </div>
  `;

  $('#toggleScopeHostBtn').addEventListener('click', () => {
    if (inScope) removeScopeRule(host);
    else addScopeRule(host);
    showHostOverview(host);
  });
}

// ============================================================
// Intercept Workbench
// ============================================================

function setupIntercept() {
  const toggleBtn = $('#interceptToggleBtn');
  const quickBtn = $('#quickInterceptBtn');

  const toggle = async () => {
    const nextState = !state.interceptEnabled;
    const res = await chrome.runtime.sendMessage({
      type: 'toggle-intercept',
      enabled: nextState
    });
    if (res && res.ok) {
      state.interceptEnabled = res.enabled;
      updateInterceptUI();
    }
  };

  toggleBtn.addEventListener('click', toggle);
  quickBtn.addEventListener('click', toggle);

  $('#interceptForwardBtn').addEventListener('click', forwardCurrentPaused);
  $('#interceptDropBtn').addEventListener('click', dropCurrentPaused);
}

function updateInterceptUI() {
  const on = state.interceptEnabled;
  const quickBtn = $('#quickInterceptBtn');
  const toggleBtn = $('#interceptToggleBtn');

  quickBtn.className = 'intercept-btn ' + (on ? 'on' : 'off');
  $('.intercept-label', quickBtn).textContent = on ? 'Intercept is ON' : 'Intercept is OFF';

  toggleBtn.className = 'btn btn-lg btn-toggle-intercept ' + (on ? 'on' : 'off');
  $('#interceptToggleText').textContent = on ? 'Intercept is ON' : 'Intercept is OFF';
}

function handlePausedRequest(req) {
  state.pausedRequests.push(req);
  $('#interceptPausedBadge').textContent = String(state.pausedRequests.length);
  $('#interceptPausedBadge').classList.remove('hidden');
  $('#interceptQueueInfo').textContent = `${state.pausedRequests.length} paused requests in queue`;

  if (!state.currentPausedId) {
    showPausedRequest(req);
  }
}

function showPausedRequest(req) {
  state.currentPausedId = req.id;
  $('#interceptEmpty').classList.add('hidden');
  $('#interceptActiveEditor').classList.remove('hidden');
  $('#interceptActionButtons').classList.remove('hidden');

  $('#interceptReqSummary').textContent = `${req.method} ${req.url}`;
  
  const raw = `${req.method} ${req.url} HTTP/1.1\r\n` +
    Object.entries(req.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\r\n') +
    '\r\n\r\n' +
    (req.postData || '');

  $('#interceptRawText').value = raw;
}

async function forwardCurrentPaused() {
  if (!state.currentPausedId) return;
  const rawText = $('#interceptRawText').value;
  const parsed = parseRawHttpRequest(rawText);

  await chrome.runtime.sendMessage({
    type: 'intercept-forward',
    requestId: state.currentPausedId,
    modified: true,
    url: parsed.fullUrl,
    method: parsed.method,
    headers: parsed.headers,
    postData: parsed.body,
  });

  finishCurrentPaused();
}

async function dropCurrentPaused() {
  if (!state.currentPausedId) return;
  await chrome.runtime.sendMessage({
    type: 'intercept-drop',
    requestId: state.currentPausedId,
  });
  finishCurrentPaused();
}

function finishCurrentPaused() {
  state.pausedRequests = state.pausedRequests.filter(r => r.id !== state.currentPausedId);
  state.currentPausedId = null;

  $('#interceptQueueInfo').textContent = `${state.pausedRequests.length} paused requests in queue`;
  $('#interceptPausedBadge').textContent = String(state.pausedRequests.length);
  if (!state.pausedRequests.length) {
    $('#interceptPausedBadge').classList.add('hidden');
    $('#interceptEmpty').classList.remove('hidden');
    $('#interceptActiveEditor').classList.add('hidden');
    $('#interceptActionButtons').classList.add('hidden');
  } else {
    showPausedRequest(state.pausedRequests[0]);
  }
}

// ============================================================
// WebSockets Logging
// ============================================================

async function reloadWebSockets() {
  state.wsFrames = await getAllWebSocketFrames();
  renderWebSocketsTable();
}

function renderWebSocketsTable() {
  const body = $('#wsTableBody');
  if (!state.wsFrames.length) {
    body.innerHTML = '<div class="empty-msg">No WebSocket frames captured yet.</div>';
    return;
  }

  body.innerHTML = state.wsFrames.map(f => `
    <div class="table-row">
      <div class="col col-ws-dir" style="color:${f.direction === 'outbound' ? 'var(--accent)' : 'var(--success)'}; font-weight:700;">
        ${f.direction === 'outbound' ? '▲ OUT' : '▼ IN'}
      </div>
      <div class="col col-ws-time">${fmtTime(f.isoTime)}</div>
      <div class="col col-ws-len">${fmtBytes(f.length)}</div>
      <div class="col col-ws-data" title="${esc(f.payloadData)}">${esc(f.payloadData)}</div>
    </div>
  `).join('');
}

$('#clearWsBtn')?.addEventListener('click', async () => {
  await clearAllWebSocketFrames();
  state.wsFrames = [];
  renderWebSocketsTable();
});

// ============================================================
// Comparer Diff Engine & Workbench Controller
// ============================================================

function setupComparer() {
  // Mode selection buttons
  $('#btnCompareWords')?.addEventListener('click', () => runComparer('words'));
  $('#btnCompareLines')?.addEventListener('click', () => runComparer('lines'));
  $('#btnCompareBytes')?.addEventListener('click', () => runComparer('bytes'));

  // View style buttons
  $('#btnViewSideBySide')?.addEventListener('click', () => setComparerView('side-by-side'));
  $('#btnViewUnified')?.addEventListener('click', () => setComparerView('unified'));

  // Diff Options checkboxes
  $('#chkIgnoreWs')?.addEventListener('change', () => {
    if (state.comparer.diffResult) runComparer();
  });
  $('#chkIgnoreCase')?.addEventListener('change', () => {
    if (state.comparer.diffResult) runComparer();
  });

  // Action buttons
  $('#btnSwapSources')?.addEventListener('click', swapComparerSources);
  $('#clearCompareBtn')?.addEventListener('click', clearComparer);
  $('#btnToggleInputs')?.addEventListener('click', toggleComparerInputs);

  // Difference jump navigation
  $('#btnPrevDiff')?.addEventListener('click', prevDiff);
  $('#btnNextDiff')?.addEventListener('click', nextDiff);

  // Dropdown loaders
  $('#selectItemA')?.addEventListener('change', () => loadSelectedItemIntoSlot('A'));
  $('#selectItemB')?.addEventListener('change', () => loadSelectedItemIntoSlot('B'));

  // Slot radios
  $$('input[name="partA"]').forEach(r => r.addEventListener('change', () => loadSelectedItemIntoSlot('A')));
  $$('input[name="partB"]').forEach(r => r.addEventListener('change', () => loadSelectedItemIntoSlot('B')));

  // Textarea input listeners for live metrics
  $('#compareTextA')?.addEventListener('input', () => updateSourceStats('A'));
  $('#compareTextB')?.addEventListener('input', () => updateSourceStats('B'));

  // Repeater integration buttons
  $('#btnRepeaterReqToComparer')?.addEventListener('click', sendRepeaterReqToComparer);
  $('#btnRepeaterResToComparer')?.addEventListener('click', sendRepeaterResToComparer);
}

function updateSourceStats(slot) {
  const el = slot === 'A' ? $('#compareTextA') : $('#compareTextB');
  const statsEl = slot === 'A' ? $('#statsSourceA') : $('#statsSourceB');
  if (!el || !statsEl) return;
  const val = el.value || '';
  const lines = val ? val.split('\n').length : 0;
  const chars = val.length;
  statsEl.textContent = `${lines} ${lines === 1 ? 'line' : 'lines'} (${fmtBytes(chars)})`;
}

function updateComparerItemDropdowns() {
  const selectA = $('#selectItemA');
  const selectB = $('#selectItemB');
  if (!selectA || !selectB) return;

  const currValA = selectA.value;
  const currValB = selectB.value;

  const opts = ['<option value="">-- Load from History --</option>'];
  for (const r of state.all) {
    const sc = r.status_code ? ` [${r.status_code}]` : '';
    opts.push(`<option value="${esc(r.id)}">#${r.seq} ${r.method} ${esc(r.host)}${esc(shortPath(r.path))}${sc}</option>`);
  }
  const html = opts.join('');
  selectA.innerHTML = html;
  selectB.innerHTML = html;

  if (currValA) selectA.value = currValA;
  if (currValB) selectB.value = currValB;
}

async function loadSelectedItemIntoSlot(slot) {
  const select = slot === 'A' ? $('#selectItemA') : $('#selectItemB');
  const reqId = select ? select.value : null;
  if (!reqId) return;

  const record = state.all.find(r => r.id === reqId) || await getRequest(reqId);
  if (!record) return;

  const radioName = slot === 'A' ? 'partA' : 'partB';
  const checkedRadio = document.querySelector(`input[name="${radioName}"]:checked`);
  const part = checkedRadio ? checkedRadio.value : 'full';

  let text = '';
  const rawReq = formatRawHttpRequest({
    method: record.method,
    path: record.path,
    query: record.query,
    headers: record.request.headers,
    body: record.request.body,
    host: record.host,
  });

  const rawRes = formatRawHttpResponse({
    status: record.status_code,
    statusText: record.status_text,
    headers: record.response.headers,
    body: record.response.body,
  });

  if (part === 'full') {
    text = `${rawReq}\n\n======================================== RESPONSE ========================================\n\n${rawRes}`;
  } else if (part === 'req') {
    text = rawReq;
  } else if (part === 'res') {
    text = rawRes;
  } else if (part === 'body') {
    text = record.response?.body || record.request?.body || '';
  }

  const targetTextarea = slot === 'A' ? $('#compareTextA') : $('#compareTextB');
  if (targetTextarea) {
    targetTextarea.value = text;
    updateSourceStats(slot);
  }

  // If both slots now have text, automatically trigger Word Compare
  const txtA = $('#compareTextA')?.value?.trim();
  const txtB = $('#compareTextB')?.value?.trim();
  if (txtA && txtB) {
    runComparer('words');
  }
}

function swapComparerSources() {
  const txtA = $('#compareTextA');
  const txtB = $('#compareTextB');
  const selA = $('#selectItemA');
  const selB = $('#selectItemB');

  const tmpTxt = txtA.value;
  txtA.value = txtB.value;
  txtB.value = tmpTxt;

  const tmpSel = selA.value;
  selA.value = selB.value;
  selB.value = tmpSel;

  const radA = document.querySelector('input[name="partA"]:checked')?.value || 'full';
  const radB = document.querySelector('input[name="partB"]:checked')?.value || 'full';
  const rA = document.querySelector(`input[name="partA"][value="${radB}"]`);
  const rB = document.querySelector(`input[name="partB"][value="${radA}"]`);
  if (rA) rA.checked = true;
  if (rB) rB.checked = true;

  updateSourceStats('A');
  updateSourceStats('B');

  if (state.comparer.diffResult) {
    runComparer();
  }
}

function clearComparer() {
  $('#compareTextA').value = '';
  $('#compareTextB').value = '';
  $('#selectItemA').value = '';
  $('#selectItemB').value = '';
  updateSourceStats('A');
  updateSourceStats('B');
  state.comparer.diffResult = null;
  state.comparer.diffIndices = [];
  state.comparer.currentDiffIdx = -1;
  const viewer = $('#diffViewerWrap');
  if (viewer) viewer.innerHTML = '';
  $('#comparerResult')?.classList.add('hidden');
}

function toggleComparerInputs() {
  const grid = $('#comparerInputsGrid');
  const btn = $('#btnToggleInputs');
  state.comparer.inputsMinimized = !state.comparer.inputsMinimized;
  grid.classList.toggle('minimized', state.comparer.inputsMinimized);
  btn.textContent = state.comparer.inputsMinimized ? 'Show Input Panes' : 'Hide Input Panes';
}

function sendSelectedToComparer(customText = null) {
  let content = customText;
  if (!content && state.selectedId) {
    const record = state.all.find(r => r.id === state.selectedId);
    if (record) {
      content = formatRawHttpRequest({
        method: record.method,
        path: record.path,
        query: record.query,
        headers: record.request.headers,
        body: record.request.body,
        host: record.host,
      });
    }
  }

  if (!content) return;

  const txtA = $('#compareTextA');
  const txtB = $('#compareTextB');

  if (!txtA.value.trim()) {
    txtA.value = content;
    updateSourceStats('A');
  } else if (!txtB.value.trim()) {
    txtB.value = content;
    updateSourceStats('B');
    runComparer('words');
  } else {
    // Both full: replace B and re-run comparison
    txtB.value = content;
    updateSourceStats('B');
    runComparer('words');
  }

  switchView('comparer');
}

function sendRepeaterReqToComparer() {
  const reqText = $('#repeaterReqEditor')?.value || '';
  if (!reqText.trim()) {
    alert('Repeater request editor is empty.');
    return;
  }
  sendSelectedToComparer(reqText);
}

function sendRepeaterResToComparer() {
  const tab = state.repeaterTabs.find(t => t.id === state.activeRepeaterTabId);
  if (!tab || !tab.responseData) {
    alert('No response data in current Repeater tab. Please send the request first.');
    return;
  }
  const rawRes = formatRawHttpResponse({
    status: tab.responseData.statusCode,
    statusText: tab.responseData.statusText,
    headers: tab.responseData.headers,
    body: tab.responseData.body,
  });
  sendSelectedToComparer(rawRes);
}

function runComparer(mode = null) {
  if (mode) state.comparer.mode = mode;
  const currentMode = state.comparer.mode || 'words';

  // Highlight active button
  $('#btnCompareWords')?.classList.toggle('btn-primary', currentMode === 'words');
  $('#btnCompareWords')?.classList.toggle('btn-secondary', currentMode !== 'words');
  $('#btnCompareLines')?.classList.toggle('btn-primary', currentMode === 'lines');
  $('#btnCompareLines')?.classList.toggle('btn-secondary', currentMode !== 'lines');
  $('#btnCompareBytes')?.classList.toggle('btn-primary', currentMode === 'bytes');
  $('#btnCompareBytes')?.classList.toggle('btn-secondary', currentMode !== 'bytes');

  const textA = $('#compareTextA')?.value || '';
  const textB = $('#compareTextB')?.value || '';

  if (!textA && !textB) {
    alert('Please enter or load items into Source A and Source B to compare.');
    return;
  }

  const ignoreWhitespace = $('#chkIgnoreWs')?.checked || false;
  const ignoreCase = $('#chkIgnoreCase')?.checked || false;

  const result = computeDiff(textA, textB, {
    mode: currentMode,
    ignoreWhitespace,
    ignoreCase,
  });

  state.comparer.diffResult = result;

  // Collect difference indices
  state.comparer.diffIndices = [];
  result.rows.forEach((row, idx) => {
    if (row.type !== 'equal') {
      state.comparer.diffIndices.push(idx);
    }
  });

  state.comparer.currentDiffIdx = state.comparer.diffIndices.length > 0 ? 0 : -1;

  // Update Metrics
  const sim = result.stats.similarity;
  const simBadge = $('#diffSimilarity');
  if (simBadge) {
    simBadge.textContent = `${sim}% Match`;
    simBadge.classList.toggle('low', sim < 60);
  }

  const modEl = $('#diffModCount');
  if (modEl) modEl.textContent = `${result.stats.modifications} modified`;
  const addEl = $('#diffAddCount');
  if (addEl) addEl.textContent = `+${result.stats.additions} added`;
  const delEl = $('#diffDelCount');
  if (delEl) delEl.textContent = `-${result.stats.deletions} deleted`;

  updateDiffCursorDisplay();

  // Show result wrap
  $('#comparerResult')?.classList.remove('hidden');

  renderDiffView();

  if (state.comparer.diffIndices.length > 0) {
    jumpToDiff(0);
  }
}

function setComparerView(view) {
  state.comparer.view = view;
  $('#btnViewSideBySide')?.classList.toggle('active', view === 'side-by-side');
  $('#btnViewUnified')?.classList.toggle('active', view === 'unified');
  if (state.comparer.diffResult) {
    renderDiffView();
    if (state.comparer.currentDiffIdx >= 0) {
      jumpToDiff(state.comparer.currentDiffIdx);
    }
  }
}

function renderDiffView() {
  const viewer = $('#diffViewerWrap');
  if (!viewer || !state.comparer.diffResult) return;

  viewer.innerHTML = '';
  const { rows } = state.comparer.diffResult;

  if (state.comparer.view === 'side-by-side') {
    const sbs = document.createElement('div');
    sbs.className = 'side-by-side-diff';

    // Left pane (Source A)
    const leftPane = document.createElement('div');
    leftPane.className = 'diff-pane';
    leftPane.id = 'diffPaneLeft';
    leftPane.innerHTML = '<div class="diff-pane-head">Source A</div>';

    // Right pane (Source B)
    const rightPane = document.createElement('div');
    rightPane.className = 'diff-pane';
    rightPane.id = 'diffPaneRight';
    rightPane.innerHTML = '<div class="diff-pane-head">Source B</div>';

    rows.forEach((r, idx) => {
      // Left row
      const rowLeft = document.createElement('div');
      rowLeft.className = `diff-row ${r.type === 'insert' ? 'gap' : r.type}`;
      rowLeft.dataset.rowIdx = idx;

      const numLeft = document.createElement('div');
      numLeft.className = 'diff-num';
      numLeft.textContent = r.leftNum != null ? String(r.leftNum) : '';

      const contentLeft = document.createElement('div');
      contentLeft.className = 'diff-content';

      if (r.type === 'modify' && r.wordDiffA && state.comparer.mode !== 'lines') {
        contentLeft.innerHTML = r.wordDiffA.map(w =>
          w.type === 'delete' ? `<span class="word-del">${esc(w.text)}</span>` : esc(w.text)
        ).join('');
      } else if (r.leftText) {
        contentLeft.textContent = r.leftText;
      } else {
        contentLeft.innerHTML = '&nbsp;';
      }

      rowLeft.appendChild(numLeft);
      rowLeft.appendChild(contentLeft);
      leftPane.appendChild(rowLeft);

      // Right row
      const rowRight = document.createElement('div');
      rowRight.className = `diff-row ${r.type === 'delete' ? 'gap' : r.type}`;
      rowRight.dataset.rowIdx = idx;

      const numRight = document.createElement('div');
      numRight.className = 'diff-num';
      numRight.textContent = r.rightNum != null ? String(r.rightNum) : '';

      const contentRight = document.createElement('div');
      contentRight.className = 'diff-content';

      if (r.type === 'modify' && r.wordDiffB && state.comparer.mode !== 'lines') {
        contentRight.innerHTML = r.wordDiffB.map(w =>
          w.type === 'insert' ? `<span class="word-add">${esc(w.text)}</span>` : esc(w.text)
        ).join('');
      } else if (r.rightText) {
        contentRight.textContent = r.rightText;
      } else {
        contentRight.innerHTML = '&nbsp;';
      }

      rowRight.appendChild(numRight);
      rowRight.appendChild(contentRight);
      rightPane.appendChild(rowRight);
    });

    // Synchronized scrolling
    let syncing = false;
    leftPane.addEventListener('scroll', () => {
      if (syncing) return;
      syncing = true;
      rightPane.scrollTop = leftPane.scrollTop;
      rightPane.scrollLeft = leftPane.scrollLeft;
      syncing = false;
    });

    rightPane.addEventListener('scroll', () => {
      if (syncing) return;
      syncing = true;
      leftPane.scrollTop = rightPane.scrollTop;
      leftPane.scrollLeft = rightPane.scrollLeft;
      syncing = false;
    });

    sbs.appendChild(leftPane);
    sbs.appendChild(rightPane);
    viewer.appendChild(sbs);

  } else {
    // Unified view
    const uni = document.createElement('div');
    uni.className = 'unified-diff-view';

    rows.forEach((r, idx) => {
      if (r.type === 'equal') {
        const row = document.createElement('div');
        row.className = 'unified-row';
        row.dataset.rowIdx = idx;
        row.innerHTML = `<span class="unified-sign">&nbsp;</span><span class="unified-text">${esc(r.leftText)}</span>`;
        uni.appendChild(row);
      } else if (r.type === 'delete') {
        const row = document.createElement('div');
        row.className = 'unified-row unified-del';
        row.dataset.rowIdx = idx;
        row.innerHTML = `<span class="unified-sign">-</span><span class="unified-text">${esc(r.leftText)}</span>`;
        uni.appendChild(row);
      } else if (r.type === 'insert') {
        const row = document.createElement('div');
        row.className = 'unified-row unified-add';
        row.dataset.rowIdx = idx;
        row.innerHTML = `<span class="unified-sign">+</span><span class="unified-text">${esc(r.rightText)}</span>`;
        uni.appendChild(row);
      } else if (r.type === 'modify') {
        const rowDel = document.createElement('div');
        rowDel.className = 'unified-row unified-del';
        rowDel.dataset.rowIdx = idx;
        const delText = r.wordDiffA && state.comparer.mode !== 'lines'
          ? r.wordDiffA.map(w => w.type === 'delete' ? `<span class="word-del">${esc(w.text)}</span>` : esc(w.text)).join('')
          : esc(r.leftText);
        rowDel.innerHTML = `<span class="unified-sign">-</span><span class="unified-text">${delText}</span>`;
        uni.appendChild(rowDel);

        const rowAdd = document.createElement('div');
        rowAdd.className = 'unified-row unified-add';
        rowAdd.dataset.rowIdx = idx;
        const addText = r.wordDiffB && state.comparer.mode !== 'lines'
          ? r.wordDiffB.map(w => w.type === 'insert' ? `<span class="word-add">${esc(w.text)}</span>` : esc(w.text)).join('')
          : esc(r.rightText);
        rowAdd.innerHTML = `<span class="unified-sign">+</span><span class="unified-text">${addText}</span>`;
        uni.appendChild(rowAdd);
      }
    });

    viewer.appendChild(uni);
  }
}

function jumpToDiff(diffIdx) {
  const diffs = state.comparer.diffIndices;
  if (!diffs.length) return;

  state.comparer.currentDiffIdx = Math.max(0, Math.min(diffs.length - 1, diffIdx));
  updateDiffCursorDisplay();

  const targetRowIdx = diffs[state.comparer.currentDiffIdx];

  $$('.diff-row.diff-active-focus, .unified-row.diff-active-focus').forEach(el => {
    el.classList.remove('diff-active-focus');
  });

  const matchingRows = $$(`[data-row-idx="${targetRowIdx}"]`);
  matchingRows.forEach(el => el.classList.add('diff-active-focus'));

  if (matchingRows[0]) {
    matchingRows[0].scrollIntoView({ block: 'center', behavior: 'smooth' });
  }
}

function nextDiff() {
  const diffs = state.comparer.diffIndices;
  if (!diffs.length) return;
  const next = (state.comparer.currentDiffIdx + 1) % diffs.length;
  jumpToDiff(next);
}

function prevDiff() {
  const diffs = state.comparer.diffIndices;
  if (!diffs.length) return;
  const prev = (state.comparer.currentDiffIdx - 1 + diffs.length) % diffs.length;
  jumpToDiff(prev);
}

function updateDiffCursorDisplay() {
  const diffs = state.comparer.diffIndices;
  const info = $('#diffCursorInfo');
  if (!info) return;
  if (!diffs.length) {
    info.textContent = '0 of 0';
  } else {
    info.textContent = `Diff ${state.comparer.currentDiffIdx + 1} of ${diffs.length}`;
  }
}

// ============================================================
// Dividers & Draggable Splitters
// ============================================================

function setupDividers() {
  setupSplitter('#historyGutter', '#historyListPane', '#historySplitContainer');
  setupSplitter('#repeaterGutter', '.repeater-req-panel', '.repeater-split-workspace');
}

function setupSplitter(gutterSel, leftPaneSel, containerSel) {
  const gutter = $(gutterSel);
  const leftPane = $(leftPaneSel);
  const container = $(containerSel);
  if (!gutter || !leftPane || !container) return;

  let isDragging = false;

  gutter.addEventListener('mousedown', (e) => {
    isDragging = true;
    gutter.classList.add('dragging');
    document.body.style.cursor = 'col-resize';
  });

  window.addEventListener('mousemove', (e) => {
    if (!isDragging) return;
    const rect = container.getBoundingClientRect();
    const newWidth = e.clientX - rect.left;
    if (newWidth > 180 && newWidth < rect.width - 180) {
      leftPane.style.flex = `0 0 ${newWidth}px`;
    }
  });

  window.addEventListener('mouseup', () => {
    if (isDragging) {
      isDragging = false;
      gutter.classList.remove('dragging');
      document.body.style.cursor = 'default';
    }
  });
}

// ============================================================
// Column Sorting Headers
// ============================================================

function setupSortingHeaders() {
  $$('.table-head .col.sortable').forEach(colEl => {
    colEl.addEventListener('click', () => {
      const colName = colEl.dataset.sort;
      if (state.sort.col === colName) {
        state.sort.dir = state.sort.dir === 'asc' ? 'desc' : 'asc';
      } else {
        state.sort.col = colName;
        state.sort.dir = 'asc';
      }
      updateSortHeaderIcons();
      applyFilters();
    });
  });
  updateSortHeaderIcons();
}

function updateSortHeaderIcons() {
  $$('.table-head .col.sortable').forEach(colEl => {
    const iconEl = colEl.querySelector('.sort-icon');
    if (!iconEl) return;
    if (colEl.dataset.sort === state.sort.col) {
      iconEl.textContent = state.sort.dir === 'asc' ? ' ▲' : ' ▼';
    } else {
      iconEl.textContent = '';
    }
  });
}

// ============================================================
// Custom Right-Click Context Menu
// ============================================================

function onRowContextMenu(e, r) {
  e.preventDefault();
  selectRow(r.id);

  const menu = $('#rowContextMenu');
  if (!menu) return;

  const inScope = isItemInScope(r.url, r.host);
  const scopeText = $('#ctxScopeText');
  if (scopeText) {
    scopeText.textContent = inScope ? 'Remove Host from Scope' : 'Add Host to Scope';
  }

  menu.classList.remove('hidden');
  const menuW = 230;
  const menuH = 340;
  let posX = e.clientX;
  let posY = e.clientY;
  if (posX + menuW > window.innerWidth) posX = window.innerWidth - menuW - 10;
  if (posY + menuH > window.innerHeight) posY = window.innerHeight - menuH - 10;
  menu.style.left = posX + 'px';
  menu.style.top = posY + 'px';
}

function setupContextMenu() {
  const menu = $('#rowContextMenu');
  if (!menu) return;

  document.addEventListener('click', () => menu.classList.add('hidden'));

  menu.querySelectorAll('.menu-item').forEach(item => {
    item.addEventListener('click', async (e) => {
      e.stopPropagation();
      menu.classList.add('hidden');
      const action = item.dataset.action;
      const targetId = state.selectedId;
      if (!targetId) return;
      const record = await getRequest(targetId);
      if (!record) return;

      switch (action) {
        case 'repeater':
          sendSelectedToRepeater();
          break;
        case 'decoder':
          sendRecordToDecoder(record);
          break;
        case 'comparer':
          sendSelectedToComparer();
          break;
        case 'toggle-scope':
          if (isItemInScope(record.url, record.host)) {
            removeScopeRule(record.host);
          } else {
            addScopeRule(record.host);
          }
          break;
        case 'copy-url':
          navigator.clipboard.writeText(record.url);
          break;
        case 'copy-curl':
          copySelectedCurl();
          break;
        case 'copy-fetch':
          copySelectedFetch(record);
          break;
        case 'add-note':
          addNoteToSelected();
          break;
        case 'delete':
          if (confirm(`Delete request #${record.seq} (${record.url})?`)) {
            await deleteRequest(record.id);
            state.all = state.all.filter(r => r.id !== record.id);
            if (state.selectedId === record.id) {
              state.selectedId = null;
              $('#detailEmpty').classList.remove('hidden');
              $('#detailContent').classList.add('hidden');
            }
            applyFilters();
          }
          break;
      }
    });
  });

  // Color picker in context menu
  menu.querySelectorAll('.color-dot').forEach(dot => {
    dot.addEventListener('click', async (e) => {
      e.stopPropagation();
      menu.classList.add('hidden');
      const color = dot.dataset.color;
      const targetId = state.selectedId;
      if (!targetId) return;
      const r = await getRequest(targetId);
      if (r) {
        r.highlight = color || null;
        await putRequest(r);
        const idx = state.all.findIndex(x => x.id === r.id);
        if (idx >= 0) state.all[idx] = r;
        const rowEl = document.querySelector(`.table-row[data-id="${r.id}"]`);
        if (rowEl) rowEl.dataset.highlight = color;
      }
    });
  });
}

function copySelectedFetch(r) {
  const method = r.method || 'GET';
  const headers = JSON.stringify(r.request.headers || {}, null, 2);
  let bodyPart = '';
  if (r.request.body && !['GET', 'HEAD'].includes(method)) {
    bodyPart = `,\n  body: ${JSON.stringify(r.request.body)}`;
  }
  const snippet = `fetch(${JSON.stringify(r.url)}, {\n  method: ${JSON.stringify(method)},\n  headers: ${headers}${bodyPart}\n})\n.then(res => res.text())\n.then(data => console.log(data))\n.catch(err => console.error(err));`;
  navigator.clipboard.writeText(snippet);
  alert('Copied as JavaScript fetch() snippet!');
}

function sendRecordToDecoder(r) {
  const selectedText = window.getSelection().toString().trim();
  const textToSend = selectedText || r.request.body || r.url;
  $('#decoderInput').value = textToSend;
  $('#decoderInput').dispatchEvent(new Event('input'));
  switchView('decoder');
}

function navigateHistorySelection(direction) {
  if (!state.filtered.length) return;
  const currIndex = state.filtered.findIndex(r => r.id === state.selectedId);
  let nextIndex = currIndex + direction;
  if (currIndex === -1) nextIndex = direction > 0 ? 0 : state.filtered.length - 1;
  nextIndex = Math.max(0, Math.min(state.filtered.length - 1, nextIndex));
  const nextReq = state.filtered[nextIndex];
  if (nextReq) {
    selectRow(nextReq.id);
    const rowEl = document.querySelector(`.table-row[data-id="${nextReq.id}"]`);
    if (rowEl) rowEl.scrollIntoView({ block: 'nearest' });
  }
}

// ============================================================
// Keyboard Shortcuts
// ============================================================

function setupKeyboardShortcuts() {
  window.addEventListener('keydown', (e) => {
    // Arrow Up / Down navigation in HTTP History
    if (state.activeView === 'proxy' && state.activeProxySub === 'history') {
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        const activeTag = document.activeElement ? document.activeElement.tagName.toLowerCase() : '';
        if (activeTag !== 'input' && activeTag !== 'textarea') {
          e.preventDefault();
          navigateHistorySelection(e.key === 'ArrowDown' ? 1 : -1);
          return;
        }
      }
    }

    // Comparer Keyboard Navigation: F7 or Shift+F7, or ArrowUp/ArrowDown when viewing comparer and not in a textarea
    if (state.activeView === 'comparer') {
      if (e.key === 'F7') {
        e.preventDefault();
        if (e.shiftKey) prevDiff();
        else nextDiff();
        return;
      }
      const activeTag = document.activeElement ? document.activeElement.tagName.toLowerCase() : '';
      if (activeTag !== 'textarea' && activeTag !== 'input' && activeTag !== 'select') {
        if (e.key === 'ArrowDown') {
          e.preventDefault();
          nextDiff();
          return;
        }
        if (e.key === 'ArrowUp') {
          e.preventDefault();
          prevDiff();
          return;
        }
      }
    }

    // Ctrl+R: Send to Repeater
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'r') {
      e.preventDefault();
      sendSelectedToRepeater();
    }
    // Ctrl+S: Save .sanchit project
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
      e.preventDefault();
      exportSanchitFile();
    }
    // Ctrl+O: Open Load file modal
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'o') {
      e.preventDefault();
      $('#importModal').classList.remove('hidden');
    }
    // Ctrl+F: Focus search
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'f') {
      e.preventDefault();
      $('#fSearch').focus();
    }
    // Escape: Close modals & context menu
    if (e.key === 'Escape') {
      $('#importModal').classList.add('hidden');
      $('#exportMenu').classList.add('hidden');
      $('#rowContextMenu')?.classList.add('hidden');
    }
  });
}

// ============================================================
// Runtime Message Listener
// ============================================================

function handleRuntimeMessage(msg) {
  if (!msg || !msg.type) return;

  if (msg.type === 'request-added') {
    state.all.push(msg.record);
    if (msg.record.host && !state.hosts.has(msg.record.host)) {
      rebuildHosts();
    }
    applyFilters();
  } else if (msg.type === 'request-updated') {
    const idx = state.all.findIndex(r => r.id === msg.record.id);
    if (idx >= 0) state.all[idx] = msg.record;
    applyFilters();
    if (state.selectedId === msg.record.id) {
      renderDetail(msg.record);
    }
  } else if (msg.type === 'cleared') {
    state.all = [];
    state.filtered = [];
    state.selectedId = null;
    $('#detailEmpty').classList.remove('hidden');
    $('#detailContent').classList.add('hidden');
    renderTable();
    updateCounts();
  } else if (msg.type === 'attached') {
    refreshStatus();
  } else if (msg.type === 'detached') {
    refreshStatus();
  } else if (msg.type === 'intercept-paused') {
    handlePausedRequest(msg.request);
  } else if (msg.type === 'websocket-frame') {
    state.wsFrames.push(msg.frame);
    $('#wsCountBadge').textContent = String(state.wsFrames.length);
    $('#wsCountBadge').classList.remove('hidden');
    if (state.activeProxySub === 'websockets') {
      renderWebSocketsTable();
    }
  }
}

async function refreshStatus() {
  const res = await chrome.runtime.sendMessage({ type: 'status' }).catch(() => null);
  const pill = $('#statusPill');
  const dot = $('.dot', pill);
  const text = $('#statusText');

  if (res && res.ok) {
    state.attached = res.attached;
    state.attachedTabId = res.tabId;
    state.interceptEnabled = res.interceptEnabled;
    updateInterceptUI();

    if (res.attached) {
      dot.dataset.state = 'on';
      text.textContent = `Attached to tab ${res.tabId}`;
    } else {
      dot.dataset.state = 'off';
      text.textContent = 'Not attached';
    }
  } else {
    dot.dataset.state = 'err';
    text.textContent = 'Worker offline';
  }
}

// ============================================================
// Utilities & Formatters
// ============================================================

function fmtTime(iso) {
  if (!iso) return '';
  try {
    const d = new Date(iso);
    return String(d.getHours()).padStart(2, '0') + ':' +
      String(d.getMinutes()).padStart(2, '0') + ':' +
      String(d.getSeconds()).padStart(2, '0');
  } catch (_) { return ''; }
}

function fmtBytes(n) {
  if (!n && n !== 0) return '';
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / (1024 * 1024)).toFixed(1) + ' MB';
}

function fmtDuration(ms) {
  if (ms == null) return '';
  if (ms < 1000) return ms + ' ms';
  return (ms / 1000).toFixed(2) + ' s';
}

function statusClass(code) {
  if (!code) return '';
  if (code < 300) return '2xx';
  if (code < 400) return '3xx';
  if (code < 500) return '4xx';
  return '5xx';
}

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function shortPath(path) {
  const p = path || '';
  return p.length > 55 ? '…' + p.slice(-53) : p;
}

function copySelectedUrl() {
  if (!state.selectedId) return;
  getRequest(state.selectedId).then(r => {
    if (r) navigator.clipboard.writeText(r.url);
  });
}

function copySelectedCurl() {
  if (!state.selectedId) return;
  getRequest(state.selectedId).then(r => {
    if (!r) return;
    const headers = Object.entries(r.request.headers || {}).map(([k, v]) => `-H "${k}: ${v}"`).join(' ');
    const body = r.request.body ? `--data '${r.request.body.replace(/'/g, "'\\''")}'` : '';
    const curl = `curl -X ${r.method} "${r.url}" ${headers} ${body}`.trim();
    navigator.clipboard.writeText(curl);
    alert('Copied as cURL command!');
  });
}

async function addNoteToSelected() {
  if (!state.selectedId) return;
  const r = await getRequest(state.selectedId);
  if (!r) return;
  const note = prompt('Add note or comment to request:', r.notes || '');
  if (note !== null) {
    r.notes = note;
    await putRequest(r);
    const idx = state.all.findIndex(x => x.id === r.id);
    if (idx >= 0) state.all[idx] = r;
    applyFilters();
  }
}

function setupFilters() {
  const fSearch = $('#fSearch');
  fSearch.addEventListener('input', () => {
    state.filters.search = fSearch.value;
    $('#searchClearBtn').classList.toggle('hidden', !fSearch.value);
    applyFilters();
  });
  $('#searchClearBtn').addEventListener('click', () => {
    fSearch.value = '';
    state.filters.search = '';
    $('#searchClearBtn').classList.add('hidden');
    applyFilters();
  });

  $('#fMethod').addEventListener('change', (e) => {
    state.filters.method = e.target.value;
    applyFilters();
  });
  $('#fStatus').addEventListener('change', (e) => {
    state.filters.status = e.target.value;
    applyFilters();
  });
  $('#fMime').addEventListener('change', (e) => {
    state.filters.mime = e.target.value;
    applyFilters();
  });
  $('#fHost').addEventListener('change', (e) => {
    state.filters.host = e.target.value;
    applyFilters();
  });
  $('#fScopeOnly').addEventListener('change', (e) => {
    state.filters.scopeOnly = e.target.checked;
    applyFilters();
  });

  $('#resetFiltersBtn').addEventListener('click', () => {
    fSearch.value = '';
    $('#fMethod').value = '';
    $('#fStatus').value = '';
    $('#fMime').value = '';
    $('#fHost').value = '';
    $('#fScopeOnly').checked = false;
    state.filters = { search: '', method: '', status: '', mime: '', host: '', scopeOnly: false };
    applyFilters();
  });
}

// Start Workbench
init();