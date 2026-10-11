/**
 * Sanchit Interceptor — Background Service Worker
 * Copyright (c) 2026 Sanchit. All rights reserved.
 *
 * Core CDP Engine:
 * - Network capture with full text and binary body preservation
 * - Real-time Request & Response Interception (Fetch.enable / requestPaused)
 * - WebSocket frame logging
 * - Cross-origin Repeater request execution engine (CORS bypass via <all_urls>)
 * - IndexedDB synchronization and rolling cap enforcement
 */

import {
  putRequest, getRequest, clearAllRequests, countRequests,
  getMaxSeq, setMeta, getMeta, putWebSocketFrame,
} from './db.js';

const CDP_VERSION = '1.3';
const MAX_ENTRIES_DEFAULT = 10000;
const MAX_BODY_BYTES = 5 * 1024 * 1024; // 5 MB
const BODY_FETCH_CONCURRENCY = 6;

// Session state
const state = {
  attachedTabId: null,
  attachedUrl: null,
  sessionStartedAt: null,
  seqCounter: 0,
  maxEntries: MAX_ENTRIES_DEFAULT,
  interceptEnabled: false,
  pausedRequests: new Map(), // fetchId -> pausedInfo
  pendingBodies: new Set(),
  bodyFetchQueue: [],
  bodyFetchesInFlight: 0,
  webSocketConnections: new Map(), // cdpRequestId -> { url, initiator }
};

// Map requestId -> record.id
const requestIdToRecordId = new Map();
// Map record.id -> record
const inFlightRecords = new Map();

// ============================================================
// Utilities
// ============================================================

function uid(prefix) {
  return prefix + '_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 8);
}

function nowISO() {
  return new Date().toISOString();
}

function classifyMimeGroup(mime, resourceType) {
  if (!mime) {
    if (resourceType === 'script') return 'js';
    if (resourceType === 'stylesheet') return 'css';
    if (resourceType === 'image') return 'image';
    if (resourceType === 'font') return 'font';
    if (resourceType === 'media') return 'media';
    if (resourceType === 'document') return 'html';
    if (resourceType === 'xhr' || resourceType === 'fetch') return 'xhr';
    if (resourceType === 'websocket') return 'ws';
    return 'other';
  }
  const m = mime.toLowerCase();
  if (m.includes('mpegurl') || m.includes('m3u')) return 'playlist';
  if (m.includes('json')) return 'json';
  if (m.includes('xml')) return 'xml';
  if (m.includes('html')) return 'html';
  if (m.includes('javascript') || m.includes('ecmascript')) return 'js';
  if (m.includes('css')) return 'css';
  if (m.startsWith('image/')) return 'image';
  if (m.startsWith('video/') || m.startsWith('audio/')) return 'media';
  if (m.startsWith('font/') || m.includes('woff') || m.includes('ttf') || m.includes('otf')) return 'font';
  if (m.startsWith('text/')) return 'text';
  return 'other';
}

function isTextMime(mime) {
  if (!mime) return false;
  const m = mime.toLowerCase();
  return (
    m.startsWith('text/') ||
    m.includes('json') ||
    m.includes('xml') ||
    m.includes('javascript') ||
    m.includes('ecmascript') ||
    m.includes('mpegurl') ||
    m.includes('x-www-form-urlencoded') ||
    m.includes('graphql')
  );
}

function parseCookies(cookieHeader, domain) {
  if (!cookieHeader) return [];
  return cookieHeader.split(';').map(p => {
    const idx = p.indexOf('=');
    if (idx < 0) return null;
    return {
      name: p.slice(0, idx).trim(),
      value: p.slice(idx + 1).trim(),
      domain: domain || null,
    };
  }).filter(Boolean);
}

function parseSetCookies(setCookieValues, domain) {
  if (!setCookieValues || !setCookieValues.length) return [];
  return setCookieValues.map(v => {
    const parts = v.split(';');
    const first = parts[0] || '';
    const idx = first.indexOf('=');
    if (idx < 0) return null;
    const name = first.slice(0, idx).trim();
    const value = first.slice(idx + 1).trim();
    const attrs = {};
    for (let i = 1; i < parts.length; i++) {
      const a = parts[i].trim();
      const ei = a.indexOf('=');
      if (ei < 0) attrs[a.toLowerCase()] = true;
      else attrs[a.slice(0, ei).toLowerCase().trim()] = a.slice(ei + 1).trim();
    }
    return {
      name, value,
      domain: attrs.domain || domain || null,
      path: attrs.path || null,
      expires: attrs.expires || null,
      http_only: !!attrs.httponly,
      secure: !!attrs.secure,
      same_site: attrs.samesite || null,
      set_by: domain || null,
    };
  }).filter(Boolean);
}

function headerListToObject(headers) {
  const out = {};
  if (!headers) return out;
  if (Array.isArray(headers)) {
    for (const h of headers) {
      if (h && h.name) out[h.name] = h.value;
    }
    return out;
  }
  for (const k of Object.keys(headers)) {
    out[k] = headers[k];
  }
  return out;
}

function queryToObject(search) {
  const out = {};
  if (!search) return out;
  const params = new URLSearchParams(search.startsWith('?') ? search.slice(1) : search);
  for (const [k, v] of params) out[k] = v;
  return out;
}

// ============================================================
// Cap enforcement
// ============================================================

async function enforceCap() {
  const count = await countRequests();
  if (count <= state.maxEntries) return;
  const db = await new Promise((resolve, reject) => {
    const r = indexedDB.open('burplite', 2);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
  const toDelete = count - state.maxEntries;
  await new Promise((resolve, reject) => {
    const t = db.transaction('requests', 'readwrite');
    const idx = t.objectStore('requests').index('seq');
    const cur = idx.openCursor();
    let deleted = 0;
    cur.onsuccess = () => {
      const c = cur.result;
      if (!c || deleted >= toDelete) { resolve(); return; }
      c.delete();
      deleted++;
      c.continue();
    };
    cur.onerror = () => reject(cur.error);
  });
}

// ============================================================
// Body fetch queue (with binary preservation)
// ============================================================

function queueBodyFetch(record) {
  state.bodyFetchQueue.push(record);
  pumpBodyQueue();
}

async function pumpBodyQueue() {
  while (state.bodyFetchesInFlight < BODY_FETCH_CONCURRENCY && state.bodyFetchQueue.length) {
    const record = state.bodyFetchQueue.shift();
    state.bodyFetchesInFlight++;
    fetchAndStoreBody(record).finally(() => {
      state.bodyFetchesInFlight--;
      pumpBodyQueue();
    });
  }
}

async function fetchAndStoreBody(record) {
  if (!state.attachedTabId) return;
  
  if (record.response.body_size > MAX_BODY_BYTES) {
    record.response.body = null;
    record.response.body_omitted = 'too_large';
    await putRequest(record);
    inFlightRecords.delete(record.id);
    return;
  }

  try {
    const result = await chrome.debugger.sendCommand(
      { tabId: state.attachedTabId },
      'Network.getResponseBody',
      { requestId: record._cdp_request_id }
    );
    if (result && typeof result.body === 'string') {
      if (result.base64Encoded) {
        record.response.body = result.body;
        record.response.body_encoding = 'base64';
      } else {
        record.response.body = result.body;
        record.response.body_encoding = 'text';
      }
    } else {
      record.response.body = null;
      record.response.body_omitted = 'no_body';
    }
  } catch (e) {
    record.response.body = null;
    record.response.body_omitted = 'fetch_failed';
    record.response.body_fetch_error = String(e && e.message || e);
  }

  await putRequest(record);
  inFlightRecords.delete(record.id);
  broadcast({ type: 'request-updated', record });
}

// ============================================================
// CDP event handlers
// ============================================================

function onDebuggerEvent(source, method, params) {
  if (!state.attachedTabId || source.tabId !== state.attachedTabId) return;

  try {
    switch (method) {
      // Network events
      case 'Network.requestWillBeSent': return onRequestWillBeSent(params);
      case 'Network.responseReceived': return onResponseReceived(params);
      case 'Network.loadingFinished': return onLoadingFinished(params);
      case 'Network.loadingFailed': return onLoadingFailed(params);
      case 'Network.requestWillBeSentExtraInfo': return onRequestExtraInfo(params);
      case 'Network.responseReceivedExtraInfo': return onResponseExtraInfo(params);

      // WebSockets
      case 'Network.webSocketCreated': return onWebSocketCreated(params);
      case 'Network.webSocketFrameSent': return onWebSocketFrame(params, 'outbound');
      case 'Network.webSocketFrameReceived': return onWebSocketFrame(params, 'inbound');

      // Fetch Interception
      case 'Fetch.requestPaused': return onFetchRequestPaused(params);

      default: return;
    }
  } catch (e) {
    console.warn('[burplite] debugger event error', method, e);
  }
}

async function onRequestWillBeSent(params) {
  const id = uid('req');
  state.seqCounter++;
  let url;
  try { url = new URL(params.request.url); } catch { return; }

  const record = {
    id,
    seq: state.seqCounter,
    tab_id: state.attachedTabId,
    session_id: state.sessionStartedAt,
    url: params.request.url,
    method: params.request.method,
    scheme: url.protocol.replace(':', ''),
    host: url.host,
    hostname: url.hostname,
    path: url.pathname,
    query: queryToObject(url.search),
    fragment: url.hash || null,
    resource_type: params.type || 'other',
    initiated_at: nowISO(),
    completed_at: null,
    duration_ms: null,
    status_code: null,
    status_text: null,
    mime_group: 'other',
    from_cache: false,
    from_service_worker: false,
    _cdp_request_id: params.requestId,
    notes: '',
    request: {
      headers: headerListToObject(params.request.headers),
      cookies: parseCookies(params.request.headers.Cookie || params.request.headers.cookie, url.host),
      body: params.request.postData || null,
      body_size: params.request.postData ? params.request.postData.length : 0,
      body_mime: params.request.postData ? (params.request.headers['Content-Type'] || params.request.headers['content-type'] || null) : null,
    },
    response: {
      status: null,
      status_text: null,
      headers: {},
      cookies: [],
      body: null,
      body_size: 0,
      body_mime: null,
      body_encoding: null,
      body_omitted: null,
      timing: null,
    },
    timing: {
      blocked: 0, dns: 0, connect: 0, ssl: 0, send: 0, wait: 0, receive: 0,
    },
  };

  requestIdToRecordId.set(params.requestId, id);
  inFlightRecords.set(id, record);

  await putRequest(record);
  broadcast({ type: 'request-added', record });

  enforceCap().catch(e => console.warn('[burplite] enforceCap', e));
}

async function onResponseReceived(params) {
  const id = requestIdToRecordId.get(params.requestId);
  if (!id) return;
  const record = inFlightRecords.get(id) || await getRequest(id);
  if (!record) return;

  const r = params.response;
  record.status_code = r.status;
  record.status_text = r.statusText || '';
  record.mime_group = classifyMimeGroup(r.mimeType, record.resource_type);
  record.response.status = r.status;
  record.response.status_text = r.statusText || '';
  record.response.headers = headerListToObject(r.headers);
  record.response.body_mime = r.mimeType || null;
  record.from_cache = !!r.fromDiskCache;
  record.from_service_worker = !!r.fromServiceWorker;

  const setCookies = [];
  for (const k of Object.keys(r.headers || {})) {
    if (k.toLowerCase() === 'set-cookie') {
      const v = r.headers[k];
      if (Array.isArray(v)) setCookies.push(...v);
      else setCookies.push(v);
    }
  }
  record.response.cookies = parseSetCookies(setCookies, record.host);

  // timing
  const t = params.response.timing || {};
  record.timing = {
    blocked: Math.max(0, (t.sendStart || 0) - (t.requestTime || 0)),
    dns: Math.max(0, (t.dnsEnd || 0) - (t.dnsStart || 0)),
    connect: Math.max(0, (t.connectEnd || 0) - (t.connectStart || 0)),
    ssl: Math.max(0, (t.sslEnd || 0) - (t.sslStart || 0)),
    send: Math.max(0, (t.sendEnd || 0) - (t.sendStart || 0)),
    wait: Math.max(0, (t.receiveHeadersEnd || 0) - (t.sendEnd || 0)),
    receive: 0,
  };

  inFlightRecords.set(id, record);
  await putRequest(record);
  broadcast({ type: 'request-updated', record });
}

async function onRequestExtraInfo(params) {
  const id = requestIdToRecordId.get(params.requestId);
  if (!id) return;
  const record = inFlightRecords.get(id) || await getRequest(id);
  if (!record) return;
  if (params.headers) {
    for (const h of params.headers) {
      if (h.name && !(h.name in record.request.headers)) {
        record.request.headers[h.name] = h.value;
      }
    }
  }
  inFlightRecords.set(id, record);
  await putRequest(record);
}

async function onResponseExtraInfo(params) {
  const id = requestIdToRecordId.get(params.requestId);
  if (!id) return;
  const record = inFlightRecords.get(id) || await getRequest(id);
  if (!record) return;
  if (params.headers) {
    for (const h of params.headers) {
      if (h.name && !(h.name.toLowerCase() in Object.fromEntries(
        Object.entries(record.response.headers).map(([k, v]) => [k.toLowerCase(), v])
      ))) {
        record.response.headers[h.name] = h.value;
      }
    }
  }
  inFlightRecords.set(id, record);
  await putRequest(record);
}

async function onLoadingFinished(params) {
  const id = requestIdToRecordId.get(params.requestId);
  if (!id) return;
  const record = inFlightRecords.get(id) || await getRequest(id);
  if (!record) return;

  record.completed_at = nowISO();
  const startMs = new Date(record.initiated_at).getTime();
  record.duration_ms = Date.now() - startMs;
  record.response.body_size = params.encodedDataLength || record.response.body_size || 0;

  inFlightRecords.set(id, record);
  await putRequest(record);
  broadcast({ type: 'request-updated', record });

  queueBodyFetch(record);
}

async function onLoadingFailed(params) {
  const id = requestIdToRecordId.get(params.requestId);
  if (!id) return;
  const record = inFlightRecords.get(id) || await getRequest(id);
  if (!record) return;
  record.completed_at = nowISO();
  record.status_code = 0;
  record.status_text = params.errorText || 'FAILED';
  record.response.status = 0;
  record.response.status_text = params.errorText || 'FAILED';
  record.response.body_omitted = 'failed';
  inFlightRecords.set(id, record);
  await putRequest(record);
  broadcast({ type: 'request-updated', record });
}

// ============================================================
// WebSockets
// ============================================================

function onWebSocketCreated(params) {
  state.webSocketConnections.set(params.requestId, {
    url: params.url,
    initiator: params.initiator,
    createdAt: nowISO(),
  });
}

async function onWebSocketFrame(params, direction) {
  const conn = state.webSocketConnections.get(params.requestId);
  const frame = {
    id: uid('ws'),
    requestId: params.requestId,
    url: conn ? conn.url : 'WebSocket',
    direction: direction, // 'inbound' | 'outbound'
    timestamp: params.timestamp ? params.timestamp * 1000 : Date.now(),
    isoTime: nowISO(),
    opcode: params.response?.opcode || 1,
    payloadData: params.response?.payloadData || '',
    length: params.response?.payloadData ? params.response.payloadData.length : 0,
  };

  await putWebSocketFrame(frame).catch(() => {});
  broadcast({ type: 'websocket-frame', frame });
}

// ============================================================
// Fetch Interception (Live Request Tampering)
// ============================================================

async function onFetchRequestPaused(params) {
  const pausedId = params.requestId;
  const paused = {
    id: pausedId,
    networkId: params.networkId,
    url: params.request.url,
    method: params.request.method,
    headers: params.request.headers || {},
    postData: params.request.postData || '',
    resourceType: params.resourceType,
    responseStatusCode: params.responseStatusCode || null,
    responseStatusText: params.responseStatusText || null,
    responseHeaders: params.responseHeaders || [],
  };

  state.pausedRequests.set(pausedId, paused);
  broadcast({ type: 'intercept-paused', request: paused });
}

// ============================================================
// Broadcast to open views
// ============================================================

function broadcast(message) {
  chrome.runtime.sendMessage(message).catch(() => {});
}

// ============================================================
// Attach / detach
// ============================================================

async function attachToTab(tabId) {
  if (state.attachedTabId === tabId) return { ok: true, already: true };
  if (state.attachedTabId !== null) {
    await detach();
  }

  try {
    await chrome.debugger.attach({ tabId }, CDP_VERSION);
  } catch (e) {
    return { ok: false, error: String(e && e.message || e) };
  }

  state.attachedTabId = tabId;
  state.sessionStartedAt = nowISO();
  state.seqCounter = await getMaxSeq();
  requestIdToRecordId.clear();
  inFlightRecords.clear();

  try {
    await chrome.debugger.sendCommand({ tabId }, 'Network.enable', {
      maxResourceBufferSize: 15 * 1024 * 1024,
      maxTotalBufferSize: 60 * 1024 * 1024,
    });
    await chrome.debugger.sendCommand({ tabId }, 'Page.enable').catch(() => {});

    // If intercept is on, enable Fetch
    if (state.interceptEnabled) {
      await chrome.debugger.sendCommand({ tabId }, 'Fetch.enable', {
        patterns: [{ urlPattern: '*' }]
      }).catch(err => console.warn('[burplite] Fetch.enable failed', err));
    }
  } catch (e) {
    await chrome.debugger.detach({ tabId }).catch(() => {});
    state.attachedTabId = null;
    return { ok: false, error: 'Network.enable failed: ' + String(e && e.message || e) };
  }

  await setMeta('session', {
    attachedTabId: tabId,
    startedAt: state.sessionStartedAt,
  });

  broadcast({ type: 'attached', tabId });
  return { ok: true, tabId };
}

async function detach() {
  const tabId = state.attachedTabId;
  state.attachedTabId = null;
  state.sessionStartedAt = null;
  requestIdToRecordId.clear();
  inFlightRecords.clear();
  state.bodyFetchQueue.length = 0;
  state.pausedRequests.clear();

  if (tabId !== null) {
    try { await chrome.debugger.detach({ tabId }); } catch (_) {}
  }
  await setMeta('session', null);
  broadcast({ type: 'detached' });
  return { ok: true };
}

// ============================================================
// Repeater Request Runner (Bypasses CORS via <all_urls>)
// ============================================================

async function executeRepeaterRequest(req) {
  const startTime = Date.now();
  const url = req.url;
  const method = (req.method || 'GET').toUpperCase();
  const headers = req.headers || {};
  const body = ['GET', 'HEAD'].includes(method) ? undefined : (req.body || undefined);

  // Filter out forbidden headers if any (or let fetch execute)
  const fetchHeaders = new Headers();
  for (const [k, v] of Object.entries(headers)) {
    try {
      fetchHeaders.append(k, v);
    } catch (_) {}
  }

  try {
    const res = await fetch(url, {
      method,
      headers: fetchHeaders,
      body,
      redirect: 'manual',
    });

    const duration = Date.now() - startTime;
    const resHeaders = {};
    for (const [k, v] of res.headers.entries()) {
      resHeaders[k] = v;
    }

    const contentType = res.headers.get('content-type') || '';
    let resBody = '';
    let bodyEncoding = 'text';

    if (isTextMime(contentType)) {
      resBody = await res.text();
    } else {
      const arrayBuffer = await res.arrayBuffer();
      const bytes = new Uint8Array(arrayBuffer);
      let binStr = '';
      for (let i = 0; i < bytes.length; i++) {
        binStr += String.fromCharCode(bytes[i]);
      }
      resBody = btoa(binStr);
      bodyEncoding = 'base64';
    }

    return {
      ok: true,
      statusCode: res.status,
      statusText: res.statusText || 'OK',
      headers: resHeaders,
      body: resBody,
      bodyEncoding: bodyEncoding,
      durationMs: duration,
      sizeBytes: resBody.length,
    };
  } catch (err) {
    return {
      ok: false,
      error: String(err && err.message || err),
      durationMs: Date.now() - startTime,
    };
  }
}

// ============================================================
// Debugger lifecycle events
// ============================================================

chrome.debugger.onEvent.addListener(onDebuggerEvent);

chrome.debugger.onDetach.addListener((source, reason) => {
  if (source.tabId === state.attachedTabId) {
    state.attachedTabId = null;
    state.sessionStartedAt = null;
    requestIdToRecordId.clear();
    inFlightRecords.clear();
    state.pausedRequests.clear();
    broadcast({ type: 'detached', reason });
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  if (tabId === state.attachedTabId) {
    detach();
  }
});

// ============================================================
// Message API
// ============================================================

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || !msg.type) {
    sendResponse({ ok: false, error: 'invalid message' });
    return true;
  }

  (async () => {
    try {
      switch (msg.type) {
        case 'attach': {
          const tabId = msg.tabId || (await getActiveTabId());
          if (tabId == null) { sendResponse({ ok: false, error: 'no active tab' }); return; }
          const res = await attachToTab(tabId);
          sendResponse(res);
          return;
        }
        case 'detach': {
          const res = await detach();
          sendResponse(res);
          return;
        }
        case 'status': {
          sendResponse({
            ok: true,
            attached: state.attachedTabId !== null,
            tabId: state.attachedTabId,
            sessionStartedAt: state.sessionStartedAt,
            interceptEnabled: state.interceptEnabled,
            pausedCount: state.pausedRequests.size,
          });
          return;
        }
        case 'clear': {
          await clearAllRequests();
          state.seqCounter = 0;
          broadcast({ type: 'cleared' });
          sendResponse({ ok: true });
          return;
        }
        case 'open-log': {
          const url = chrome.runtime.getURL('log.html');
          const existing = await chrome.tabs.query({ url });
          if (existing && existing.length) {
            await chrome.tabs.update(existing[0].id, { active: true });
          } else {
            await chrome.tabs.create({ url });
          }
          sendResponse({ ok: true });
          return;
        }
        case 'toggle-intercept': {
          state.interceptEnabled = !!msg.enabled;
          if (state.attachedTabId) {
            if (state.interceptEnabled) {
              await chrome.debugger.sendCommand({ tabId: state.attachedTabId }, 'Fetch.enable', {
                patterns: [{ urlPattern: '*' }]
              }).catch(err => console.warn('[burplite] Fetch.enable err', err));
            } else {
              // Flush any paused requests before disabling
              for (const [pausedId] of state.pausedRequests) {
                chrome.debugger.sendCommand({ tabId: state.attachedTabId }, 'Fetch.continueRequest', {
                  requestId: pausedId
                }).catch(() => {});
              }
              state.pausedRequests.clear();
              await chrome.debugger.sendCommand({ tabId: state.attachedTabId }, 'Fetch.disable').catch(() => {});
            }
          }
          broadcast({ type: 'intercept-status', enabled: state.interceptEnabled });
          sendResponse({ ok: true, enabled: state.interceptEnabled });
          return;
        }
        case 'intercept-forward': {
          const pausedId = msg.requestId;
          state.pausedRequests.delete(pausedId);
          if (state.attachedTabId) {
            const params = { requestId: pausedId };
            if (msg.modified) {
              if (msg.url) params.url = msg.url;
              if (msg.method) params.method = msg.method;
              if (msg.headers) {
                params.headers = Object.entries(msg.headers).map(([name, value]) => ({ name, value }));
              }
              if (msg.postData) params.postData = btoa(msg.postData);
            }
            await chrome.debugger.sendCommand({ tabId: state.attachedTabId }, 'Fetch.continueRequest', params);
          }
          sendResponse({ ok: true });
          return;
        }
        case 'intercept-drop': {
          const pausedId = msg.requestId;
          state.pausedRequests.delete(pausedId);
          if (state.attachedTabId) {
            await chrome.debugger.sendCommand({ tabId: state.attachedTabId }, 'Fetch.failRequest', {
              requestId: pausedId,
              errorReason: 'Aborted',
            });
          }
          sendResponse({ ok: true });
          return;
        }
        case 'repeater-send': {
          const res = await executeRepeaterRequest(msg.request);
          sendResponse(res);
          return;
        }
        default:
          sendResponse({ ok: false, error: 'unknown message type: ' + msg.type });
      }
    } catch (e) {
      sendResponse({ ok: false, error: String(e && e.message || e) });
    }
  })();

  return true;
});

async function getActiveTabId() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs && tabs.length ? tabs[0].id : null;
}

// Keep-alive
if (chrome.alarms && chrome.alarms.create) {
  try {
    chrome.alarms.create('keepAlive', { periodInMinutes: 1 });
    chrome.alarms.onAlarm.addListener((a) => {
      if (a.name === 'keepAlive') {
        chrome.storage.local.get('_ping', () => {});
      }
    });
  } catch (_) {}
}

console.info('[burplite] service worker initialized');