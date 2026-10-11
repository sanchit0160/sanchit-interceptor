/**
 * Sanchit Interceptor — .sanchit Project Format Engine
 * Copyright (c) 2026 Sanchit. All rights reserved.
 *
 * Implements the native .sanchit project container specification.
 * Supports saving complete analysis workspace state:
 * - Live captured & imported HTTP traffic with deep bodies
 * - Repeater tabs & history
 * - Target Site Map & scope definitions
 * - Intercept configurations
 * - User notes, tags & comments
 */

export const SANCHIT_MAGIC = 'SANCHIT_BURP_PROJECT_V1';
export const SANCHIT_FORMAT_VERSION = '1.0.0';

/**
 * Serialize workspace into a .sanchit project file structure
 */
export function createSanchitProject({
  projectName = 'Sanchit Interceptor Session',
  requests = [],
  repeaterTabs = [],
  sitemap = {},
  scopeRules = { include: [], exclude: [] },
  settings = {},
  meta = {}
}) {
  const hosts = new Set();
  const mimeStats = {};
  let totalBytes = 0;

  for (const r of requests) {
    if (r.host) hosts.add(r.host);
    if (r.mime_group) {
      mimeStats[r.mime_group] = (mimeStats[r.mime_group] || 0) + 1;
    }
    if (r.response && r.response.body_size) {
      totalBytes += r.response.body_size;
    }
  }

  const project = {
    magic: SANCHIT_MAGIC,
    version: SANCHIT_FORMAT_VERSION,
    app: 'Sanchit Interceptor',
    created_at: new Date().toISOString(),
    project_name: projectName,
    summary: {
      request_count: requests.length,
      host_count: hosts.size,
      hosts: [...hosts].sort(),
      mime_breakdown: mimeStats,
      total_response_bytes: totalBytes,
      repeater_tab_count: repeaterTabs.length,
    },
    scope: scopeRules,
    sitemap: sitemap,
    repeater: repeaterTabs,
    settings: settings,
    meta: meta,
    requests: requests.map((r, index) => ({
      id: r.id || `req_sanchit_${index + 1}`,
      seq: r.seq || (index + 1),
      tab_id: r.tab_id || null,
      session_id: r.session_id || null,
      url: r.url,
      method: r.method,
      scheme: r.scheme || (r.url.startsWith('https') ? 'https' : 'http'),
      host: r.host,
      hostname: r.hostname || r.host,
      path: r.path || '/',
      query: r.query || {},
      fragment: r.fragment || null,
      resource_type: r.resource_type || 'other',
      initiated_at: r.initiated_at,
      completed_at: r.completed_at,
      duration_ms: r.duration_ms,
      status_code: r.status_code,
      status_text: r.status_text,
      mime_group: r.mime_group || 'other',
      from_cache: !!r.from_cache,
      from_service_worker: !!r.from_service_worker,
      notes: r.notes || '',
      highlight: r.highlight || null,
      request: {
        headers: r.request?.headers || {},
        cookies: r.request?.cookies || [],
        body: r.request?.body || '',
        body_size: r.request?.body_size || (r.request?.body ? r.request.body.length : 0),
        body_mime: r.request?.body_mime || null,
      },
      response: {
        status: r.response?.status || r.status_code,
        status_text: r.response?.status_text || r.status_text,
        headers: r.response?.headers || {},
        cookies: r.response?.cookies || [],
        body: r.response?.body || '',
        body_size: r.response?.body_size || (r.response?.body ? r.response.body.length : 0),
        body_mime: r.response?.body_mime || null,
        body_encoding: r.response?.body_encoding || 'text',
        body_omitted: r.response?.body_omitted || null,
      },
      timing: r.timing || {
        blocked: 0, dns: 0, connect: 0, ssl: 0, send: 0, wait: 0, receive: 0
      }
    }))
  };

  return project;
}

/**
 * Validate and parse a .sanchit file string or JSON object
 */
export function parseSanchitProject(content) {
  let parsed;
  if (typeof content === 'string') {
    try {
      parsed = JSON.parse(content);
    } catch (e) {
      throw new Error('Invalid .sanchit file: Not valid JSON (' + e.message + ')');
    }
  } else if (typeof content === 'object' && content !== null) {
    parsed = content;
  } else {
    throw new Error('Invalid .sanchit content type');
  }

  // Check magic or signature
  const isSanchitMagic = parsed.magic === SANCHIT_MAGIC;
  const isLegacyBurpLite = parsed.version === 1 && Array.isArray(parsed.entries);

  if (!isSanchitMagic && !isLegacyBurpLite) {
    // Check if it looks like an exported JSON session
    if (!Array.isArray(parsed.requests) && !Array.isArray(parsed.entries)) {
      throw new Error('File does not appear to be a .sanchit project or valid BurpLite capture');
    }
  }

  const rawRequests = parsed.requests || parsed.entries || [];
  const normalizedRequests = rawRequests.map((r, i) => ({
    id: r.id || `imported_${Date.now()}_${i}`,
    seq: r.seq || (i + 1),
    url: r.url || '',
    method: (r.method || 'GET').toUpperCase(),
    scheme: r.scheme || (r.url?.startsWith('https') ? 'https' : 'http'),
    host: r.host || (r.url ? new URL(r.url).host : ''),
    hostname: r.hostname || r.host,
    path: r.path || (r.url ? new URL(r.url).pathname : '/'),
    query: r.query || {},
    resource_type: r.resource_type || 'xhr',
    initiated_at: r.initiated_at || new Date().toISOString(),
    completed_at: r.completed_at || null,
    duration_ms: r.duration_ms || 0,
    status_code: r.status_code || r.response?.status || 200,
    status_text: r.status_text || r.response?.status_text || 'OK',
    mime_group: r.mime_group || 'other',
    from_cache: !!r.from_cache,
    from_service_worker: !!r.from_service_worker,
    notes: r.notes || '',
    highlight: r.highlight || null,
    request: {
      headers: r.request?.headers || {},
      cookies: r.request?.cookies || [],
      body: r.request?.body || '',
      body_size: r.request?.body_size || 0,
      body_mime: r.request?.body_mime || null,
    },
    response: {
      status: r.response?.status || r.status_code || 200,
      status_text: r.response?.status_text || r.status_text || 'OK',
      headers: r.response?.headers || {},
      cookies: r.response?.cookies || [],
      body: r.response?.body || '',
      body_size: r.response?.body_size || 0,
      body_mime: r.response?.body_mime || null,
      body_encoding: r.response?.body_encoding || 'text',
      body_omitted: r.response?.body_omitted || null,
    },
    timing: r.timing || { blocked: 0, dns: 0, connect: 0, ssl: 0, send: 0, wait: 0, receive: 0 }
  }));

  return {
    projectName: parsed.project_name || 'Imported .sanchit Project',
    createdAt: parsed.created_at || new Date().toISOString(),
    version: parsed.version || '1.0.0',
    requests: normalizedRequests,
    repeaterTabs: Array.isArray(parsed.repeater) ? parsed.repeater : [],
    sitemap: parsed.sitemap || {},
    scopeRules: parsed.scope || { include: [], exclude: [] },
    settings: parsed.settings || {},
  };
}

/**
 * Trigger download of a .sanchit project file in the browser
 */
export function downloadSanchitFile(projectData, filename = null) {
  const json = JSON.stringify(projectData, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const safeName = filename || `burp-project-${new Date().toISOString().replace(/[:.]/g, '-')}.sanchit`;
  
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = safeName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
  return safeName;
}
