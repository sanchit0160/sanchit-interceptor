/**
 * Sanchit Interceptor — HAR 1.2 Parser & Exporter
 * Copyright (c) 2026 Sanchit. All rights reserved.
 *
 * Imports and exports standard HTTP Archive (HAR 1.2) files.
 */

export function parseHar(harContent) {
  let parsed;
  if (typeof harContent === 'string') {
    parsed = JSON.parse(harContent);
  } else {
    parsed = harContent;
  }

  if (!parsed || !parsed.log || !Array.isArray(parsed.log.entries)) {
    throw new Error('Invalid HAR file: missing log.entries');
  }

  const entries = parsed.log.entries;
  const records = [];
  let seq = 1;

  for (const e of entries) {
    const req = e.request || {};
    const res = e.response || {};
    const timings = e.timings || {};

    let urlObj;
    try {
      urlObj = new URL(req.url);
    } catch (_) {
      urlObj = { host: 'unknown', pathname: '/', searchParams: new URLSearchParams() };
    }

    const headersReq = {};
    for (const h of req.headers || []) {
      headersReq[h.name] = h.value;
    }

    const headersRes = {};
    for (const h of res.headers || []) {
      headersRes[h.name] = h.value;
    }

    const record = {
      id: `har_entry_${seq}_${Date.now().toString(36)}`,
      seq: seq++,
      tab_id: null,
      session_id: 'har_import',
      url: req.url || '',
      method: (req.method || 'GET').toUpperCase(),
      scheme: req.url?.startsWith('https') ? 'https' : 'http',
      host: urlObj.host,
      hostname: urlObj.hostname || urlObj.host,
      path: urlObj.pathname || '/',
      query: Object.fromEntries(new URLSearchParams(urlObj.search || '').entries()),
      resource_type: res.content?.mimeType || 'other',
      initiated_at: e.startedDateTime || new Date().toISOString(),
      completed_at: null,
      duration_ms: e.time || 0,
      status_code: res.status || 0,
      status_text: res.statusText || '',
      mime_group: classifyMime(res.content?.mimeType),
      from_cache: !!res.fromDiskCache,
      from_service_worker: false,
      notes: e.comment || '',
      request: {
        headers: headersReq,
        cookies: req.cookies || [],
        body: req.postData?.text || '',
        body_size: req.bodySize || (req.postData?.text ? req.postData.text.length : 0),
        body_mime: req.postData?.mimeType || null,
      },
      response: {
        status: res.status || 0,
        status_text: res.statusText || '',
        headers: headersRes,
        cookies: res.cookies || [],
        body: res.content?.text || '',
        body_size: res.content?.size || (res.content?.text ? res.content.text.length : 0),
        body_mime: res.content?.mimeType || null,
        body_encoding: res.content?.encoding === 'base64' ? 'base64' : 'text',
        body_omitted: null,
      },
      timing: {
        blocked: timings.blocked || 0,
        dns: timings.dns || 0,
        connect: timings.connect || 0,
        ssl: timings.ssl || 0,
        send: timings.send || 0,
        wait: timings.wait || 0,
        receive: timings.receive || 0,
      }
    };

    records.push(record);
  }

  return {
    source: 'HAR 1.2',
    count: records.length,
    requests: records,
  };
}

export function exportHar(records) {
  const entries = records.map(r => ({
    startedDateTime: r.initiated_at,
    time: r.duration_ms || 0,
    request: {
      method: r.method,
      url: r.url,
      httpVersion: 'HTTP/1.1',
      cookies: (r.request.cookies || []).map(c => ({ name: c.name, value: c.value })),
      headers: Object.entries(r.request.headers || {}).map(([k, v]) => ({ name: k, value: String(v) })),
      queryString: Object.entries(r.query || {}).map(([k, v]) => ({ name: k, value: String(v) })),
      postData: r.request.body ? { mimeType: r.request.body_mime || 'text/plain', text: r.request.body } : undefined,
      headersSize: -1,
      bodySize: r.request.body_size || 0,
    },
    response: {
      status: r.status_code || 0,
      statusText: r.status_text || '',
      httpVersion: 'HTTP/1.1',
      cookies: (r.response.cookies || []).map(c => ({ name: c.name, value: c.value })),
      headers: Object.entries(r.response.headers || {}).map(([k, v]) => ({ name: k, value: String(v) })),
      content: {
        size: r.response.body_size || 0,
        mimeType: r.response.body_mime || '',
        text: r.response.body || '',
        encoding: r.response.body_encoding === 'base64' ? 'base64' : undefined,
      },
      redirectURL: r.response.headers['location'] || '',
      headersSize: -1,
      bodySize: r.response.body_size || 0,
    },
    cache: {},
    timings: {
      blocked: r.timing?.blocked || 0,
      dns: r.timing?.dns || 0,
      connect: r.timing?.connect || 0,
      ssl: r.timing?.ssl || 0,
      send: r.timing?.send || 0,
      wait: r.timing?.wait || 0,
      receive: r.timing?.receive || 0,
    },
    serverIPAddress: '',
    connection: '',
  }));

  return {
    log: {
      version: '1.2',
      creator: { name: 'Sanchit Interceptor', version: '1.0.0' },
      entries,
    },
  };
}

function classifyMime(mime) {
  if (!mime) return 'other';
  const m = mime.toLowerCase();
  if (m.includes('json')) return 'json';
  if (m.includes('xml')) return 'xml';
  if (m.includes('html')) return 'html';
  if (m.includes('javascript') || m.includes('ecmascript')) return 'js';
  if (m.includes('css')) return 'css';
  if (m.startsWith('image/')) return 'image';
  if (m.startsWith('font/')) return 'font';
  if (m.startsWith('text/')) return 'text';
  return 'other';
}
