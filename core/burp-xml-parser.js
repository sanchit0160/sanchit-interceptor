/**
 * Sanchit Interceptor — Burp Suite XML / .burp File Parser & Exporter
 * Copyright (c) 2026 Sanchit. All rights reserved.
 *
 * Parses Burp Suite exported items (.burp or .xml) and reconstructs
 * full HTTP records (requests, responses, headers, bodies, cookies, timing).
 * Also exports captured records back to Burp Suite XML format.
 */

import { parseRawHttpRequest, parseRawHttpResponse } from './http-parser.js';

/**
 * UTF-8 & Binary safe Base64 decoder
 */
export function safeBase64Decode(b64) {
  if (!b64 || typeof b64 !== 'string') return '';
  const cleaned = b64.replace(/\s+/g, '');
  try {
    const binStr = atob(cleaned);
    const bytes = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) {
      bytes[i] = binStr.charCodeAt(i);
    }
    // Attempt UTF-8 text decode
    try {
      const decoder = new TextDecoder('utf-8', { fatal: false });
      return decoder.decode(bytes);
    } catch (_) {
      return binStr;
    }
  } catch (e) {
    // If not valid base64, return raw string
    return b64;
  }
}

/**
 * UTF-8 safe Base64 encoder
 */
export function safeBase64Encode(str) {
  if (!str) return '';
  try {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(str);
    let binStr = '';
    const chunk = 8192;
    for (let i = 0; i < bytes.length; i += chunk) {
      binStr += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(binStr);
  } catch (e) {
    return btoa(unescape(encodeURIComponent(str)));
  }
}

/**
 * Parse .burp or .xml file containing Burp Suite items
 */
export function parseBurpXml(xmlString) {
  if (!xmlString || typeof xmlString !== 'string') {
    throw new Error('Burp XML content is empty or invalid');
  }

  if (typeof DOMParser === 'undefined') {
    return parseBurpXmlRegexFallback(xmlString);
  }

  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(xmlString, 'text/xml');

  // Check for parse errors
  const parseError = xmlDoc.querySelector('parsererror');
  if (parseError) {
    // Attempt regex fallback for slightly malformed XML
    return parseBurpXmlRegexFallback(xmlString);
  }

  const itemNodes = xmlDoc.querySelectorAll('item');
  if (!itemNodes || itemNodes.length === 0) {
    throw new Error('No <item> elements found in Burp file');
  }

  const records = [];
  let seq = 1;

  for (const item of itemNodes) {
    const timeText = item.querySelector('time')?.textContent?.trim() || new Date().toISOString();
    const urlText = item.querySelector('url')?.textContent?.trim() || '';
    const hostNode = item.querySelector('host');
    const hostText = hostNode?.textContent?.trim() || '';
    const hostIp = hostNode?.getAttribute('ip') || '';
    const portText = item.querySelector('port')?.textContent?.trim() || '';
    const protocol = item.querySelector('protocol')?.textContent?.trim() || (portText === '443' ? 'https' : 'http');
    const methodText = item.querySelector('method')?.textContent?.trim() || 'GET';
    const pathText = item.querySelector('path')?.textContent?.trim() || '/';
    const statusText = item.querySelector('status')?.textContent?.trim() || '200';
    const responseLen = item.querySelector('responselength')?.textContent?.trim() || '0';
    const mimeText = item.querySelector('mimetype')?.textContent?.trim() || '';
    const commentText = item.querySelector('comment')?.textContent?.trim() || '';

    // Request payload
    const reqNode = item.querySelector('request');
    let rawRequest = '';
    if (reqNode) {
      const isB64 = reqNode.getAttribute('base64') === 'true' || reqNode.getAttribute('base64') === '1';
      const text = reqNode.textContent?.trim() || '';
      rawRequest = isB64 ? safeBase64Decode(text) : text;
    }

    // Response payload
    const resNode = item.querySelector('response');
    let rawResponse = '';
    if (resNode) {
      const isB64 = resNode.getAttribute('base64') === 'true' || resNode.getAttribute('base64') === '1';
      const text = resNode.textContent?.trim() || '';
      rawResponse = isB64 ? safeBase64Decode(text) : text;
    }

    const parsedReq = parseRawHttpRequest(rawRequest, protocol);
    const parsedRes = parseRawHttpResponse(rawResponse);

    let effectiveUrl = urlText;
    if (!effectiveUrl) {
      effectiveUrl = `${protocol}://${hostText}${portText && portText !== '80' && portText !== '443' ? ':' + portText : ''}${pathText}`;
    }

    let parsedUrl;
    try {
      parsedUrl = new URL(effectiveUrl);
    } catch (_) {
      parsedUrl = { pathname: pathText, host: hostText, searchParams: new URLSearchParams() };
    }

    const statusCode = parseInt(statusText, 10) || parsedRes.statusCode || 200;

    const record = {
      id: `burp_item_${seq}_${Date.now().toString(36)}`,
      seq: seq++,
      tab_id: null,
      session_id: 'burp_import',
      url: effectiveUrl,
      method: methodText.toUpperCase(),
      scheme: protocol,
      host: hostText || parsedUrl.host,
      hostname: hostText,
      path: pathText || parsedUrl.pathname,
      query: Object.fromEntries(new URLSearchParams(effectiveUrl.split('?')[1] || '').entries()),
      resource_type: mimeText ? mimeText.toLowerCase() : 'xhr',
      initiated_at: parseBurpDate(timeText),
      completed_at: null,
      duration_ms: 0,
      status_code: statusCode,
      status_text: parsedRes.statusText || 'OK',
      mime_group: classifyMime(mimeText || parsedRes.headers['content-type'] || ''),
      from_cache: false,
      from_service_worker: false,
      notes: commentText,
      request: {
        headers: parsedReq.headers,
        cookies: extractCookies(parsedReq.headers['Cookie'] || parsedReq.headers['cookie'] || '', hostText),
        body: parsedReq.body,
        body_size: parsedReq.body ? parsedReq.body.length : 0,
        body_mime: parsedReq.headers['Content-Type'] || parsedReq.headers['content-type'] || null,
      },
      response: {
        status: statusCode,
        status_text: parsedRes.statusText || 'OK',
        headers: parsedRes.headers,
        cookies: extractCookies(parsedRes.headers['Set-Cookie'] || parsedRes.headers['set-cookie'] || '', hostText),
        body: parsedRes.body,
        body_size: parseInt(responseLen, 10) || (parsedRes.body ? parsedRes.body.length : 0),
        body_mime: parsedRes.headers['Content-Type'] || parsedRes.headers['content-type'] || mimeText || null,
        body_encoding: 'text',
        body_omitted: null,
      },
      timing: { blocked: 0, dns: 0, connect: 0, ssl: 0, send: 0, wait: 0, receive: 0 },
      _burp_raw_req: rawRequest,
      _burp_raw_res: rawResponse,
    };

    records.push(record);
  }

  return {
    source: 'Burp Suite XML',
    count: records.length,
    requests: records,
  };
}

/**
 * Regex fallback for malformed or huge XML streams
 */
function parseBurpXmlRegexFallback(xmlString) {
  const itemRegex = /<item>([\s\S]*?)<\/item>/gi;
  const records = [];
  let match;
  let seq = 1;

  while ((match = itemRegex.exec(xmlString)) !== null) {
    const itemBlock = match[1];
    const extract = tag => {
      const m = new RegExp(`<${tag}(?:\\s+[^>]*>|>)([\\s\\S]*?)<\\/${tag}>`, 'i').exec(itemBlock);
      return m ? m[1].trim() : '';
    };

    const url = extract('url');
    const host = extract('host');
    const method = extract('method') || 'GET';
    const status = parseInt(extract('status'), 10) || 200;
    const time = extract('time');
    const reqB64 = extract('request');
    const resB64 = extract('response');

    const rawReq = safeBase64Decode(reqB64);
    const rawRes = safeBase64Decode(resB64);
    const parsedReq = parseRawHttpRequest(rawReq);
    const parsedRes = parseRawHttpResponse(rawRes);

    records.push({
      id: `burp_regex_${seq}_${Date.now().toString(36)}`,
      seq: seq++,
      url: url || `http://${host || 'localhost'}/`,
      method: method.toUpperCase(),
      scheme: url.startsWith('https') ? 'https' : 'http',
      host: host || 'localhost',
      path: url ? new URL(url).pathname : '/',
      query: {},
      resource_type: 'xhr',
      initiated_at: parseBurpDate(time),
      completed_at: null,
      duration_ms: 0,
      status_code: status,
      status_text: parsedRes.statusText || 'OK',
      mime_group: 'other',
      from_cache: false,
      from_service_worker: false,
      notes: extract('comment'),
      request: {
        headers: parsedReq.headers,
        cookies: [],
        body: parsedReq.body,
        body_size: parsedReq.body.length,
        body_mime: null,
      },
      response: {
        status: status,
        status_text: parsedRes.statusText || 'OK',
        headers: parsedRes.headers,
        cookies: [],
        body: parsedRes.body,
        body_size: parsedRes.body.length,
        body_mime: null,
        body_encoding: 'text',
        body_omitted: null,
      },
      timing: { blocked: 0, dns: 0, connect: 0, ssl: 0, send: 0, wait: 0, receive: 0 }
    });
  }

  return {
    source: 'Burp Suite XML (Regex)',
    count: records.length,
    requests: records,
  };
}

/**
 * Export internal records to Burp Suite compatible XML format
 */
export function exportBurpXml(records) {
  const items = records.map(r => {
    let rawReq = r._burp_raw_req;
    if (!rawReq) {
      const lines = [`${r.method} ${r.path} HTTP/1.1`, `Host: ${r.host}`];
      for (const [k, v] of Object.entries(r.request.headers || {})) {
        if (k.toLowerCase() === 'host') continue;
        lines.push(`${k}: ${v}`);
      }
      lines.push('', r.request.body || '');
      rawReq = lines.join('\r\n');
    }

    let rawRes = r._burp_raw_res;
    if (!rawRes) {
      const lines = [`HTTP/1.1 ${r.status_code} ${r.status_text || 'OK'}`];
      for (const [k, v] of Object.entries(r.response.headers || {})) {
        lines.push(`${k}: ${v}`);
      }
      lines.push('', r.response.body || '');
      rawRes = lines.join('\r\n');
    }

    const reqB64 = safeBase64Encode(rawReq);
    const resB64 = safeBase64Encode(rawRes);

    return `  <item>
    <time>${escapeXml(r.initiated_at || new Date().toISOString())}</time>
    <url>${escapeXml(r.url)}</url>
    <host ip="">${escapeXml(r.host)}</host>
    <port>${r.scheme === 'https' ? '443' : '80'}</port>
    <protocol>${escapeXml(r.scheme)}</protocol>
    <method>${escapeXml(r.method)}</method>
    <path>${escapeXml(r.path)}</path>
    <extension>null</extension>
    <request base64="true">${reqB64}</request>
    <status>${r.status_code || 200}</status>
    <responselength>${r.response?.body_size || 0}</responselength>
    <mimetype>${escapeXml(r.mime_group || '')}</mimetype>
    <response base64="true">${resB64}</response>
    <comment>${escapeXml(r.notes || '')}</comment>
  </item>`;
  }).join('\n');

  return `<?xml version="1.0"?>
<!DOCTYPE items SYSTEM "https://burp.net/dtd/burp_items.dtd">
<items burpVersion="2026.1" exportDate="${new Date().toUTCString()}">
${items}
</items>`;
}

function escapeXml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function parseBurpDate(dateStr) {
  if (!dateStr) return new Date().toISOString();
  try {
    const d = new Date(dateStr);
    if (!isNaN(d.getTime())) return d.toISOString();
  } catch (_) {}
  return new Date().toISOString();
}

function classifyMime(mime) {
  if (!mime) return 'other';
  const m = mime.toLowerCase();
  if (m.includes('json')) return 'json';
  if (m.includes('xml')) return 'xml';
  if (m.includes('html')) return 'html';
  if (m.includes('javascript')) return 'js';
  if (m.includes('css')) return 'css';
  if (m.includes('image')) return 'image';
  if (m.includes('text')) return 'text';
  return 'other';
}

function extractCookies(cookieStr, domain) {
  if (!cookieStr) return [];
  return cookieStr.split(';').map(p => {
    const idx = p.indexOf('=');
    if (idx < 0) return null;
    return {
      name: p.slice(0, idx).trim(),
      value: p.slice(idx + 1).trim(),
      domain: domain || null
    };
  }).filter(Boolean);
}
