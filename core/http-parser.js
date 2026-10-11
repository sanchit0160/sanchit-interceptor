/**
 * Sanchit Interceptor — HTTP Parser & Serializer
 * Copyright (c) 2026 Sanchit. All rights reserved.
 *
 * Handles bidirectional parsing between raw HTTP wire strings and structured objects.
 * Essential for Repeater, Intercept, and Raw viewers.
 */

/**
 * Parse a raw HTTP request string into structured data
 * e.g.
 * POST /api/v1/auth?token=123 HTTP/1.1
 * Host: example.com
 * Content-Type: application/json
 * 
 * {"user": "admin"}
 */
export function parseRawHttpRequest(rawText, defaultProtocol = 'https') {
  if (!rawText || typeof rawText !== 'string') {
    return {
      method: 'GET',
      url: '',
      path: '/',
      httpVersion: 'HTTP/1.1',
      headers: {},
      body: '',
    };
  }

  // Normalize line endings
  const normalized = rawText.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  const splitIndex = normalized.indexOf('\n\n');
  
  let headerSection = '';
  let bodySection = '';

  if (splitIndex !== -1) {
    headerSection = normalized.slice(0, splitIndex);
    bodySection = normalized.slice(splitIndex + 2);
  } else {
    headerSection = normalized;
    bodySection = '';
  }

  const lines = headerSection.split('\n');
  const requestLine = lines[0] ? lines[0].trim() : 'GET / HTTP/1.1';
  const reqLineParts = requestLine.split(/\s+/);

  const method = (reqLineParts[0] || 'GET').toUpperCase();
  const rawPath = reqLineParts[1] || '/';
  const httpVersion = reqLineParts[2] || 'HTTP/1.1';

  const headers = {};
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    const colonIdx = line.indexOf(':');
    if (colonIdx > 0) {
      const key = line.slice(0, colonIdx).trim();
      const val = line.slice(colonIdx + 1).trim();
      headers[key] = val;
    }
  }

  // Reconstruct full URL if Host header is present
  const host = headers['Host'] || headers['host'] || '';
  let fullUrl = rawPath;
  if (rawPath.startsWith('http://') || rawPath.startsWith('https://')) {
    fullUrl = rawPath;
  } else if (host) {
    fullUrl = `${defaultProtocol}://${host}${rawPath.startsWith('/') ? '' : '/'}${rawPath}`;
  }

  return {
    method,
    rawPath,
    fullUrl,
    httpVersion,
    headers,
    body: bodySection,
  };
}

/**
 * Parse a raw HTTP response string into structured data
 * e.g.
 * HTTP/1.1 200 OK
 * Content-Type: application/json
 * Content-Length: 15
 * 
 * {"success":true}
 */
export function parseRawHttpResponse(rawText) {
  if (!rawText || typeof rawText !== 'string') {
    return {
      httpVersion: 'HTTP/1.1',
      statusCode: 200,
      statusText: 'OK',
      headers: {},
      body: '',
    };
  }

  const normalized = rawText.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  const splitIndex = normalized.indexOf('\n\n');

  let headerSection = '';
  let bodySection = '';

  if (splitIndex !== -1) {
    headerSection = normalized.slice(0, splitIndex);
    bodySection = normalized.slice(splitIndex + 2);
  } else {
    headerSection = normalized;
    bodySection = '';
  }

  const lines = headerSection.split('\n');
  const statusLine = lines[0] ? lines[0].trim() : 'HTTP/1.1 200 OK';
  const match = statusLine.match(/^(HTTP\/[\d\.]+)\s+(\d+)(?:\s+(.*))?$/i);

  let httpVersion = 'HTTP/1.1';
  let statusCode = 200;
  let statusText = 'OK';

  if (match) {
    httpVersion = match[1];
    statusCode = parseInt(match[2], 10) || 200;
    statusText = match[3] || '';
  }

  const headers = {};
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    const colonIdx = line.indexOf(':');
    if (colonIdx > 0) {
      const key = line.slice(0, colonIdx).trim();
      const val = line.slice(colonIdx + 1).trim();
      headers[key] = val;
    }
  }

  return {
    httpVersion,
    statusCode,
    statusText,
    headers,
    body: bodySection,
  };
}

/**
 * Format a structured request into standard raw HTTP string
 */
export function formatRawHttpRequest(req) {
  let path = req.path || '/';
  if (req.query && Object.keys(req.query).length > 0) {
    const qs = new URLSearchParams(req.query).toString();
    if (qs && !path.includes('?')) {
      path += '?' + qs;
    }
  }

  const method = (req.method || 'GET').toUpperCase();
  const httpVer = req.httpVersion || 'HTTP/1.1';
  const headers = req.headers || {};
  
  const headerLines = [];
  
  // Ensure Host header is first if present
  if (headers['Host']) {
    headerLines.push(`Host: ${headers['Host']}`);
  } else if (headers['host']) {
    headerLines.push(`Host: ${headers['host']}`);
  } else if (req.host) {
    headerLines.push(`Host: ${req.host}`);
  }

  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === 'host') continue;
    headerLines.push(`${k}: ${v}`);
  }

  const body = req.body || '';
  return `${method} ${path} ${httpVer}\r\n${headerLines.join('\r\n')}\r\n\r\n${body}`;
}

/**
 * Format a structured response into standard raw HTTP string
 */
export function formatRawHttpResponse(res) {
  const httpVer = res.httpVersion || 'HTTP/1.1';
  const status = res.status || res.statusCode || 200;
  const statusText = res.statusText || res.status_text || 'OK';
  const headers = res.headers || {};

  const headerLines = [];
  for (const [k, v] of Object.entries(headers)) {
    headerLines.push(`${k}: ${v}`);
  }

  const body = res.body || '';
  return `${httpVer} ${status} ${statusText}\r\n${headerLines.join('\r\n')}\r\n\r\n${body}`;
}
