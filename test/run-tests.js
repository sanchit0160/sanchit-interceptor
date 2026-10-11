/**
 * Sanchit Interceptor — Test Suite
 * Copyright (c) 2026 Sanchit. All rights reserved.
 *
 * Verifies:
 * 1. HTTP parser & serializer
 * 2. .sanchit Project format creation & parsing
 * 3. Burp XML / .burp import & export
 * 4. HAR 1.2 import & export
 * 5. Crypto utils (URL, Base64, Hex, HTML, MD5, JWT, Format detection)
 * 6. Diff Engine & Comparer
 */

import {
  parseRawHttpRequest, parseRawHttpResponse,
  formatRawHttpRequest, formatRawHttpResponse
} from '../core/http-parser.js';

import {
  createSanchitProject, parseSanchitProject,
  SANCHIT_MAGIC, SANCHIT_FORMAT_VERSION
} from '../core/sanchit-format.js';

import {
  parseBurpXml, exportBurpXml,
  safeBase64Decode, safeBase64Encode
} from '../core/burp-xml-parser.js';

import {
  parseHar, exportHar
} from '../core/har-parser.js';

import {
  urlEncode, urlDecode, base64Encode, base64Decode,
  hexEncode, hexDecode, htmlEncode, htmlDecode,
  inspectJwt, md5, detectFormat
} from '../core/crypto-utils.js';

import {
  computeDiff, diffWords, formatHexDumpLines
} from '../core/diff-engine.js';

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    passed++;
    console.log(`  ✓ ${message}`);
  } else {
    failed++;
    console.error(`  ✗ FAIL: ${message}`);
  }
}

function runSection(name, fn) {
  console.log(`\n=== Testing: ${name} ===`);
  try {
    fn();
  } catch (e) {
    failed++;
    console.error(`  ✗ UNCAUGHT ERROR in ${name}:`, e);
  }
}

// 1. HTTP Parser
runSection('HTTP Parser & Serializer', () => {
  const rawReq = `POST /api/v1/auth?client=web HTTP/1.1\r\nHost: api.test.com\r\nContent-Type: application/json\r\nAuthorization: Bearer secret123\r\n\r\n{"username":"admin","password":"password123"}`;
  const parsed = parseRawHttpRequest(rawReq);

  assert(parsed.method === 'POST', 'Method is POST');
  assert(parsed.rawPath === '/api/v1/auth?client=web', 'Path and query matches');
  assert(parsed.fullUrl === 'https://api.test.com/api/v1/auth?client=web', 'Full URL reconstructed using Host header');
  assert(parsed.headers['Host'] === 'api.test.com', 'Host header extracted');
  assert(parsed.headers['Authorization'] === 'Bearer secret123', 'Auth header extracted');
  assert(parsed.body === '{"username":"admin","password":"password123"}', 'Body extracted correctly');

  const rawRes = `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nServer: nginx\r\n\r\n{"token":"jwt.xyz"}`;
  const parsedRes = parseRawHttpResponse(rawRes);
  assert(parsedRes.statusCode === 200, 'Status code is 200');
  assert(parsedRes.statusText === 'OK', 'Status text is OK');
  assert(parsedRes.headers['Server'] === 'nginx', 'Server header extracted');
  assert(parsedRes.body === '{"token":"jwt.xyz"}', 'Response body extracted');

  const formatted = formatRawHttpRequest({
    method: 'GET',
    path: '/users',
    query: { page: '1' },
    host: 'example.com',
    headers: { 'Accept': 'application/json' },
    body: '',
  });
  assert(formatted.includes('GET /users?page=1 HTTP/1.1'), 'Formatted raw HTTP request line');
  assert(formatted.includes('Host: example.com'), 'Formatted Host header');
});

// 2. .sanchit Project Format
runSection('.sanchit Project Format Engine', () => {
  const mockRequests = [
    {
      id: 'req_1',
      seq: 1,
      url: 'https://target.com/api/login',
      method: 'POST',
      host: 'target.com',
      path: '/api/login',
      status_code: 200,
      status_text: 'OK',
      mime_group: 'json',
      notes: 'Initial test vector',
      request: {
        headers: { 'Content-Type': 'application/json' },
        body: '{"user":"test"}',
      },
      response: {
        status: 200,
        headers: { 'Set-Cookie': 'session=abc' },
        body: '{"success":true}',
        body_size: 16,
      }
    }
  ];

  const project = createSanchitProject({
    projectName: 'Pentest Sanchit Target',
    requests: mockRequests,
    repeaterTabs: [{ id: 'rep_1', name: 'Tab 1', url: 'https://target.com', requestText: 'GET / HTTP/1.1\r\n\r\n' }],
    scopeRules: { include: ['*.target.com'], exclude: [] },
  });

  assert(project.magic === SANCHIT_MAGIC, 'Project has SANCHIT_BURP_PROJECT_V1 magic signature');
  assert(project.version === SANCHIT_FORMAT_VERSION, 'Project version matches 1.0.0');
  assert(project.project_name === 'Pentest Sanchit Target', 'Project name preserved');
  assert(project.summary.request_count === 1, 'Summary request count is 1');
  assert(project.summary.hosts.includes('target.com'), 'Summary hosts includes target.com');

  const jsonStr = JSON.stringify(project);
  const parsed = parseSanchitProject(jsonStr);

  assert(parsed.projectName === 'Pentest Sanchit Target', 'Parsed project name matches');
  assert(parsed.requests.length === 1, 'Parsed requests count is 1');
  assert(parsed.requests[0].notes === 'Initial test vector', 'User notes preserved in .sanchit format');
  assert(parsed.repeaterTabs.length === 1, 'Repeater tabs restored');
  assert(parsed.scopeRules.include.includes('*.target.com'), 'Scope rules restored');
});

// 3. Burp XML / .burp Parser & Exporter
runSection('Burp Suite XML (.burp) Parser & Exporter', () => {
  const sampleBurpXml = `<?xml version="1.0"?>
<items burpVersion="2026.1" exportDate="Sun Oct 11 12:00:00 UTC 2026">
  <item>
    <time>Sun Oct 11 12:00:00 UTC 2026</time>
    <url>https://target.corp/api/v1/test</url>
    <host ip="10.0.0.1">target.corp</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>POST</method>
    <path>/api/v1/test</path>
    <extension>null</extension>
    <request base64="true">${safeBase64Encode('POST /api/v1/test HTTP/1.1\r\nHost: target.corp\r\nContent-Type: application/json\r\n\r\n{"data":"test"}')}</request>
    <status>200</status>
    <responselength>45</responselength>
    <mimetype>JSON</mimetype>
    <response base64="true">${safeBase64Encode('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"status":"ok"}')}</response>
    <comment>Crucial endpoint</comment>
  </item>
</items>`;

  const burpParsed = parseBurpXml(sampleBurpXml);
  assert(burpParsed.count === 1, 'Burp items parsed count is 1');
  const req = burpParsed.requests[0];
  assert(req.url === 'https://target.corp/api/v1/test', 'URL parsed correctly');
  assert(req.method === 'POST', 'Method parsed correctly');
  assert(req.host === 'target.corp', 'Host parsed correctly');
  assert(req.status_code === 200, 'Status code parsed correctly');
  assert(req.request.body === '{"data":"test"}', 'Decoded base64 request body correctly');
  assert(req.response.body === '{"status":"ok"}', 'Decoded base64 response body correctly');
  assert(req.notes === 'Crucial endpoint', 'Burp comment mapped to notes');

  // Test Export
  const exportedXml = exportBurpXml(burpParsed.requests);
  assert(exportedXml.includes('<items burpVersion="2026.1"'), 'Exported XML contains items header');
  assert(exportedXml.includes('<url>https://target.corp/api/v1/test</url>'), 'Exported XML contains URL');
  assert(exportedXml.includes('base64="true"'), 'Exported XML base64 encoded payloads');
});

// 4. HAR 1.2 Parser & Exporter
runSection('HAR 1.2 Parser & Exporter', () => {
  const sampleHar = {
    log: {
      version: '1.2',
      entries: [
        {
          startedDateTime: '2026-10-11T12:00:00.000Z',
          time: 85,
          request: {
            method: 'GET',
            url: 'https://api.github.com/user',
            headers: [{ name: 'Authorization', value: 'token ghp_123' }],
            cookies: [],
          },
          response: {
            status: 200,
            statusText: 'OK',
            headers: [{ name: 'Content-Type', value: 'application/json' }],
            content: {
              size: 24,
              mimeType: 'application/json',
              text: '{"login":"sanchit0160"}',
            }
          }
        }
      ]
    }
  };

  const parsedHar = parseHar(sampleHar);
  assert(parsedHar.count === 1, 'HAR parsed entries is 1');
  assert(parsedHar.requests[0].url === 'https://api.github.com/user', 'HAR URL matches');
  assert(parsedHar.requests[0].response.body === '{"login":"sanchit0160"}', 'HAR response body matches');

  const reExported = exportHar(parsedHar.requests);
  assert(reExported.log.version === '1.2', 'HAR re-exported with version 1.2');
  assert(reExported.log.entries.length === 1, 'HAR re-exported with 1 entry');
});

// 5. Crypto, Encoder, Decoder & JWT
runSection('Crypto & Decoder Engine', () => {
  // URL
  const testUrl = 'admin & user=100%';
  assert(urlDecode(urlEncode(testUrl, true)) === testUrl, 'URL Encode -> Decode roundtrip');

  // Base64
  const testB64 = 'Secret $ymbols & 🚀 emoji UTF-8 test';
  assert(base64Decode(base64Encode(testB64)) === testB64, 'Base64 UTF-8 multibyte roundtrip');

  // Hex
  const testHex = 'ABC';
  const encodedHex = hexEncode(testHex);
  assert(encodedHex === '41 42 43', 'Hex encoding matches 41 42 43');
  assert(hexDecode(encodedHex) === testHex, 'Hex decode matches ABC');

  // HTML
  assert(htmlEncode('<div>"hello" & \'world\'</div>').includes('&lt;div&gt;'), 'HTML encoding');

  // MD5
  assert(md5('hello') === '5d41402abc4b2a76b9719d911017c592', 'MD5 of "hello" matches known hash');
  assert(md5('sanchit') === '94398c93c2370b9426d0c7588d9d79ec', 'MD5 of "sanchit" calculated');

  // JWT
  // Sample JWT: { alg: "HS256", typ: "JWT" } . { sub: "1234567890", name: "Sanchit", iat: 1516239022, exp: 9999999999 }
  const mockJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlNhbmNoaXQiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6OTk5OTk5OTk5OX0.dummy_sig';
  const jwtAnalysis = inspectJwt(mockJwt);
  assert(jwtAnalysis.isValidJwt === true, 'JWT detected and verified as valid');
  assert(jwtAnalysis.header.alg === 'HS256', 'JWT algorithm is HS256');
  assert(jwtAnalysis.payload.name === 'Sanchit', 'JWT payload name is Sanchit');
  assert(jwtAnalysis.claims.expiration.isExpired === false, 'JWT future expiration detected as valid');

  // Format Detection
  assert(detectFormat(mockJwt).includes('jwt'), 'Format detector recognizes JWT');
  assert(detectFormat('SGVsbG8gV29ybGQ=').includes('base64'), 'Format detector recognizes Base64');
  assert(detectFormat('41 42 43 44').includes('hex'), 'Format detector recognizes Hex');
  assert(detectFormat('%20%2F%3F').includes('url'), 'Format detector recognizes URL encoding');
});

// 6. Diff Engine (Comparer)
runSection('Diff Engine & Comparer Suite', () => {
  // Word Diff
  const wd = diffWords('GET /api/user?id=1 HTTP/1.1', 'GET /api/user?id=2 HTTP/1.1');
  assert(wd.wordsA.length > 0 && wd.wordsB.length > 0, 'diffWords produces token arrays');
  const changedA = wd.wordsA.find(w => w.type === 'delete');
  const changedB = wd.wordsB.find(w => w.type === 'insert');
  assert(changedA && changedA.text === '1', 'diffWords identifies deleted word "1"');
  assert(changedB && changedB.text === '2', 'diffWords identifies inserted word "2"');

  // Identical comparison
  const sameA = 'Line 1\nLine 2\nLine 3';
  const diffIdentical = computeDiff(sameA, sameA);
  assert(diffIdentical.stats.similarity === 100, 'Identical strings have 100% similarity');
  assert(diffIdentical.stats.additions === 0, '0 additions on identical diff');
  assert(diffIdentical.stats.deletions === 0, '0 deletions on identical diff');
  assert(diffIdentical.stats.modifications === 0, '0 modifications on identical diff');

  // Line & Word diff with modifications
  const docA = 'Host: example.com\nAuthorization: Bearer token1\nContent-Type: text/plain';
  const docB = 'Host: example.com\nAuthorization: Bearer token2\nContent-Type: text/plain';
  const diffWordsResult = computeDiff(docA, docB, { mode: 'words' });
  assert(diffWordsResult.stats.modifications === 1, '1 modification found');
  const modRow = diffWordsResult.rows.find(r => r.type === 'modify');
  assert(modRow && modRow.wordDiffA && modRow.wordDiffB, 'Modified row has wordDiff breakdown');

  // Ignore Whitespace
  const wsA = 'GET /index.html   HTTP/1.1';
  const wsB = 'GET /index.html HTTP/1.1';
  const diffWs = computeDiff(wsA, wsB, { ignoreWhitespace: true });
  assert(diffWs.stats.similarity === 100, 'Whitespace ignored successfully');

  // Ignore Case
  const caseA = 'Authorization: Bearer secret';
  const caseB = 'authorization: bearer SECRET';
  const diffCase = computeDiff(caseA, caseB, { ignoreCase: true });
  assert(diffCase.stats.similarity === 100, 'Letter case ignored successfully');

  // Byte / Hex Dump Diff
  const hexDump = formatHexDumpLines('HELLO WORLD');
  assert(hexDump.includes('48 45 4c 4c 4f'), 'formatHexDumpLines produces correct hex representation');
  const byteDiff = computeDiff('HELLO WORLD 1', 'HELLO WORLD 2', { mode: 'bytes' });
  assert(byteDiff.rows.length > 0, 'Byte diff mode generates aligned hex diff rows');
});

console.log(`\n========================================`);
console.log(`Test Results: ${passed} PASSED, ${failed} FAILED`);
console.log(`========================================\n`);

if (failed > 0) {
  process.exit(1);
}
