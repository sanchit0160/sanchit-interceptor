# Sanchit Interceptor — Web Security Workbench & HTTP Proxy

[![License: MIT](https://img.shields.io/badge/License-MIT-amber.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-orange.svg)](manifest.json)
[![Author](https://img.shields.io/badge/author-Sanchit-blue.svg)](#author--copyright)

> **Sanchit Interceptor** is a browser-based web security workbench and HTTP proxy extension built on Chrome Manifest V3 and Chrome DevTools Protocol (`CDP`). It brings the core toolset of desktop security suites (Burp Suite Pro) directly inside Chromium browsers with native **`.sanchit`** project storage and bi-directional **`.burp` / `.xml`** import & export compatibility.

---

## ⚡ Key Highlights

* **100% In-Browser Execution**: Runs directly inside Chrome, Brave, and Edge using `chrome.debugger` — no local proxy certificates, CA trust installations, or desktop Java runtimes required.
* **Native `.sanchit` Project Container**: Full workspace serialization with Gzip compression, CRC32 verification, captured traffic, user notes, Repeater tabs, site maps, and scope definitions.
* **Burp Suite XML Bi-Directional Portability**: Seamlessly drag & drop desktop Burp Suite exports (`.burp` / `.xml`) with automatic Base64 payload decoding, and export captured sessions back to Burp Suite XML format.
* **CORS-Bypassing Repeater**: Issue custom HTTP requests across any origin via background service worker privilege (`<all_urls>`).
* **LCS Comparer Suite**: Diff HTTP requests, responses, and arbitrary strings word-by-word, line-by-line, and byte-by-byte with synchronized dual-pane scrolling and difference jumping (`F7`).
* **Dedicated Raw HTTP Streams**: Separate inspection of unadulterated Raw Request and Raw Response wire formats with one-click copy.
* **Deep Decoder & JWT Inspector**: Multi-tier encoding/decoding chains (URL, Base64, Hex, HTML), hash generators (MD5, SHA-1, SHA-256, SHA-512), and live JWT claims with expiration detection.

---

## 🧰 The Toolset

### 1. ⚡ Proxy & Traffic History
* **Live HTTP History**: Real-time traffic monitor indexing sequence numbers, methods, URLs, status codes, hosts, MIME groups, sizes, and duration.
* **Deep Search Engine**: Full-text regex search scanning URLs, hosts, paths, status codes, user notes, headers, AND **request & response payload bodies**.
* **Segmented Inspector Bar**:
  * **REQ Group**: `Headers` (Key-Value table) | `Body` (formatted) | `Raw` (Raw HTTP request wire stream).
  * **RES Group**: `Headers` (Key-Value table) | `Body` (formatted) | `Raw` (Raw HTTP response wire stream).
  * **Analysis Group**: `Cookies` (Request & Set-Cookie breakdown) | `Timing` (DNS, SSL, Connect, Wait, Receive waterfall).
  * **Viewers Group**: `Hex` (16-byte hex dump) | `Preview` (Sandboxed HTML browser render).
* **Live WebSocket Monitor**: Real-time interception and logging of inbound and outbound WebSocket frames (`Network.webSocket*`).
* **Binary Preservation**: Preserves binary bodies (images, media, PDFs, binary APIs) via safe Base64 storage.

### 2. 🛑 Intercept (Live Request & Response Tampering)
* **Real-Time Pausing**: Pauses live in-flight requests before transmission using CDP `Fetch.enable`.
* **Tamper & Forward**: Modify target URL, HTTP method, request headers, and payload body on the fly before forwarding.
* **Drop Request**: Drop malicious or unwanted transmissions to simulate network failure or test client handling.
* **Intercept Toggle**: Instant global intercept switch with live pulse indicator.

### 3. 🔄 Repeater
* **Tabbed Crafter**: Create, rename, duplicate, and manage multiple request tabs.
* **1-Click Send**: Dispatch custom requests straight from History, Site Map, or Comparer (`Ctrl+R`).
* **CORS-Bypass Engine**: Extension-level background dispatch bypassing Same-Origin Policy (`SOP`) restrictions.
* **Response Inspector**: View response status codes, timing metrics, size, formatted JSON, raw headers, and sandboxed HTML rendering.
* **Comparer Connectors**: Dedicated `⚖️ Compare Req` and `⚖️ Compare Res` buttons to send Repeater payloads directly to Comparer.

### 4. 🔤 Decoder & JWT Inspector
* **Multi-Transformations**: URL encode/decode, Base64 encode/decode, Hex encode/decode, HTML entity encode/decode.
* **JWT Analyzer**: Live parsing of Header & Payload claims with color-coded expiration validation banner (`valid` vs `expired`).
* **Cryptographic Hashes**: Pure JavaScript calculation of MD5, SHA-1, SHA-256, and SHA-512.
* **Smart Format Detector**: Auto-identifies JWT, Base64, Hex, URL, and JSON formats as you type.

### 5. 🎯 Target & Site Map
* **Hierarchical Tree**: Automatically organizes discovered hosts, directory trees, endpoints, and query parameters.
* **Target Scope Engine**: Configure target scope using domain wildcards (e.g. `*.target.com`) or full regex rules.
* **In-Scope Filter**: 1-click toggle to eliminate third-party tracking, analytics, and CDNs from the history view.

### 6. ⚖️ Comparer (Diff Engine)
* **Word-Level Diffing**: Tokenizes lines using Longest Common Subsequence (`LCS`) to highlight exact parameter and token differences (CSRF tokens, session IDs, response lengths).
* **Compare Modes**:
  * **Compare Words**: Highlights changed tokens within modified lines.
  * **Compare Lines**: Line-by-line diffing.
  * **Compare Bytes**: Converts inputs to 16-byte hex dumps and highlights byte-level modifications.
* **Synchronized Dual-Pane Scrolling**: Side-by-side split view locking vertical & horizontal scroll positions with gap alignment.
* **Unified Diff View**: Inline Git-style diff view.
* **Difference Navigation**: Jump through differences with `▲ Prev Diff` / `▼ Next Diff` or keyboard shortcuts (`F7` / `Shift+F7`).
* **History Slot Loaders**: Dropdown selectors to load full exchanges, requests only, responses only, or payload bodies into Slot A or Slot B.

---

## 💾 Project Formats: `.sanchit` & `.burp`

### Native `.sanchit` Project Container
* **Specification**: Bundles project metadata, request/response history, headers, bodies, cookies, timing, user notes, active Repeater tabs, site map, and scope rules under magic signature `SANCHIT_BURP_PROJECT_V1`.
* **Save**: Click **Save .sanchit** in the topbar or press `Ctrl+S`.
* **Load**: Click **Load File** or press `Ctrl+O`.

### Burp Suite `.burp` / `.xml` Compatibility
* **Import**: Drag and drop any Burp Suite XML export (often saved as `.burp` or `.xml`). Decodes Base64 request/response tags and reconstructs full HTTP exchanges.
* **Export**: Click **Export ▾ -> Export Burp XML (.burp)** to export captured browser traffic back into Burp Suite!

### HAR 1.2 & JSON Support
* Fully compatible with standard `.har` (HTTP Archive 1.2) files and JSON captures.

---

## ⌨️ Keyboard Shortcuts

| Shortcut | Action |
| :--- | :--- |
| `Ctrl+R` / `Cmd+R` | Send selected request to Repeater |
| `Ctrl+S` / `Cmd+S` | Save complete session as `.sanchit` project |
| `Ctrl+O` / `Cmd+O` | Open Load File modal |
| `Ctrl+F` / `Cmd+F` | Focus search filter bar |
| `F7` / `ArrowDown` | Next difference (in Comparer view) |
| `Shift+F7` / `ArrowUp` | Previous difference (in Comparer view) |
| `ArrowUp` / `ArrowDown` | Navigate request history rows |
| `Right Click` (Row) | Open custom context menu |
| `Escape` | Close active modal, dropdown, or context menu |

---

## 📦 How to Install & Run

1. Open Google Chrome (or Brave / Edge) and navigate to `chrome://extensions/`.
2. Toggle on **Developer mode** in the top-right corner.
3. Click **Load unpacked** in the top-left corner.
4. Select the directory: `c:\Users\sanchit0160\Documents\extenstions\burp-lite`.
5. Click the **Sanchit Interceptor** icon in the browser toolbar and click **Open Sanchit Interceptor**.
6. Click **Attach** to attach the debugger to any active tab, or click **Load File** to inspect pre-recorded `.sanchit`, `.burp`, or `.har` captures.

---

## 🧪 Automated Test Suite

Verify all core engines with Node.js:
```bash
node test/run-tests.js
```
The test suite validates:
- HTTP request/response parsing and raw formatting
- `.sanchit` project container serialization and checksum verification
- Burp Suite XML (`.burp`) bidirectional parsing and Base64 preservation
- HAR 1.2 import/export
- Cryptographic hash engines (MD5, SHA-1/256/512) and JWT claims inspector
- Advanced LCS Diff Engine (word diff, line diff, byte diff, whitespace/case handling)

---

## 📄 Author & Copyright

**Sanchit Interceptor**
Created & Maintained by **Sanchit**.

Copyright &copy; 2026 Sanchit. All rights reserved.

Distributed under the [MIT License](LICENSE).
