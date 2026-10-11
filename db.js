/**
 * Sanchit Interceptor — IndexedDB Engine
 * Copyright (c) 2026 Sanchit. All rights reserved.
 *
 * Stores:
 * - requests: HTTP exchanges
 * - repeater_tabs: Saved & active Repeater tabs
 * - websockets: WebSocket frames
 * - meta: settings, session state, scope rules
 */

const DB_NAME = 'burplite';
const DB_VERSION = 2;
const STORE_REQUESTS = 'requests';
const STORE_REPEATER = 'repeater_tabs';
const STORE_WEBSOCKETS = 'websockets';
const STORE_META = 'meta';

let _dbPromise = null;

export function openDB() {
  if (_dbPromise) return _dbPromise;
  _dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (ev) => {
      const db = req.result;

      // requests store
      if (!db.objectStoreNames.contains(STORE_REQUESTS)) {
        const store = db.createObjectStore(STORE_REQUESTS, { keyPath: 'id' });
        store.createIndex('seq', 'seq', { unique: false });
        store.createIndex('host', 'host', { unique: false });
        store.createIndex('mime_group', 'mime_group', { unique: false });
        store.createIndex('status', 'status_code', { unique: false });
        store.createIndex('method', 'method', { unique: false });
        store.createIndex('started_at', 'initiated_at', { unique: false });
      }

      // meta store
      if (!db.objectStoreNames.contains(STORE_META)) {
        db.createObjectStore(STORE_META, { keyPath: 'key' });
      }

      // repeater_tabs store
      if (!db.objectStoreNames.contains(STORE_REPEATER)) {
        db.createObjectStore(STORE_REPEATER, { keyPath: 'id' });
      }

      // websockets store
      if (!db.objectStoreNames.contains(STORE_WEBSOCKETS)) {
        const wsStore = db.createObjectStore(STORE_WEBSOCKETS, { keyPath: 'id' });
        wsStore.createIndex('requestId', 'requestId', { unique: false });
        wsStore.createIndex('timestamp', 'timestamp', { unique: false });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => {
      _dbPromise = null;
      reject(req.error);
    };
  });
  return _dbPromise;
}

// ============================================================
// Requests
// ============================================================

export async function putRequest(record) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE_REQUESTS, 'readwrite');
    t.objectStore(STORE_REQUESTS).put(record);
    t.oncomplete = () => resolve(record.id);
    t.onerror = () => reject(t.error);
  });
}

export async function bulkPutRequests(records) {
  if (!records || !records.length) return 0;
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE_REQUESTS, 'readwrite');
    const store = t.objectStore(STORE_REQUESTS);
    for (const r of records) {
      store.put(r);
    }
    t.oncomplete = () => resolve(records.length);
    t.onerror = () => reject(t.error);
  });
}

export async function getRequest(id) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE_REQUESTS, 'readonly');
    const r = t.objectStore(STORE_REQUESTS).get(id);
    r.onsuccess = () => resolve(r.result || null);
    r.onerror = () => reject(r.error);
  });
}

export async function getAllRequests() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE_REQUESTS, 'readonly');
    const r = t.objectStore(STORE_REQUESTS).getAll();
    r.onsuccess = () => {
      const arr = r.result || [];
      arr.sort((a, b) => a.seq - b.seq);
      resolve(arr);
    };
    r.onerror = () => reject(r.error);
  });
}

export async function deleteRequest(id) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE_REQUESTS, 'readwrite');
    t.objectStore(STORE_REQUESTS).delete(id);
    t.oncomplete = () => resolve();
    t.onerror = () => reject(t.error);
  });
}

export async function clearAllRequests() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE_REQUESTS, 'readwrite');
    t.objectStore(STORE_REQUESTS).clear();
    t.oncomplete = () => resolve();
    t.onerror = () => reject(t.error);
  });
}

export async function countRequests() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE_REQUESTS, 'readonly');
    const r = t.objectStore(STORE_REQUESTS).count();
    r.onsuccess = () => resolve(r.result || 0);
    r.onerror = () => reject(r.error);
  });
}

export async function getMaxSeq() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE_REQUESTS, 'readonly');
    const idx = t.objectStore(STORE_REQUESTS).index('seq');
    const r = idx.openCursor(null, 'prev');
    r.onsuccess = () => {
      const cur = r.result;
      resolve(cur ? cur.key : 0);
    };
    r.onerror = () => reject(r.error);
  });
}

// ============================================================
// Repeater Tabs
// ============================================================

export async function saveRepeaterTab(tab) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE_REPEATER, 'readwrite');
    t.objectStore(STORE_REPEATER).put(tab);
    t.oncomplete = () => resolve(tab.id);
    t.onerror = () => reject(t.error);
  });
}

export async function getAllRepeaterTabs() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE_REPEATER, 'readonly');
    const r = t.objectStore(STORE_REPEATER).getAll();
    r.onsuccess = () => resolve(r.result || []);
    r.onerror = () => reject(r.error);
  });
}

export async function deleteRepeaterTab(id) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE_REPEATER, 'readwrite');
    t.objectStore(STORE_REPEATER).delete(id);
    t.oncomplete = () => resolve();
    t.onerror = () => reject(t.error);
  });
}

// ============================================================
// WebSockets
// ============================================================

export async function putWebSocketFrame(frame) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE_WEBSOCKETS, 'readwrite');
    t.objectStore(STORE_WEBSOCKETS).put(frame);
    t.oncomplete = () => resolve(frame.id);
    t.onerror = () => reject(t.error);
  });
}

export async function getAllWebSocketFrames() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE_WEBSOCKETS, 'readonly');
    const r = t.objectStore(STORE_WEBSOCKETS).getAll();
    r.onsuccess = () => {
      const arr = r.result || [];
      arr.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
      resolve(arr);
    };
    r.onerror = () => reject(r.error);
  });
}

export async function clearAllWebSocketFrames() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE_WEBSOCKETS, 'readwrite');
    t.objectStore(STORE_WEBSOCKETS).clear();
    t.oncomplete = () => resolve();
    t.onerror = () => reject(t.error);
  });
}

// ============================================================
// Meta (Settings, Scope, Session)
// ============================================================

export async function setMeta(key, value) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE_META, 'readwrite');
    t.objectStore(STORE_META).put({ key, value });
    t.oncomplete = () => resolve();
    t.onerror = () => reject(t.error);
  });
}

export async function getMeta(key, fallback = null) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE_META, 'readonly');
    const r = t.objectStore(STORE_META).get(key);
    r.onsuccess = () => resolve(r.result ? r.result.value : fallback);
    r.onerror = () => reject(r.error);
  });
}