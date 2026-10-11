import { setMeta, getMeta } from './db.js';

const DEFAULTS = {
  maxEntries: 5000,
};

const maxEntriesInput = document.getElementById('maxEntries');
const savedMsg = document.getElementById('savedMsg');

async function load() {
  const cfg = await getMeta('settings', DEFAULTS);
  const merged = { ...DEFAULTS, ...(cfg || {}) };
  maxEntriesInput.value = String(merged.maxEntries);
}

document.getElementById('saveBtn').addEventListener('click', async () => {
  const maxEntries = Math.max(100, Math.min(100000, parseInt(maxEntriesInput.value, 10) || DEFAULTS.maxEntries));
  await setMeta('settings', { maxEntries });
  savedMsg.classList.add('show');
  setTimeout(() => savedMsg.classList.remove('show'), 1400);
});

document.getElementById('resetBtn').addEventListener('click', async () => {
  await setMeta('settings', DEFAULTS);
  await load();
});

load();