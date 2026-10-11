import { countRequests } from './db.js';

const statusDot = document.querySelector('#status .dot');
const statusText = document.getElementById('statusText');
const statTotal = document.getElementById('statTotal');
const statIntercept = document.getElementById('statIntercept');

async function refresh() {
  try {
    const res = await chrome.runtime.sendMessage({ type: 'status' });
    if (res && res.ok && res.attached) {
      statusDot.dataset.state = 'on';
      statusText.textContent = 'Attached to tab ' + res.tabId;
    } else {
      statusDot.dataset.state = 'off';
      statusText.textContent = 'Not attached';
    }

    if (res && res.ok && res.interceptEnabled) {
      statIntercept.textContent = 'ON';
      statIntercept.style.color = '#f97316';
    } else {
      statIntercept.textContent = 'OFF';
      statIntercept.style.color = '#94a3b8';
    }
  } catch (e) {
    statusDot.dataset.state = 'warn';
    statusText.textContent = 'Worker offline';
  }

  const n = await countRequests();
  statTotal.textContent = String(n);
}

document.getElementById('attachBtn').addEventListener('click', async () => {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tabs.length) return;
  const res = await chrome.runtime.sendMessage({ type: 'attach', tabId: tabs[0].id });
  if (!res || !res.ok) {
    alert('Attach failed: ' + (res && res.error || 'unknown'));
  }
  refresh();
});

document.getElementById('detachBtn').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ type: 'detach' });
  refresh();
});

document.getElementById('openLogBtn').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ type: 'open-log' });
  window.close();
});

refresh();
setInterval(refresh, 1500);