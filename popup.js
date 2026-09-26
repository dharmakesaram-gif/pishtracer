const API_BASE = 'http://localhost:8000';

function render() {
  chrome.storage.local.get({ scanned: 0, flagged: 0, enabled: true }, (s) => {
    document.getElementById('scanned').textContent = s.scanned;
    document.getElementById('flagged').textContent = s.flagged;
    document.getElementById('toggle').checked = s.enabled;
  });
  
  // Check backend status
  fetch(`${API_BASE}/api/stats`)
    .then(r => r.ok ? r.json() : Promise.reject())
    .then(() => {
      document.getElementById('statusDot').className = 'status-dot online';
      document.getElementById('statusText').textContent = 'AI Online';
    })
    .catch(() => {
      document.getElementById('statusDot').className = 'status-dot offline';
      document.getElementById('statusText').textContent = 'Local Mode';
    });
}

document.getElementById('toggle').addEventListener('change', (e) => {
  chrome.storage.local.set({ enabled: e.target.checked }, render);
});

document.getElementById('openDashboard').addEventListener('click', () => {
  chrome.runtime.sendMessage({ type: 'phishtrace-open-dashboard' });
});

document.getElementById('resetStats').addEventListener('click', () => {
  chrome.storage.local.set({ scanned: 0, flagged: 0 }, () => {
    chrome.action.setBadgeText({ text: '' });
    render();
  });
});

render();
