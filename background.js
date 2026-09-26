const API_BASE = 'http://localhost:8000';

// Fallback local scoring (used when backend is unavailable)
function localQuickScore(data) {
  const BRAND_DOMAINS = ['paypal.com','amazon.com','microsoft.com','icicibank.com','hdfcbank.com',
    'sbi.co.in','google.com','apple.com','netflix.com','irctc.co.in'];
  const URGENCY_CUES = ['urgent','verify your account','suspended','wire transfer','click here',
    'password expires','invoice attached','act now','confidential','gift card','account will be locked'];
  
  let score = 0; const reasons = [];
  const dom = (data.sender_email || '').match(/@([\w.-]+)/)?.[1]?.toLowerCase();
  const lower = (data.sender_name || '').toLowerCase();
  
  for (const b of BRAND_DOMAINS) {
    const brand = b.split('.')[0];
    if (lower.includes(brand) && dom && dom !== b) {
      score += 30; reasons.push(`Display name references "${brand}" but domain is "${dom}".`);
      break;
    }
  }
  const text = ((data.subject || '') + ' ' + (data.body_text || '')).toLowerCase();
  const hits = URGENCY_CUES.filter(c => text.includes(c));
  if (hits.length) { score += Math.min(25, hits.length * 6); reasons.push(`Urgency language: ${hits.join(', ')}.`); }
  
  return {
    risk_score: Math.min(100, score),
    risk_level: score >= 60 ? 'HIGH' : score >= 30 ? 'MEDIUM' : 'LOW',
    reasons: reasons,
    source: 'local_fallback'
  };
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'phishtrace-analyze') {
    fetch(`${API_BASE}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(msg.data)
    })
    .then(r => r.json())
    .then(result => {
      result.source = 'backend';
      sendResponse(result);
      updateBadge(result.risk_score);
    })
    .catch(err => {
      console.warn('PhishTrace: Backend unavailable, using local scoring.', err.message);
      const fallback = localQuickScore(msg.data);
      sendResponse(fallback);
      updateBadge(fallback.risk_score);
    });
    return true; // keep channel open for async response
  }
  
  if (msg.type === 'phishtrace-open-dashboard') {
    chrome.tabs.create({ url: `${API_BASE}/dashboard` });
  }
  
  if (msg.type === 'phishtrace-result') {
    updateBadge(msg.score);
  }
});

function updateBadge(score) {
  chrome.storage.local.get({ scanned: 0, flagged: 0 }, (s) => {
    const scanned = s.scanned + 1;
    const flagged = s.flagged + (score >= 30 ? 1 : 0);
    chrome.storage.local.set({ scanned, flagged });
    if (flagged > 0) {
      chrome.action.setBadgeText({ text: String(flagged) });
      chrome.action.setBadgeBackgroundColor({ color: score >= 60 ? '#e8543c' : '#e0a940' });
    }
  });
}
