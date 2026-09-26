// PhishTrace v2.0 Enterprise Content Script — Gmail Defense Shield
// Integrates with FastAPI backend for deep AI Threat Forensics

function domainOf(addr) { 
  const m = (addr || "").match(/@([\w.-]+)/); 
  return m ? m[1].toLowerCase() : null; 
}

// ---------- Enterprise Security Warning Banner ----------
function makeBanner(result) {
  const score = result.risk_score || result.score || 0;
  
  let borderColor = '#10b981';
  let bgColor = 'rgba(16, 185, 129, 0.06)';
  let tagBg = 'rgba(16, 185, 129, 0.15)';
  let tagText = '#059669';
  let levelName = 'VERIFIED SAFE';
  let iconSvg = '🛡️';

  if (score >= 80) {
    borderColor = '#ef4444';
    bgColor = 'rgba(239, 68, 68, 0.08)';
    tagBg = '#fef2f2';
    tagText = '#b91c1c';
    levelName = 'CRITICAL PHISHING RISK';
    iconSvg = '🚨';
  } else if (score >= 60) {
    borderColor = '#f97316';
    bgColor = 'rgba(249, 115, 22, 0.08)';
    tagBg = '#fff7ed';
    tagText = '#c2410c';
    levelName = 'HIGH THREAT SUSPICION';
    iconSvg = '⚠️';
  } else if (score >= 30) {
    borderColor = '#f59e0b';
    bgColor = 'rgba(245, 158, 11, 0.08)';
    tagBg = '#fffbeb';
    tagText = '#b45309';
    levelName = 'CAUTION ADVISED';
    iconSvg = '⚡';
  }

  const div = document.createElement('div');
  div.setAttribute('data-phishtrace-banner', '1');
  div.style.cssText = `
    margin: 12px 0 16px 0;
    padding: 14px 18px;
    border-radius: 12px;
    border: 1px solid ${borderColor}55;
    border-left: 6px solid ${borderColor};
    background: ${bgColor};
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    color: #1e293b;
    box-shadow: 0 4px 15px -2px rgba(0,0,0,0.06);
    position: relative;
  `;

  let html = `
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
      <div style="display: flex; align-items: center; gap: 8px;">
        <span style="font-size: 18px;">${iconSvg}</span>
        <b style="font-size: 14px; letter-spacing: -0.01em; color: ${tagText};">
          PhishTrace Shield: ${levelName} (${score}/100)
        </b>
      </div>
      <span style="font-size: 11px; font-weight: 700; color: #475569; background: #e2e8f0; padding: 3px 9px; border-radius: 9999px; text-transform: uppercase;">
        ${result.source === 'backend' ? '🤖 AI Engine' : '⚡ Local Sensor'}
      </span>
    </div>
  `;

  // Detected Threat Reasons
  const reasons = result.reasons || [];
  if (reasons.length) {
    html += `<div style="margin: 6px 0 10px 0; font-size: 12.5px; color: #334155; line-height: 1.5;">`;
    reasons.forEach(r => {
      const text = typeof r === 'string' ? r : (r.detail || r.message || JSON.stringify(r));
      html += `<div style="display: flex; gap: 6px; margin: 3px 0;"><span>•</span><span>${text}</span></div>`;
    });
    html += `</div>`;
  }

  // Header Authentication Chips & Geo
  const hf = result.header_forensics;
  const geo = result.geo_data;
  if (hf || geo) {
    html += `<div style="display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 10px; font-size: 11.5px; color: #475569;">`;
    if (hf) {
      html += `
        <span style="background: white; border: 1px solid #cbd5e1; padding: 2px 8px; border-radius: 6px;">
          SPF: ${authChip(hf.spf)}
        </span>
        <span style="background: white; border: 1px solid #cbd5e1; padding: 2px 8px; border-radius: 6px;">
          DKIM: ${authChip(hf.dkim)}
        </span>
        <span style="background: white; border: 1px solid #cbd5e1; padding: 2px 8px; border-radius: 6px;">
          DMARC: ${authChip(hf.dmarc)}
        </span>
      `;
    }
    if (geo && geo.country) {
      html += `
        <span style="background: white; border: 1px solid #cbd5e1; padding: 2px 8px; border-radius: 6px;">
          📍 Origin: <b>${geo.city || '?'}, ${geo.country}</b> ${geo.infra_type && geo.infra_type !== 'RESIDENTIAL' ? `(${geo.infra_type})` : ''}
        </span>
      `;
    }
    html += `</div>`;
  }

  // Interactive CTAs
  html += `<div style="display: flex; gap: 10px; margin-top: 10px;">`;
  if (result.scan_id) {
    html += `
      <button onclick="window.open('http://localhost:8000/dashboard/')" 
        style="background: #0284c7; color: white; border: none; border-radius: 6px; padding: 6px 14px; font-size: 12px; font-weight: 700; cursor: pointer; display: flex; align-items: center; gap: 5px; box-shadow: 0 2px 6px rgba(2,132,199,0.3);">
        🔍 Open in SOC Radar
      </button>
      <button onclick="window.open('http://localhost:8000/api/scans/${result.scan_id}/report?format=pdf')" 
        style="background: white; color: #334155; border: 1px solid #cbd5e1; border-radius: 6px; padding: 6px 12px; font-size: 12px; font-weight: 600; cursor: pointer;">
        📄 Export PDF Dossier
      </button>
    `;
  }
  html += `</div>`;

  div.innerHTML = html;
  return div;
}

function authChip(val) {
  if (!val) return '<span style="color:#94a3b8">—</span>';
  const pass = val.toLowerCase() === 'pass';
  return `<span style="color:${pass ? '#10b981' : '#ef4444'}; font-weight: 700;">${val.toUpperCase()}</span>`;
}

// ---------- Scan Messages in Reading Pane ----------
function scanOpenMessages() {
  document.querySelectorAll('.adn.ads').forEach(msg => {
    if (msg.getAttribute('data-phishtrace-scanned')) return;
    const senderEl = msg.querySelector('.gD');
    const subjectEl = document.querySelector('.hP');
    const bodyEl = msg.querySelector('.a3s.aiL');
    if (!senderEl) return;
    msg.setAttribute('data-phishtrace-scanned', '1');

    const senderName = senderEl.getAttribute('name') || senderEl.textContent;
    const senderEmail = senderEl.getAttribute('email') || '';
    const subject = subjectEl ? subjectEl.textContent : '';
    const bodyText = bodyEl ? bodyEl.textContent.slice(0, 3000) : '';

    chrome.runtime.sendMessage({
      type: 'phishtrace-analyze',
      data: {
        sender_name: senderName,
        sender_email: senderEmail,
        subject: subject,
        body_text: bodyText
      }
    }, (result) => {
      if (chrome.runtime.lastError || !result) return;
      const banner = makeBanner(result);
      if (msg.parentElement) {
        msg.parentElement.insertBefore(banner, msg);
      }
    });
  });
}

// ---------- Forensic Scan of Raw Source ("Show original") ----------
function headerFrom(text, name) {
  const re = new RegExp('^' + name + ':\\s*(.*(?:\\n[ \\t].*)*)', 'im');
  const m = text.match(re);
  return m ? m[1].replace(/\n[ \t]+/g, ' ').trim() : null;
}
function allHeadersFrom(text, name) {
  const re = new RegExp('^' + name + ':\\s*(.*(?:\\n[ \\t].*)*)', 'img');
  return [...text.matchAll(re)].map(m => m[1].replace(/\n[ \t]+/g, ' ').trim());
}

function scanRawSource() {
  if (document.getElementById('phishtrace-forensic-panel')) return;
  const text = document.body.innerText || '';
  if (!/^Delivered-To:|^Received:|^Return-Path:/im.test(text)) return;

  const from = headerFrom(text, 'From'), returnPath = headerFrom(text, 'Return-Path');
  const fromDom = domainOf(from), rpDom = domainOf(returnPath);
  const subject = headerFrom(text, 'Subject') || '';
  const auth = headerFrom(text, 'Authentication-Results') || '';
  const spf = /spf=(\w+)/i.exec(auth), dkim = /dkim=(\w+)/i.exec(auth), dmarc = /dmarc=(\w+)/i.exec(auth);
  const received = allHeadersFrom(text, 'Received').reverse();
  const ips = received.map(r => { const m = r.match(/\[?(\d{1,3}(?:\.\d{1,3}){3})\]?/); return m ? m[1] : null; }).filter(Boolean);
  const originIp = ips.find(ip => !ip.startsWith('192.168.') && !ip.startsWith('10.') && !ip.startsWith('127.')) || ips[0];

  let score = 0; const lines = [];
  if (rpDom && fromDom && rpDom !== fromDom) { score += 25; lines.push(`Return-Path (${rpDom}) ≠ From domain (${fromDom})`); }
  [['SPF', spf], ['DKIM', dkim], ['DMARC', dmarc]].forEach(([label, m]) => {
    if (m && m[1].toLowerCase() !== 'pass') { score += 15; lines.push(`${label} Authentication: ${m[1]}`); }
  });

  const panel = document.createElement('div');
  panel.id = 'phishtrace-forensic-panel';
  panel.style.cssText = `
    position: sticky; top: 0; z-index: 9999;
    background: #090d16; color: #f1f5f9;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    padding: 16px 24px; border-bottom: 3px solid #38bdf8;
    box-shadow: 0 10px 30px rgba(0,0,0,0.6); margin-bottom: 20px;
  `;

  panel.innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 8px;">
      <div style="display:flex; align-items:center; gap:8px;">
        <span style="font-size:20px;">🔬</span>
        <b style="font-size: 15px; color: #38bdf8; letter-spacing: -0.01em;">PhishTrace Forensic Header Deconstruction</b>
      </div>
      <span style="font-size: 11px; background: rgba(56,189,248,0.15); color: #38bdf8; padding: 3px 10px; border-radius: 9999px; font-weight: 700; border: 1px solid rgba(56,189,248,0.3);">
        THREAT INDEX: ${Math.min(100, score)}/100
      </span>
    </div>
    <div style="font-size: 13px; color: #94a3b8; line-height: 1.6;">
      From Domain: <code style="color: #f8fafc; background: rgba(255,255,255,0.08); padding: 2px 6px; border-radius: 4px;">${fromDom || '—'}</code> · 
      Return-Path: <code style="color: #f8fafc; background: rgba(255,255,255,0.08); padding: 2px 6px; border-radius: 4px;">${rpDom || '—'}</code><br>
      Probable Relay Origin IP: <code style="color: #38bdf8; background: rgba(56,189,248,0.1); padding: 2px 6px; border-radius: 4px;">${originIp || 'Not found'}</code> 
      (${ips.length} relay hops traversed)
      ${lines.length ? `<div style="margin-top:6px; color:#fca5a5;">${lines.map(l => '• ' + l).join('<br>')}</div>` : ''}
    </div>
  `;

  document.body.insertBefore(panel, document.body.firstChild);
}

// ---------- Driver ----------
function tick() {
  chrome.storage.local.get({ enabled: true }, (s) => {
    if (!s.enabled) return;
    if (location.href.includes('view=om')) scanRawSource();
    else scanOpenMessages();
  });
}

const observer = new MutationObserver(() => {
  clearTimeout(window.__phishtraceT);
  window.__phishtraceT = setTimeout(tick, 400);
});
observer.observe(document.body, { childList: true, subtree: true });
tick();
