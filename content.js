// PhishTrace content script — runs on mail.google.com
// Two modes: (1) normal inbox/reading pane -> quick heuristic scan on every opened message
//            (2) "Show original" raw-source view (?...&view=om&...) -> deep header forensics

const BRAND_DOMAINS = ["paypal.com","amazon.com","microsoft.com","icicibank.com","hdfcbank.com",
  "sbi.co.in","google.com","apple.com","netflix.com","irctc.co.in"];
const URGENCY_CUES = ["urgent","verify your account","suspended","wire transfer","click here",
  "password expires","invoice attached","act now","confidential","gift card","account will be locked"];
const CAMPAIGNS = [
  { name: "Campaign INV-Redwood", domains: ["secure-verify-alerts.com"] },
  { name: "Campaign GhostInvoice", domains: ["accounts-billing-support.net"] }
];

function lev(a, b) {
  const m = [];
  for (let i = 0; i <= a.length; i++) m[i] = [i];
  for (let j = 0; j <= b.length; j++) m[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      m[i][j] = a[i-1] === b[j-1] ? m[i-1][j-1] : 1 + Math.min(m[i-1][j-1], m[i-1][j], m[i][j-1]);
  return m[a.length][b.length];
}
function domainOf(addr) { const m = (addr||"").match(/@([\w.-]+)/); return m ? m[1].toLowerCase() : null; }

// ---------- MODE 1: quick heuristic scan of an opened message in the reading pane ----------
function quickScore(senderName, senderEmail, subject, bodyText) {
  let score = 0; const reasons = [];
  const dom = domainOf(senderEmail);
  const lower = (senderName || "").toLowerCase();

  // display-name-vs-domain mismatch: e.g. name says "PayPal Support" but domain isn't paypal.com
  for (const b of BRAND_DOMAINS) {
    const brand = b.split(".")[0];
    if (lower.includes(brand) && dom && dom !== b) {
      score += 30; reasons.push(`Display name references "${brand}" but sender domain is "${dom}", not "${b}".`);
      break;
    }
  }
  // lookalike domain
  if (dom) for (const b of BRAND_DOMAINS) {
    const d = lev(dom, b);
    if (d > 0 && d <= 3 && dom !== b) { score += 25; reasons.push(`Sender domain "${dom}" closely resembles "${b}" (possible typosquat).`); break; }
  }
  // known campaign domain
  if (dom && CAMPAIGNS.some(c => c.domains.includes(dom))) {
    score += 20; reasons.push("Sender domain matches a previously seen fraud campaign fingerprint.");
  }
  // urgency / social engineering language
  const text = ((subject||"") + " " + (bodyText||"")).toLowerCase();
  const hits = URGENCY_CUES.filter(c => text.includes(c));
  if (hits.length) { score += Math.min(25, hits.length * 6); reasons.push(`Urgency/social-engineering language: ${hits.join(", ")}.`); }

  return { score: Math.min(100, score), reasons, dom };
}

function makeBanner(result) {
  const level = result.score >= 60 ? "#e8543c" : result.score >= 30 ? "#e0a940" : "#2fbf8f";
  const label = result.score >= 60 ? "High risk — likely fraudulent" : result.score >= 30 ? "Suspicious — review carefully" : "Low risk";
  const div = document.createElement("div");
  div.setAttribute("data-phishtrace-banner", "1");
  div.style.cssText = `margin:10px 0;padding:10px 14px;border-radius:6px;border-left:4px solid ${level};
    background:${level}1a;font:13px/1.4 -apple-system,Arial,sans-serif;color:#222`;
  div.innerHTML = `<b>PhishTrace: ${label} (${result.score}/100)</b>` +
    (result.reasons.length ? `<ul style="margin:6px 0 0 18px;padding:0">${result.reasons.map(r=>`<li>${r}</li>`).join("")}</ul>` : "");
  return div;
}

function scanOpenMessages() {
  // .adn.ads is Gmail's per-message container in the reading pane; .gD holds sender email/name attrs;
  // .hP is the subject line; .a3s.aiL is the rendered message body. These are stable-ish but Gmail's
  // DOM is unofficial/obfuscated, so a production build should move to the Gmail API instead.
  document.querySelectorAll(".adn.ads").forEach(msg => {
    if (msg.getAttribute("data-phishtrace-scanned")) return;
    const senderEl = msg.querySelector(".gD");
    const subjectEl = document.querySelector(".hP");
    const bodyEl = msg.querySelector(".a3s.aiL");
    if (!senderEl) return;
    msg.setAttribute("data-phishtrace-scanned", "1");

    const senderName = senderEl.getAttribute("name") || senderEl.textContent;
    const senderEmail = senderEl.getAttribute("email") || "";
    const subject = subjectEl ? subjectEl.textContent : "";
    const bodyText = bodyEl ? bodyEl.textContent.slice(0, 2000) : "";

    const result = quickScore(senderName, senderEmail, subject, bodyText);
    const banner = makeBanner(result);
    msg.parentElement.insertBefore(banner, msg);
    chrome.runtime.sendMessage({ type: "phishtrace-result", score: result.score });
  });
}

// ---------- MODE 2: deep forensic parse of the raw "Show original" source ----------
function headerFrom(text, name) {
  const re = new RegExp("^" + name + ":\\s*(.*(?:\\n[ \\t].*)*)", "im");
  const m = text.match(re);
  return m ? m[1].replace(/\n[ \t]+/g, " ").trim() : null;
}
function allHeadersFrom(text, name) {
  const re = new RegExp("^" + name + ":\\s*(.*(?:\\n[ \\t].*)*)", "img");
  return [...text.matchAll(re)].map(m => m[1].replace(/\n[ \t]+/g, " ").trim());
}

function scanRawSource() {
  if (document.getElementById("phishtrace-forensic-panel")) return; // already rendered
  const text = document.body.innerText || "";
  if (!/^Delivered-To:|^Received:|^Return-Path:/im.test(text)) return; // not a raw-source view yet

  const from = headerFrom(text, "From"), returnPath = headerFrom(text, "Return-Path");
  const fromDom = domainOf(from), rpDom = domainOf(returnPath);
  const auth = headerFrom(text, "Authentication-Results") || "";
  const spf = /spf=(\w+)/i.exec(auth), dkim = /dkim=(\w+)/i.exec(auth), dmarc = /dmarc=(\w+)/i.exec(auth);
  const received = allHeadersFrom(text, "Received").reverse();
  const ips = received.map(r => { const m = r.match(/\[?(\d{1,3}(?:\.\d{1,3}){3})\]?/); return m ? m[1] : null; }).filter(Boolean);
  const originIp = ips.find(ip => !ip.startsWith("192.168.") && !ip.startsWith("10.")) || ips[0];

  let score = 0; const lines = [];
  if (rpDom && fromDom && rpDom !== fromDom) { score += 25; lines.push(`Return-Path (${rpDom}) ≠ From domain (${fromDom}).`); }
  [["SPF", spf], ["DKIM", dkim], ["DMARC", dmarc]].forEach(([label, m]) => {
    if (m && m[1].toLowerCase() !== "pass") { score += 15; lines.push(`${label}: ${m[1]}.`); }
  });

  const panel = document.createElement("div");
  panel.id = "phishtrace-forensic-panel";
  panel.style.cssText = `position:sticky;top:0;z-index:9999;background:#161d27;color:#e7ecf2;
    font:13px/1.5 -apple-system,Arial,sans-serif;padding:14px 18px;border-bottom:3px solid #4fa8e0;margin-bottom:16px`;
  panel.innerHTML = `<b>PhishTrace forensic trace</b> — fraud signal score: <b>${Math.min(100,score)}/100</b><br>
    From domain: <code>${fromDom || "—"}</code> · Return-Path domain: <code>${rpDom || "—"}</code><br>
    ${lines.map(l => "• " + l).join("<br>")}<br>
    Probable origin hop: <code>${originIp || "not found"}</code> (${ips.length} relay hop(s) detected)`;
  document.body.insertBefore(panel, document.body.firstChild);
}

// ---------- driver ----------
function tick() {
  chrome.storage.local.get({ enabled: true }, (s) => {
    if (!s.enabled) return;
    if (location.href.includes("view=om")) scanRawSource();
    else scanOpenMessages();
  });
}
const observer = new MutationObserver(() => {
  clearTimeout(window.__phishtraceT);
  window.__phishtraceT = setTimeout(tick, 400);
});
observer.observe(document.body, { childList: true, subtree: true });
tick();
