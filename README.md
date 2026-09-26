# PhishTrace — Automatic Email Threat Scanner (Chrome Extension)

## Install (unpacked, for demo/judging)
1. Unzip this folder.
2. Go to `chrome://extensions`.
3. Enable **Developer mode** (top right).
4. Click **Load unpacked** → select the unzipped `phishtrace-extension` folder.
5. Open Gmail (`mail.google.com`) and open any email.

## What it does automatically
- **Every email you open** in the reading pane is scanned instantly:
  sender display-name-vs-domain mismatch, lookalike/typosquat domains, known
  fraud-campaign domain fingerprints, and urgency/social-engineering language.
  A colored banner (green/amber/red) appears above the message with a score and reasons.
- **"Show original"** (Gmail's raw-source view) is scanned separately for deep
  forensic tracing: From vs Return-Path alignment, SPF/DKIM/DMARC results, and
  the reconstructed relay-hop chain with the probable origin hop highlighted.
- The toolbar badge shows a running count of flagged emails; the popup shows
  total scanned vs. flagged.

## Honest limitations (say this proactively in your demo)
- Gmail's reading-pane DOM (`.adn.ads`, `.gD`, `.a3s.aiL`, etc.) is unofficial
  and can change with Gmail UI updates. A production version would use the
  **Gmail API** (OAuth, `messages.get` with `format=full`) instead of DOM
  scraping, which is far more robust.
- The reading-pane scan is a **fast heuristic pass** (no header access —
  Gmail doesn't expose raw headers in the normal view). Full forensic
  analysis (SPF/DKIM/relay tracing) only runs on the "Show original" page,
  where the raw source is actually visible.
- IP geolocation, WHOIS/domain-age lookups, and the campaign-fingerprint
  database are stubbed for the demo. Swap in MaxMind GeoLite2 / a WHOIS API
  and a real (growing) fraud-cluster database for production.
- This targets Gmail's web UI only. Outlook/other clients would need their
  own content-script adapter, but the scoring engine (`quickScore` /
  raw-source parser in `content.js`) is client-agnostic and reusable.
