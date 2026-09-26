chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type !== "phishtrace-result") return;
  chrome.storage.local.get({ scanned: 0, flagged: 0 }, (s) => {
    const scanned = s.scanned + 1;
    const flagged = s.flagged + (msg.score >= 30 ? 1 : 0);
    chrome.storage.local.set({ scanned, flagged });
    if (flagged > 0) {
      chrome.action.setBadgeText({ text: String(flagged) });
      chrome.action.setBadgeBackgroundColor({ color: "#e8543c" });
    }
  });
});
