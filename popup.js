function render() {
  chrome.storage.local.get({ scanned: 0, flagged: 0, enabled: true }, (s) => {
    document.getElementById("scanned").textContent = s.scanned;
    document.getElementById("flagged").textContent = s.flagged;
    document.getElementById("toggle").textContent = s.enabled ? "On" : "Off";
  });
}
document.getElementById("toggle").addEventListener("click", () => {
  chrome.storage.local.get({ enabled: true }, (s) => {
    chrome.storage.local.set({ enabled: !s.enabled }, render);
  });
});
render();
