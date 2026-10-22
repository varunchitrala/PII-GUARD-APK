const status = document.getElementById("status");
const toggle = document.getElementById("toggle");
let enabled = true;
function render() {
  status.textContent = enabled ? "ON" : "OFF";
  toggle.textContent = enabled ? "Turn protection off" : "Turn protection on";
}
chrome.storage.sync.get({ enabled: true }, data => { enabled = data.enabled; render(); });
toggle.addEventListener("click", () => {
  enabled = !enabled;
  chrome.storage.sync.set({ enabled }, render);
});