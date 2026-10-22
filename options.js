const checkbox = document.getElementById("enabled");
const saved = document.getElementById("saved");
chrome.storage.sync.get(
  { enabled: true },
  (data) => (checkbox.checked = data.enabled),
);
checkbox.addEventListener("change", () => {
  chrome.storage.sync.set({ enabled: checkbox.checked }, () => {
    saved.textContent = "Settings saved.";
    setTimeout(() => (saved.textContent = ""), 1800);
  });
});
