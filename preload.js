const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("piiGuardAPI", {
  // App state & stats
  getState: () => ipcRenderer.invoke("get-state"),
  toggleMonitoring: (enabled) => ipcRenderer.invoke("toggle-monitoring", enabled),
  updateSettings: (settings) => ipcRenderer.invoke("update-settings", settings),
  
  // Real-time actions
  scanText: (text, context) => ipcRenderer.invoke("scan-text", { text, context }),
  maskClipboard: () => ipcRenderer.invoke("mask-clipboard"),
  clearClipboard: () => ipcRenderer.invoke("clear-clipboard"),
  scanClipboardNow: () => ipcRenderer.invoke("scan-clipboard-now"),
  
  // History & logs
  getHistory: () => ipcRenderer.invoke("get-history"),
  clearHistory: () => ipcRenderer.invoke("clear-history"),
  
  // Window controls
  minimizeWindow: () => ipcRenderer.send("window-control", "minimize"),
  maximizeWindow: () => ipcRenderer.send("window-control", "maximize"),
  closeWindow: () => ipcRenderer.send("window-control", "close"),
  
  // Event listeners
  onPIIDetected: (callback) => {
    const listener = (event, data) => callback(data);
    ipcRenderer.on("pii-detected", listener);
    return () => ipcRenderer.removeListener("pii-detected", listener);
  },
  onStateChanged: (callback) => {
    const listener = (event, data) => callback(data);
    ipcRenderer.on("state-changed", listener);
    return () => ipcRenderer.removeListener("state-changed", listener);
  },
});
