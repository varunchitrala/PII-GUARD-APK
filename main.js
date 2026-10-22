const {
  app,
  BrowserWindow,
  ipcMain,
  clipboard,
  Notification,
  Tray,
  Menu,
  nativeImage,
  globalShortcut,
  screen,
} = require("electron");
const path = require("path");
const fs = require("fs");

const PATTERNS = require("./patterns.js");
const DetectionEngine = require("./detection-engine.js");

// ─── State & Storage ──────────────────────────────────────────────
const USER_DATA_PATH = app.getPath("userData");
const SETTINGS_FILE = path.join(USER_DATA_PATH, "pii-guard-settings.json");
const HISTORY_FILE = path.join(USER_DATA_PATH, "pii-guard-history.json");

const allPatternsList = PATTERNS.PATTERNS || PATTERNS;
const initialEnabledRules = {};
allPatternsList.forEach((p) => {
  initialEnabledRules[p.type] = true;
});

let defaultSettings = {
  monitoringEnabled: true,
  soundAlerts: true,
  showDesktopOverlay: true,
  showSystemNotification: true,
  autoMaskClipboard: false,
  minimizeToTray: true,
  pollInterval: 350,
  enabledRules: initialEnabledRules,
};

let settings = { ...defaultSettings };
try {
  if (fs.existsSync(SETTINGS_FILE)) {
    const raw = fs.readFileSync(SETTINGS_FILE, "utf-8");
    settings = { ...defaultSettings, ...JSON.parse(raw) };
  }
} catch (e) {
  console.error("Failed to load settings:", e);
}

let alertsHistory = [];
try {
  if (fs.existsSync(HISTORY_FILE)) {
    const raw = fs.readFileSync(HISTORY_FILE, "utf-8");
    alertsHistory = JSON.parse(raw);
  }
} catch (e) {
  console.error("Failed to load history:", e);
}

let stats = {
  totalScans: 0,
  piiDetected: 0,
  threatsBlocked: 0,
  monitoringSince: new Date().toISOString(),
};

// ─── Helpers: Masking & Redaction ─────────────────────────────────

function maskPIIString(text, type) {
  if (!text) return "";
  const str = text.trim();

  // Credit card: show only last 4
  if (type && type.includes("card")) {
    const digits = str.replace(/\D/g, "");
    if (digits.length >= 4) {
      return "•••• •••• •••• " + digits.slice(-4);
    }
  }

  // Aadhaar: show only last 4
  if (type && type.includes("Aadhaar")) {
    const digits = str.replace(/\D/g, "");
    if (digits.length >= 4) {
      return "•••• •••• " + digits.slice(-4);
    }
  }

  // SSN: show only last 4
  if (type && type.includes("SSN")) {
    const digits = str.replace(/\D/g, "");
    if (digits.length >= 4) {
      return "•••-••-" + digits.slice(-4);
    }
  }

  // Email
  if (type && type.includes("Email")) {
    const parts = str.split("@");
    if (parts.length === 2) {
      const user = parts[0];
      const visible = user.length > 2 ? user[0] + "•••" + user[user.length - 1] : "•••";
      return visible + "@" + parts[1];
    }
  }

  // Phone
  if (type && type.includes("Phone")) {
    const digits = str.replace(/\D/g, "");
    if (digits.length >= 4) {
      return "•••••• " + digits.slice(-4);
    }
  }

  // General fallback: mask middle characters
  if (str.length <= 4) return "••••";
  const keep = Math.min(2, Math.floor(str.length / 4));
  return str.slice(0, keep) + "••••••••" + str.slice(-keep);
}

function redactEntireText(fullText, detections) {
  if (!fullText || !detections || !detections.length) return fullText;
  let redacted = fullText;
  // Sort detections by length descending to replace longest matches first
  const sorted = [...detections].sort((a, b) => (b.rawText?.length || 0) - (a.rawText?.length || 0));
  for (const det of sorted) {
    if (det.rawText) {
      const masked = maskPIIString(det.rawText, det.type);
      redacted = redacted.split(det.rawText).join(masked);
    }
  }
  return redacted;
}

function saveSettings() {
  try {
    fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2), "utf-8");
  } catch (e) {
    console.error("Failed to save settings:", e);
  }
}

function saveHistory() {
  try {
    // Keep max 250 records
    if (alertsHistory.length > 250) {
      alertsHistory = alertsHistory.slice(0, 250);
    }
    fs.writeFileSync(HISTORY_FILE, JSON.stringify(alertsHistory, null, 2), "utf-8");
  } catch (e) {
    console.error("Failed to save history:", e);
  }
}

// ─── Windows & Tray References ────────────────────────────────────
let mainWindow = null;
let overlayWindow = null;
let tray = null;
let monitorInterval = null;
let lastClipboardText = "";
let lastAlertTimestamp = 0;
let lastAlertedHash = "";

// ─── Window Creation ──────────────────────────────────────────────

function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1150,
    height: 780,
    minWidth: 920,
    minHeight: 620,
    frame: false,
    titleBarStyle: "hidden",
    backgroundColor: "#090d16",
    show: false,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  mainWindow.loadFile(path.join(__dirname, "index.html"));

  mainWindow.once("ready-to-show", () => {
    mainWindow.show();
  });

  mainWindow.on("close", (event) => {
    if (settings.minimizeToTray && !app.isQuitting) {
      event.preventDefault();
      mainWindow.hide();
      if (Notification.isSupported()) {
        new Notification({
          title: "PII Guard Active in Background",
          body: "PII Guard is silently monitoring your desktop to protect sensitive data.",
          silent: true,
        }).show();
      }
    }
  });
}

function createOverlayWindow() {
  overlayWindow = new BrowserWindow({
    width: 420,
    height: 180,
    frame: false,
    transparent: true,
    alwaysOnTop: true,
    skipTaskbar: true,
    resizable: false,
    show: false,
    focusable: false,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
  });

  overlayWindow.loadFile(path.join(__dirname, "overlay.html"));
}

function positionOverlayWindow() {
  if (!overlayWindow) return;
  const primaryDisplay = screen.getPrimaryDisplay();
  const { width, height } = primaryDisplay.workAreaSize;
  const overlayWidth = 420;
  const overlayHeight = 180;
  // Position in bottom-right corner with 24px margin
  const x = width - overlayWidth - 24;
  const y = height - overlayHeight - 24;
  overlayWindow.setBounds({ x, y, width: overlayWidth, height: overlayHeight });
}

function showOverlayAlert(alertData) {
  if (!settings.showDesktopOverlay) return;
  if (!overlayWindow || overlayWindow.isDestroyed()) {
    createOverlayWindow();
  }
  positionOverlayWindow();
  overlayWindow.webContents.send("show-alert", alertData);
  overlayWindow.setAlwaysOnTop(true, "screen-saver");
  overlayWindow.showInactive();
}

// ─── Tray Creation ────────────────────────────────────────────────

function createTray() {
  // Generate a clean programmatically drawn shield SVG or 16x16 icon
  const iconSvg = `
    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="#3b82f6">
      <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 2.18l7 3.12v4.7c0 4.62-3.13 8.94-7 10-3.87-1.06-7-5.38-7-10V6.3l7-3.12z"/>
    </svg>`;
  const iconBuffer = Buffer.from(iconSvg);
  const trayIcon = nativeImage.createFromBuffer(iconBuffer).resize({ width: 16, height: 16 });

  try {
    tray = new Tray(trayIcon);
  } catch (e) {
    console.error("Failed to create tray icon:", e);
    return;
  }

  const updateTrayMenu = () => {
    const contextMenu = Menu.buildFromTemplate([
      {
        label: "🛡️ PII Guard Desktop",
        enabled: false,
      },
      { type: "separator" },
      {
        label: "Open Dashboard",
        click: () => {
          if (mainWindow) {
            mainWindow.show();
            mainWindow.focus();
          }
        },
      },
      {
        label: settings.monitoringEnabled ? "● Monitoring: ACTIVE" : "○ Monitoring: PAUSED",
        click: () => {
          settings.monitoringEnabled = !settings.monitoringEnabled;
          saveSettings();
          broadcastState();
          updateTrayMenu();
        },
      },
      {
        label: "🔍 Scan Clipboard Now",
        click: () => scanClipboardNow(),
      },
      {
        label: "🛡️ Mask / Sanitize Clipboard",
        click: () => maskClipboardContent(),
      },
      {
        label: "❌ Clear Clipboard",
        click: () => {
          clipboard.clear();
          if (mainWindow) {
            mainWindow.webContents.send("clipboard-cleared");
          }
        },
      },
      { type: "separator" },
      {
        label: "Exit PII Guard",
        click: () => {
          app.isQuitting = true;
          app.quit();
        },
      },
    ]);
    tray.setToolTip(`PII Guard: ${settings.monitoringEnabled ? "Active" : "Paused"}`);
    tray.setContextMenu(contextMenu);
  };

  updateTrayMenu();
  tray.on("double-click", () => {
    if (mainWindow) {
      mainWindow.show();
      mainWindow.focus();
    }
  });
}

// ─── Detection & System-Wide Watcher ──────────────────────────────

function getActivePatterns() {
  const allPatterns = PATTERNS.PATTERNS || PATTERNS;
  return allPatterns.filter((p) => {
    if (settings.enabledRules && settings.enabledRules[p.type] === false) {
      return false;
    }
    return true;
  });
}

function scanTextContent(text, context = null) {
  if (!text || typeof text !== "string" || !text.trim()) {
    return [];
  }
  const patterns = getActivePatterns();
  const results = DetectionEngine.detectWithContext(text, context, patterns);

  // Attach raw text snippet and masked preview to each detection
  return results.map((r) => {
    let matchedSnippet = "";
    // Find pattern regex match if possible
    const pat = patterns.find((p) => p.type === r.type);
    if (pat && pat.regex) {
      try {
        const m = pat.regex.exec(text);
        if (m) matchedSnippet = m[0];
      } catch {}
    }
    const snippet = matchedSnippet || text.slice(0, 40);
    return {
      ...r,
      rawText: snippet,
      masked: maskPIIString(snippet, r.type),
    };
  });
}

function handlePIIDetected(detectedResults, fullText, source = "System Clipboard") {
  if (!detectedResults || !detectedResults.length) return;

  const primaryThreat = detectedResults[0];
  const alertId = Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
  const now = new Date();

  const alertItem = {
    id: alertId,
    timestamp: now.toISOString(),
    displayTime: now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
    source,
    type: primaryThreat.type,
    severity: primaryThreat.severity || "danger",
    priority: primaryThreat.priority || 2,
    confidence: primaryThreat.confidence,
    confidenceLabel: primaryThreat.confidenceLabel,
    validated: primaryThreat.validated,
    message: primaryThreat.message,
    masked: primaryThreat.masked || maskPIIString(fullText, primaryThreat.type),
    rawText: primaryThreat.rawText || fullText.slice(0, 30),
    totalMatches: detectedResults.length,
    allMatches: detectedResults.map((d) => ({
      type: d.type,
      severity: d.severity,
      masked: d.masked,
      confidence: d.confidence,
    })),
  };

  // Add to alerts history
  alertsHistory.unshift(alertItem);
  saveHistory();

  // Update statistics
  stats.piiDetected += detectedResults.length;
  if (primaryThreat.severity === "danger") {
    stats.threatsBlocked += 1;
  }

  // 1. Send to renderer
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send("pii-detected", alertItem);
  }

  // 2. Show floating desktop overlay
  showOverlayAlert(alertItem);

  // 3. Show native OS notification
  if (settings.showSystemNotification && Notification.isSupported()) {
    const notif = new Notification({
      title: `🚨 PII Alert: ${primaryThreat.type}`,
      body: `${primaryThreat.message}\nProtected by PII Guard.`,
      silent: !settings.soundAlerts,
    });
    notif.on("click", () => {
      if (mainWindow) {
        mainWindow.show();
        mainWindow.focus();
      }
    });
    notif.show();
  }

  // 4. Auto-mask if enabled
  if (settings.autoMaskClipboard && source === "System Clipboard") {
    maskClipboardContent(detectedResults);
  }
}

function maskClipboardContent(optionalDetections = null) {
  try {
    const text = clipboard.readText();
    if (!text) return false;
    const detections = optionalDetections || scanTextContent(text);
    if (!detections.length) return false;

    const redacted = redactEntireText(text, detections);
    clipboard.writeText(redacted);
    lastClipboardText = redacted;

    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send("clipboard-masked", {
        originalLength: text.length,
        maskedLength: redacted.length,
      });
    }
    return true;
  } catch (e) {
    console.error("Failed to mask clipboard:", e);
    return false;
  }
}

function scanClipboardNow() {
  try {
    const text = clipboard.readText();
    if (!text || !text.trim()) return [];
    stats.totalScans += 1;
    const detections = scanTextContent(text);
    if (detections.length) {
      handlePIIDetected(detections, text, "Manual Clipboard Scan");
    }
    return detections;
  } catch (e) {
    console.error("Scan clipboard error:", e);
    return [];
  }
}

function startClipboardWatcher() {
  if (monitorInterval) clearInterval(monitorInterval);

  monitorInterval = setInterval(() => {
    if (!settings.monitoringEnabled) return;

    try {
      const currentText = clipboard.readText();
      if (!currentText || !currentText.trim()) return;
      if (currentText === lastClipboardText) return;

      lastClipboardText = currentText;
      stats.totalScans += 1;

      // Simple hash to avoid repeated alerts for identical copies within 6 seconds
      const textHash = currentText.slice(0, 80) + currentText.length;
      const now = Date.now();
      if (textHash === lastAlertedHash && now - lastAlertTimestamp < 6000) {
        return;
      }

      const detections = scanTextContent(currentText);
      if (detections.length > 0) {
        lastAlertedHash = textHash;
        lastAlertTimestamp = now;
        handlePIIDetected(detections, currentText, "System Clipboard");
      }
    } catch (e) {
      console.error("Clipboard watcher error:", e);
    }
  }, settings.pollInterval || 350);
}

function broadcastState() {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send("state-changed", {
      settings,
      stats,
      historyCount: alertsHistory.length,
    });
  }
}

// ─── IPC Handlers ─────────────────────────────────────────────────

ipcMain.handle("get-state", () => {
  return {
    settings,
    stats,
    history: alertsHistory.slice(0, 100),
    rulesList: (PATTERNS.PATTERNS || PATTERNS).map((p) => ({
      type: p.type,
      severity: p.severity,
      priority: p.priority,
      description: p.description,
      limitations: p.limitations,
      hasChecksum: !!p.validate,
      enabled: settings.enabledRules ? settings.enabledRules[p.type] !== false : true,
    })),
  };
});

ipcMain.handle("toggle-monitoring", (event, enabled) => {
  settings.monitoringEnabled = !!enabled;
  saveSettings();
  broadcastState();
  return settings.monitoringEnabled;
});

ipcMain.handle("update-settings", (event, newSettings) => {
  settings = { ...settings, ...newSettings };
  saveSettings();
  broadcastState();
  return settings;
});

ipcMain.handle("scan-text", (event, { text, context }) => {
  stats.totalScans += 1;
  const detections = scanTextContent(text, context);
  return {
    detections,
    totalMatches: detections.length,
    redactedText: redactEntireText(text, detections),
  };
});

ipcMain.handle("mask-clipboard", () => {
  return maskClipboardContent();
});

ipcMain.handle("clear-clipboard", () => {
  clipboard.clear();
  return true;
});

ipcMain.handle("scan-clipboard-now", () => {
  return scanClipboardNow();
});

ipcMain.handle("get-history", () => {
  return alertsHistory;
});

ipcMain.handle("clear-history", () => {
  alertsHistory = [];
  saveHistory();
  return true;
});

ipcMain.on("window-control", (event, action) => {
  if (!mainWindow) return;
  if (action === "minimize") mainWindow.minimize();
  if (action === "maximize") {
    if (mainWindow.isMaximized()) mainWindow.unmaximize();
    else mainWindow.maximize();
  }
  if (action === "close") {
    mainWindow.close();
  }
});

ipcMain.on("dismiss-overlay", () => {
  if (overlayWindow && !overlayWindow.isDestroyed()) {
    overlayWindow.hide();
  }
});

ipcMain.on("mask-clipboard-from-overlay", () => {
  maskClipboardContent();
});

ipcMain.on("show-main-window", () => {
  if (mainWindow) {
    mainWindow.show();
    mainWindow.focus();
  }
});

// ─── App Lifecycle ────────────────────────────────────────────────

const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
} else {
  app.on("second-instance", () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.focus();
    }
  });

  app.whenReady().then(() => {
    createMainWindow();
    createOverlayWindow();
    createTray();
    startClipboardWatcher();

    // Register global hotkey to summon scanner
    try {
      globalShortcut.register("CommandOrControl+Shift+P", () => {
        if (mainWindow) {
          if (mainWindow.isVisible()) {
            mainWindow.focus();
          } else {
            mainWindow.show();
          }
        }
      });
    } catch (e) {
      console.warn("Could not register global hotkey:", e);
    }
  });

  app.on("window-all-closed", () => {
    if (process.platform !== "darwin" && !settings.minimizeToTray) {
      app.quit();
    }
  });

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createMainWindow();
    }
  });

  app.on("will-quit", () => {
    globalShortcut.unregisterAll();
    if (monitorInterval) clearInterval(monitorInterval);
  });
}
