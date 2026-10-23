/**
 * PII Guard Desktop — Renderer Application
 */
(() => {
  "use strict";

  // App State Cache
  let currentSettings = {};
  let currentStats = {};
  let currentHistory = [];
  let availableRules = [];
  let audioCtx = null;
  let activeAuditedFileContent = "";
  let activeAuditedFileName = "";
  let activeAuditedRedacted = "";

  // ─── Web Audio Synthesized Chime ────────────────────────────────
  function playAlertChime() {
    if (currentSettings && currentSettings.soundAlerts === false) return;
    try {
      if (!audioCtx) {
        audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      }
      if (audioCtx.state === "suspended") {
        audioCtx.resume();
      }

      const now = audioCtx.currentTime;
      const osc1 = audioCtx.createOscillator();
      const osc2 = audioCtx.createOscillator();
      const gainNode = audioCtx.createGain();

      osc1.type = "sine";
      osc1.frequency.setValueAtTime(880, now); // A5
      osc1.frequency.exponentialRampToValueAtTime(587.33, now + 0.28); // D5

      osc2.type = "triangle";
      osc2.frequency.setValueAtTime(1046.5, now); // C6
      osc2.frequency.exponentialRampToValueAtTime(659.25, now + 0.28); // E5

      gainNode.gain.setValueAtTime(0.001, now);
      gainNode.gain.linearRampToValueAtTime(0.18, now + 0.03);
      gainNode.gain.exponentialRampToValueAtTime(0.0001, now + 0.35);

      osc1.connect(gainNode);
      osc2.connect(gainNode);
      gainNode.connect(audioCtx.destination);

      osc1.start(now);
      osc2.start(now);
      osc1.stop(now + 0.38);
      osc2.stop(now + 0.38);
    } catch (e) {
      console.warn("Audio chime error:", e);
    }
  }

  // ─── Toast System ────────────────────────────────────────────────
  function showToast(message, type = "info") {
    const container = document.getElementById("toastContainer");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = "toast";
    let icon = "ℹ️";
    if (type === "success") icon = "✅";
    if (type === "warning") icon = "⚠️";
    if (type === "danger") icon = "🚨";

    toast.innerHTML = `<span>${icon}</span> <span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateY(10px)";
      toast.style.transition = "all 0.2s ease";
      setTimeout(() => toast.remove(), 200);
    }, 3200);
  }

  // ─── Initialization ──────────────────────────────────────────────
  async function initApp() {
    setupTitlebar();
    setupNavigation();
    setupDashboard();
    setupLiveScanner();
    setupFileAuditor();
    setupHistory();
    setupPreferences();

    // Fetch initial state from Main process
    if (window.piiGuardAPI) {
      try {
        const state = await window.piiGuardAPI.getState();
        currentSettings = state.settings || {};
        currentStats = state.stats || {};
        currentHistory = state.history || [];
        availableRules = state.rulesList || [];

        renderState();
        renderRulesGrid();
        renderHistoryTable();

        // Listen for live detection events
        window.piiGuardAPI.onPIIDetected((alertItem) => {
          handleIncomingAlert(alertItem);
        });

        // Listen for state changes (settings or stats)
        window.piiGuardAPI.onStateChanged((stateUpdate) => {
          if (stateUpdate.settings) currentSettings = stateUpdate.settings;
          if (stateUpdate.stats) currentStats = stateUpdate.stats;
          renderState();
        });
      } catch (e) {
        console.error("Failed to load initial state:", e);
      }
    }
  }

  // ─── Titlebar Window Controls ───
  function setupTitlebar() {
    document.getElementById("btnMin")?.addEventListener("click", () => {
      window.piiGuardAPI?.minimizeWindow();
    });
    document.getElementById("btnMax")?.addEventListener("click", () => {
      window.piiGuardAPI?.maximizeWindow();
    });
    document.getElementById("btnClose")?.addEventListener("click", () => {
      window.piiGuardAPI?.closeWindow();
    });
  }

  // ─── Navigation Tabs ───
  function setupNavigation() {
    const navItems = document.querySelectorAll(".nav-item");
    const tabPanes = document.querySelectorAll(".tab-pane");

    navItems.forEach((btn) => {
      btn.addEventListener("click", () => {
        const targetTab = btn.getAttribute("data-tab");
        navItems.forEach((n) => n.classList.remove("active"));
        tabPanes.forEach((p) => p.classList.remove("active"));

        btn.classList.add("active");
        const pane = document.getElementById(targetTab);
        if (pane) pane.classList.add("active");
      });
    });

    document.getElementById("btnViewAllHistory")?.addEventListener("click", () => {
      const historyNav = document.querySelector('[data-tab="tab-history"]');
      if (historyNav) historyNav.click();
    });
  }

  // ─── State Rendering ───
  function renderState() {
    // Stats
    const totalScansEl = document.getElementById("statTotalScans");
    const piiDetectedEl = document.getElementById("statPIIDetected");
    const threatsBlockedEl = document.getElementById("statThreatsBlocked");
    const activeRulesEl = document.getElementById("statActiveRules");
    const threatBadgeEl = document.getElementById("threatCountBadge");
    const historyCounterEl = document.getElementById("historyCounter");

    if (totalScansEl) totalScansEl.textContent = currentStats.totalScans || 0;
    if (piiDetectedEl) piiDetectedEl.textContent = currentStats.piiDetected || 0;
    if (threatsBlockedEl) threatsBlockedEl.textContent = currentStats.threatsBlocked || 0;
    if (threatBadgeEl) threatBadgeEl.textContent = currentStats.threatsBlocked || 0;
    if (historyCounterEl) historyCounterEl.textContent = currentHistory.length || 0;

    const activeRulesCount = availableRules.filter((r) => r.enabled).length;
    if (activeRulesEl) activeRulesEl.textContent = activeRulesCount;
    const rulesCounterNav = document.getElementById("rulesActiveCounter");
    if (rulesCounterNav) rulesCounterNav.textContent = activeRulesCount;

    // Master Toggle
    const masterToggle = document.getElementById("mainMonitoringToggle");
    const titlebarPill = document.getElementById("titlebarStatusPill");
    const heroBanner = document.getElementById("heroBanner");
    const heroTitle = document.getElementById("heroStatusTitle");
    const heroDesc = document.getElementById("heroStatusDesc");

    const isEnabled = currentSettings.monitoringEnabled !== false;
    if (masterToggle) masterToggle.checked = isEnabled;

    if (isEnabled) {
      titlebarPill?.classList.remove("paused");
      titlebarPill?.classList.add("active");
      if (titlebarPill) titlebarPill.querySelector(".status-text").textContent = "MONITORING ACTIVE";

      heroBanner?.classList.remove("paused");
      if (heroTitle) heroTitle.textContent = "System-Wide PII Shield Active";
      if (heroDesc) {
        heroDesc.textContent = "Monitoring clipboard and text inputs across browsers, office apps, chat clients, and code editors. Instant alert overlay enabled.";
      }
    } else {
      titlebarPill?.classList.remove("active");
      titlebarPill?.classList.add("paused");
      if (titlebarPill) titlebarPill.querySelector(".status-text").textContent = "MONITORING PAUSED";

      heroBanner?.classList.add("paused");
      if (heroTitle) heroTitle.textContent = "PII Shield is Paused";
      if (heroDesc) {
        heroDesc.textContent = "System-wide background monitoring is currently suspended. Clipboard and text entries are not being inspected.";
      }
    }

    const prefRealtimeTyping = document.getElementById("prefRealtimeTyping");
    const prefOverlay = document.getElementById("prefOverlay");
    const prefSound = document.getElementById("prefSound");
    const prefSystemNotif = document.getElementById("prefSystemNotif");
    const prefAutoMask = document.getElementById("prefAutoMask");
    const prefMinimizeToTray = document.getElementById("prefMinimizeToTray");
    const prefPollInterval = document.getElementById("prefPollInterval");

    if (prefRealtimeTyping) prefRealtimeTyping.checked = currentSettings.realtimeTypingMonitor !== false;
    if (prefOverlay) prefOverlay.checked = currentSettings.showDesktopOverlay !== false;
    if (prefSound) prefSound.checked = currentSettings.soundAlerts !== false;
    if (prefSystemNotif) prefSystemNotif.checked = currentSettings.showSystemNotification !== false;
    if (prefAutoMask) prefAutoMask.checked = !!currentSettings.autoMaskClipboard;
    if (prefMinimizeToTray) prefMinimizeToTray.checked = currentSettings.minimizeToTray !== false;
    if (prefPollInterval) prefPollInterval.value = currentSettings.pollInterval || "350";
  }

  // ─── Incoming Alert Handler ───
  function handleIncomingAlert(alertItem) {
    playAlertChime();
    currentHistory.unshift(alertItem);
    currentStats.piiDetected = (currentStats.piiDetected || 0) + 1;
    if (alertItem.severity === "danger") {
      currentStats.threatsBlocked = (currentStats.threatsBlocked || 0) + 1;
    }

    renderState();
    renderRecentAlertFeed();
    renderHistoryTable();
    showToast(`Intercepted ${alertItem.type} on ${alertItem.source}!`, alertItem.severity);
  }

  // ─── Dashboard Setup ───
  function setupDashboard() {
    const masterToggle = document.getElementById("mainMonitoringToggle");
    masterToggle?.addEventListener("change", async (e) => {
      const enabled = e.target.checked;
      await window.piiGuardAPI?.toggleMonitoring(enabled);
      currentSettings.monitoringEnabled = enabled;
      renderState();
      showToast(enabled ? "System monitoring activated." : "System monitoring paused.", enabled ? "success" : "warning");
    });

    // Test overlay button
    document.getElementById("btnTestAlertOverlay")?.addEventListener("click", () => {
      const sampleAlert = {
        type: "Indian Aadhaar number",
        severity: "danger",
        confidence: 0.95,
        confidenceLabel: "HIGH CONFIDENCE",
        validated: true,
        masked: "•••• •••• 9012",
        message: "Valid 12-digit Indian Aadhaar number with Verhoeff checksum pass.",
      };
      handleIncomingAlert({
        id: "test-" + Date.now(),
        timestamp: new Date().toISOString(),
        displayTime: new Date().toLocaleTimeString(),
        source: "Test Overlay Trigger",
        ...sampleAlert,
      });
    });

    // Quick clipboard actions
    document.getElementById("btnQuickScanClip")?.addEventListener("click", async () => {
      const results = await window.piiGuardAPI?.scanClipboardNow();
      if (results && results.length > 0) {
        showToast(`Detected ${results.length} PII instance(s) in clipboard!`, "danger");
      } else {
        showToast("Clipboard scanned: No PII detected.", "success");
      }
    });

    document.getElementById("btnQuickMaskClip")?.addEventListener("click", async () => {
      const masked = await window.piiGuardAPI?.maskClipboard();
      if (masked) {
        showToast("Sensitive data on clipboard has been masked!", "success");
      } else {
        showToast("No sensitive PII found on clipboard to mask.", "info");
      }
    });
  }

  function renderRecentAlertFeed() {
    const feed = document.getElementById("dashboardThreatFeed");
    if (!feed) return;

    if (!currentHistory.length) {
      feed.innerHTML = `
        <div class="empty-state">
          <span class="empty-icon">🛡️</span>
          <p>No PII leaks detected recently.</p>
          <small>When sensitive data is copied or entered anywhere on your computer, it will appear here in real time.</small>
        </div>`;
      return;
    }

    feed.innerHTML = currentHistory.slice(0, 5).map((item) => {
      let riskBadgeClass = "badge-danger";
      if (item.severity === "warning") riskBadgeClass = "badge-warning";
      if (item.severity === "info") riskBadgeClass = "badge-info";

      return `
        <div class="threat-item" style="--threat-color: ${item.severity === 'danger' ? '#f43f5e' : (item.severity === 'warning' ? '#f59e0b' : '#3b82f6')}">
          <div class="threat-left">
            <div class="threat-topline">
              <span class="threat-type">${escapeHtml(item.type)}</span>
              <span class="badge-risk ${riskBadgeClass}">${escapeHtml(item.severity)}</span>
              ${item.validated ? '<span class="tag-status" style="font-size: 10px;">✓ Validated</span>' : ''}
            </div>
            <div class="threat-snippet">${escapeHtml(item.masked || item.rawText)}</div>
          </div>
          <div class="threat-right">
            <span class="threat-time">${escapeHtml(item.displayTime || '')}</span>
            <span class="threat-source-pill">${escapeHtml(item.source || 'Desktop')}</span>
          </div>
        </div>`;
    }).join("");
  }

  // ─── Live Scanner & Inspector Setup ───
  function setupLiveScanner() {
    const input = document.getElementById("scannerInput");
    const meta = document.getElementById("scannerMeta");
    const findingsBadge = document.getElementById("findingsBadge");
    const findingsList = document.getElementById("findingsList");
    const redactedCard = document.getElementById("redactedPreviewCard");
    const redactedPre = document.getElementById("redactedTextPre");
    const btnCopyRedacted = document.getElementById("btnCopyRedacted");
    const contextSelect = document.getElementById("selectContextSimulation");

    let debounceTimer = null;

    async function runScan() {
      const text = input.value;
      const charCount = text.length;
      const wordCount = text.trim() ? text.trim().split(/\s+/).length : 0;
      if (meta) meta.textContent = `${charCount} characters | ${wordCount} words`;

      if (!text.trim()) {
        findingsBadge.textContent = "0 DETECTED";
        findingsBadge.classList.remove("has-threats");
        findingsList.innerHTML = `
          <div class="empty-state">
            <span class="empty-icon">🔍</span>
            <p>No PII detected yet.</p>
            <small>Type or pick a quick sample above to test the real-time detection engine.</small>
          </div>`;
        redactedCard.style.display = "none";
        btnCopyRedacted.disabled = true;
        return;
      }

      // Simulate field context if selected
      let context = null;
      const sim = contextSelect.value;
      if (sim) {
        context = {
          name: sim,
          id: sim,
          placeholder: sim,
          type: "text",
          label: sim,
        };
      }

      const scanResult = await window.piiGuardAPI?.scanText(text, context);
      const detections = scanResult?.detections || [];
      const totalMatches = scanResult?.totalMatches || 0;
      const redactedText = scanResult?.redactedText || text;

      if (totalMatches > 0) {
        findingsBadge.textContent = `${totalMatches} DETECTED`;
        findingsBadge.classList.add("has-threats");
        btnCopyRedacted.disabled = false;

        findingsList.innerHTML = detections.map((d) => {
          let cardColor = "#f43f5e";
          if (d.severity === "warning") cardColor = "#f59e0b";
          if (d.severity === "info") cardColor = "#3b82f6";

          return `
            <div class="finding-card" style="--card-color: ${cardColor}">
              <div class="finding-top">
                <span class="finding-name">${escapeHtml(d.type)}</span>
                <span class="finding-confidence">${d.validated ? '✓ Verified Checksum' : `${Math.round(d.confidence * 100)}% Confidence`}</span>
              </div>
              <div class="finding-masked">${escapeHtml(d.masked || d.rawText)}</div>
              <div class="finding-desc">${escapeHtml(d.message || '')}</div>
            </div>`;
        }).join("");

        redactedCard.style.display = "block";
        redactedPre.textContent = redactedText;
      } else {
        findingsBadge.textContent = "0 DETECTED";
        findingsBadge.classList.remove("has-threats");
        findingsList.innerHTML = `
          <div class="empty-state">
            <span class="empty-icon">✅</span>
            <p>No PII detected in this text.</p>
            <small>Clean input or content is safe to share.</small>
          </div>`;
        redactedCard.style.display = "none";
        btnCopyRedacted.disabled = true;
      }
    }

    input?.addEventListener("input", () => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(runScan, 200);
    });

    contextSelect?.addEventListener("change", runScan);

    // Quick Samples
    const samples = {
      aadhaar: "Customer Aadhaar identity: 2854 4452 4687 verified at regional portal.",
      card: "Please process monthly subscription using Visa card: 4532 0150 1234 5671 expiring 08/29.",
      ssn: "Applicant official SSN on record: 123-45-6789 for federal background check.",
      pan: "Indian Income Tax Permanent Account Number (PAN): ABCDE1234F submitted with invoice.",
      email: "Reach our director directly at john.doe@enterprise-security.org or support@domain.com.",
      mixed: "Full dossier:\nClient: Radha Chitrala\nEmail: radha.c@gmail.com\nPhone: +91 98765 43210\nAadhaar: 2854 4452 4687\nEmergency card: 4532 0150 1234 5671\nIP: 192.168.1.104",
    };

    document.querySelectorAll(".pill-btn").forEach((pill) => {
      pill.addEventListener("click", () => {
        const key = pill.getAttribute("data-sample");
        if (samples[key]) {
          input.value = samples[key];
          runScan();
        }
      });
    });

    document.getElementById("btnClearScanner")?.addEventListener("click", () => {
      input.value = "";
      runScan();
    });

    document.getElementById("btnPasteClipboard")?.addEventListener("click", async () => {
      try {
        const text = await navigator.clipboard.readText();
        if (text) {
          input.value = text;
          runScan();
          showToast("Pasted from clipboard.", "info");
        }
      } catch {
        showToast("Could not access clipboard directly.", "warning");
      }
    });

    async function copyRedacted() {
      const text = redactedPre.textContent;
      if (text) {
        await navigator.clipboard.writeText(text);
        showToast("Copied sanitized text to clipboard!", "success");
      }
    }

    btnCopyRedacted?.addEventListener("click", copyRedacted);
    document.getElementById("btnCopyRedactedBox")?.addEventListener("click", copyRedacted);
  }

  // ─── File Auditor Setup ───
  function setupFileAuditor() {
    const dropzone = document.getElementById("fileDropzone");
    const fileInput = document.getElementById("fileInput");
    const btnBrowse = document.getElementById("btnBrowseFile");
    const resultsArea = document.getElementById("fileResultsArea");
    const fileNameEl = document.getElementById("auditedFileName");
    const fileMetaEl = document.getElementById("auditedFileMeta");
    const dangerCountEl = document.getElementById("fileDangerCount");
    const warnCountEl = document.getElementById("fileWarnCount");
    const findingsBody = document.getElementById("fileFindingsBody");
    const btnExportSanitized = document.getElementById("btnExportSanitizedFile");

    btnBrowse?.addEventListener("click", () => fileInput?.click());
    dropzone?.addEventListener("click", (e) => {
      if (e.target !== btnBrowse) fileInput?.click();
    });

    dropzone?.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropzone.classList.add("dragover");
    });

    dropzone?.addEventListener("dragleave", () => {
      dropzone.classList.remove("dragover");
    });

    dropzone?.addEventListener("drop", (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
      if (e.dataTransfer.files.length) {
        handleFile(e.dataTransfer.files[0]);
      }
    });

    fileInput?.addEventListener("change", (e) => {
      if (e.target.files.length) {
        handleFile(e.target.files[0]);
      }
    });

    async function handleFile(file) {
      if (!file) return;
      activeAuditedFileName = file.name;
      const sizeKB = (file.size / 1024).toFixed(1);

      const reader = new FileReader();
      reader.onload = async (event) => {
        const text = event.target.result;
        activeAuditedFileContent = text;
        const lines = text.split(/\r?\n/);

        fileNameEl.textContent = file.name;
        fileMetaEl.textContent = `${sizeKB} KB • ${lines.length} lines`;

        let dangerCount = 0;
        let warnCount = 0;
        const findings = [];

        // Scan line-by-line
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (!line.trim()) continue;

          const res = await window.piiGuardAPI?.scanText(line);
          if (res && res.detections && res.detections.length) {
            for (const d of res.detections) {
              if (d.severity === "danger") dangerCount++;
              else warnCount++;
              findings.push({
                lineNumber: i + 1,
                type: d.type,
                severity: d.severity,
                masked: d.masked || d.rawText,
                confidence: d.confidence,
                validated: d.validated,
              });
            }
          }
        }

        dangerCountEl.textContent = `${dangerCount} Critical Threats`;
        warnCountEl.textContent = `${warnCount} Warnings`;

        if (findings.length === 0) {
          findingsBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding: 24px; color: #34d399;">✅ No PII detected! This document appears clean.</td></tr>`;
        } else {
          findingsBody.innerHTML = findings.slice(0, 100).map((f) => `
            <tr>
              <td>Line ${f.lineNumber}</td>
              <td><b>${escapeHtml(f.type)}</b></td>
              <td><span class="badge-risk ${f.severity === 'danger' ? 'badge-danger' : 'badge-warning'}">${f.severity}</span></td>
              <td class="code-cell" style="color: #fca5a5;">${escapeHtml(f.masked)}</td>
              <td>${f.validated ? '✓ Verified' : `${Math.round(f.confidence * 100)}%`}</td>
            </tr>`).join("");
        }

        // Full document redaction
        const fullRes = await window.piiGuardAPI?.scanText(text);
        activeAuditedRedacted = fullRes?.redactedText || text;

        resultsArea.style.display = "block";
        showToast(`Audit completed: ${findings.length} PII instance(s) found.`, findings.length ? "warning" : "success");
      };

      reader.readAsText(file);
    }

    btnExportSanitized?.addEventListener("click", () => {
      if (!activeAuditedRedacted) return;
      const blob = new Blob([activeAuditedRedacted], { type: "text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `sanitized_${activeAuditedFileName || "document.txt"}`;
      a.click();
      URL.revokeObjectURL(url);
      showToast("Exported sanitized document.", "success");
    });
  }

  // ─── History & Audit Log Setup ───
  function setupHistory() {
    const searchInput = document.getElementById("inputSearchHistory");
    const severitySelect = document.getElementById("selectSeverityFilter");
    const btnClear = document.getElementById("btnClearHistory");
    const btnExport = document.getElementById("btnExportHistory");

    searchInput?.addEventListener("input", renderHistoryTable);
    severitySelect?.addEventListener("change", renderHistoryTable);

    btnClear?.addEventListener("click", async () => {
      if (confirm("Are you sure you want to clear the entire PII alert audit log?")) {
        await window.piiGuardAPI?.clearHistory();
        currentHistory = [];
        renderHistoryTable();
        renderRecentAlertFeed();
        renderState();
        showToast("Audit history cleared.", "info");
      }
    });

    btnExport?.addEventListener("click", () => {
      if (!currentHistory.length) {
        showToast("No history records to export.", "warning");
        return;
      }
      const headers = ["Timestamp", "Source", "PII Type", "Severity", "Masked Value", "Verified", "Message"];
      const rows = currentHistory.map((h) => [
        `"${h.timestamp || ''}"`,
        `"${h.source || ''}"`,
        `"${h.type || ''}"`,
        `"${h.severity || ''}"`,
        `"${(h.masked || '').replace(/"/g, '""')}"`,
        `"${h.validated ? 'Yes' : 'No'}"`,
        `"${(h.message || '').replace(/"/g, '""')}"`,
      ]);
      const csvContent = [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
      const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `pii_guard_threat_log_${Date.now()}.csv`;
      a.click();
      URL.revokeObjectURL(url);
      showToast("Threat log exported to CSV.", "success");
    });
  }

  function renderHistoryTable() {
    const tableBody = document.getElementById("historyTableBody");
    if (!tableBody) return;

    const searchTerm = (document.getElementById("inputSearchHistory")?.value || "").toLowerCase();
    const severityFilter = document.getElementById("selectSeverityFilter")?.value || "all";

    const filtered = currentHistory.filter((item) => {
      if (severityFilter !== "all" && item.severity !== severityFilter) return false;
      if (searchTerm) {
        const text = `${item.type} ${item.source} ${item.masked} ${item.message}`.toLowerCase();
        if (!text.includes(searchTerm)) return false;
      }
      return true;
    });

    if (!filtered.length) {
      tableBody.innerHTML = `<tr><td colspan="7" style="text-align: center; padding: 32px; color: var(--text-dim);">No alerts match the criteria.</td></tr>`;
      return;
    }

    tableBody.innerHTML = filtered.map((item) => `
      <tr>
        <td style="color: var(--text-dim);">${escapeHtml(item.displayTime || item.timestamp)}</td>
        <td><span class="threat-source-pill">${escapeHtml(item.source || 'Desktop')}</span></td>
        <td><b>${escapeHtml(item.type)}</b></td>
        <td><span class="badge-risk ${item.severity === 'danger' ? 'badge-danger' : (item.severity === 'warning' ? 'badge-warning' : 'badge-info')}">${item.severity}</span></td>
        <td class="code-cell" style="color: #fca5a5;">${escapeHtml(item.masked || item.rawText)}</td>
        <td>${item.validated ? '<span class="tag-status">✓ Validated</span>' : '<span style="color: var(--text-dim);">Heuristic</span>'}</td>
        <td>
          <button class="btn-xs" onclick="navigator.clipboard.writeText('${escapeHtml(item.masked || '')}'); alert('Copied masked snippet to clipboard!');">Copy</button>
        </td>
      </tr>`).join("");
  }

  // ─── Rules Grid ───
  function renderRulesGrid() {
    const grid = document.getElementById("rulesGrid");
    if (!grid) return;

    grid.innerHTML = availableRules.map((rule) => {
      let riskBadgeClass = "badge-danger";
      if (rule.severity === "warning") riskBadgeClass = "badge-warning";
      if (rule.severity === "info") riskBadgeClass = "badge-info";

      return `
        <div class="rule-card">
          <div class="rule-card-top">
            <div>
              <div class="rule-name">${escapeHtml(rule.type)}</div>
              <div class="rule-desc">${escapeHtml(rule.description || 'Detects and alerts on matches.')}</div>
            </div>
            <label class="switch">
              <input type="checkbox" class="rule-toggle" data-rule="${escapeHtml(rule.type)}" ${rule.enabled ? 'checked' : ''}>
              <span class="slider"></span>
            </label>
          </div>
          <div class="rule-card-bottom">
            <div class="rule-tags">
              <span class="badge-risk ${riskBadgeClass}">${rule.severity}</span>
              ${rule.hasChecksum ? '<span class="tag-status" style="font-size: 10px;">Checksum Validated</span>' : ''}
            </div>
          </div>
        </div>`;
    }).join("");

    // Wire up rule toggles
    grid.querySelectorAll(".rule-toggle").forEach((toggle) => {
      toggle.addEventListener("change", async (e) => {
        const ruleName = e.target.getAttribute("data-rule");
        const enabled = e.target.checked;
        const targetRule = availableRules.find((r) => r.type === ruleName);
        if (targetRule) targetRule.enabled = enabled;

        if (!currentSettings.enabledRules) currentSettings.enabledRules = {};
        currentSettings.enabledRules[ruleName] = enabled;

        await window.piiGuardAPI?.updateSettings(currentSettings);
        renderState();
      });
    });

    document.getElementById("btnEnableAllRules")?.addEventListener("click", async () => {
      availableRules.forEach((r) => (r.enabled = true));
      if (!currentSettings.enabledRules) currentSettings.enabledRules = {};
      availableRules.forEach((r) => (currentSettings.enabledRules[r.type] = true));
      await window.piiGuardAPI?.updateSettings(currentSettings);
      renderRulesGrid();
      renderState();
      showToast("All protection rules enabled.", "success");
    });

    document.getElementById("btnDisableAllRules")?.addEventListener("click", async () => {
      availableRules.forEach((r) => (r.enabled = false));
      if (!currentSettings.enabledRules) currentSettings.enabledRules = {};
      availableRules.forEach((r) => (currentSettings.enabledRules[r.type] = false));
      await window.piiGuardAPI?.updateSettings(currentSettings);
      renderRulesGrid();
      renderState();
      showToast("All protection rules disabled.", "warning");
    });
  }

  // ─── Preferences Setup ───
  function setupPreferences() {
    const prefRealtimeTyping = document.getElementById("prefRealtimeTyping");
    const prefOverlay = document.getElementById("prefOverlay");
    const prefSound = document.getElementById("prefSound");
    const prefSystemNotif = document.getElementById("prefSystemNotif");
    const prefAutoMask = document.getElementById("prefAutoMask");
    const prefMinimizeToTray = document.getElementById("prefMinimizeToTray");
    const prefPollInterval = document.getElementById("prefPollInterval");
    const btnTestSound = document.getElementById("btnTestSound");

    btnTestSound?.addEventListener("click", () => {
      playAlertChime();
      showToast("Played alert chime test.", "info");
    });

    prefRealtimeTyping?.addEventListener("change", async (e) => {
      currentSettings.realtimeTypingMonitor = e.target.checked;
      await window.piiGuardAPI?.updateSettings(currentSettings);
      showToast(e.target.checked ? "Real-time typing monitor active." : "Real-time typing monitor paused.", e.target.checked ? "success" : "warning");
    });

    prefOverlay?.addEventListener("change", async (e) => {
      currentSettings.showDesktopOverlay = e.target.checked;
      await window.piiGuardAPI?.updateSettings(currentSettings);
    });

    prefSound?.addEventListener("change", async (e) => {
      currentSettings.soundAlerts = e.target.checked;
      await window.piiGuardAPI?.updateSettings(currentSettings);
    });

    prefSystemNotif?.addEventListener("change", async (e) => {
      currentSettings.showSystemNotification = e.target.checked;
      await window.piiGuardAPI?.updateSettings(currentSettings);
    });

    prefAutoMask?.addEventListener("change", async (e) => {
      currentSettings.autoMaskClipboard = e.target.checked;
      await window.piiGuardAPI?.updateSettings(currentSettings);
      showToast(e.target.checked ? "Auto-masking enabled for clipboard." : "Auto-masking disabled.", "info");
    });

    prefMinimizeToTray?.addEventListener("change", async (e) => {
      currentSettings.minimizeToTray = e.target.checked;
      await window.piiGuardAPI?.updateSettings(currentSettings);
    });

    prefPollInterval?.addEventListener("change", async (e) => {
      currentSettings.pollInterval = parseInt(e.target.value, 10);
      await window.piiGuardAPI?.updateSettings(currentSettings);
      showToast(`Polling rate set to ${e.target.value}ms.`, "info");
    });
  }

  // ─── Utility ───
  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // Run on load
  window.addEventListener("DOMContentLoaded", initApp);
})();
