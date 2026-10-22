(() => {
  "use strict";

  const FIELD_SELECTOR = [
    "input:not([type='password'])",
    "textarea",
    "[contenteditable]:not([contenteditable='false'])",
    "[role='textbox']",
    "[role='searchbox']",
    "[role='combobox']",
  ].join(",");

  // Loaded from patterns.js (loaded prior to content.js in manifest.json)
  function getPatterns() {
    return (
      (typeof window !== "undefined" && window.PII_PATTERNS) ||
      (typeof globalThis !== "undefined" && globalThis.PII_PATTERNS) ||
      []
    );
  }

  function getContextAnalyzer() {
    return (
      (typeof window !== "undefined" && window.PIIContextAnalyzer) ||
      (typeof globalThis !== "undefined" && globalThis.PIIContextAnalyzer) ||
      null
    );
  }

  function getDetectionEngine() {
    return (
      (typeof window !== "undefined" && window.PIIDetectionEngine) ||
      (typeof globalThis !== "undefined" && globalThis.PIIDetectionEngine) ||
      null
    );
  }

  const SAFE_TYPES = new Set([
    "button",
    "submit",
    "reset",
    "checkbox",
    "radio",
    "file",
    "image",
    "hidden",
    "password",
    "color",
    "range",
  ]);

  // ─── State ─────────────────────────────────────────────────────
  const warned = new WeakMap(); // el → warning key string
  const debounceTimers = new WeakMap(); // el → timer id
  const contextCache = new WeakMap(); // el → { context, timestamp }
  let activeWarningElement = null; // currently warned field
  const DEBOUNCE_MS = 300;
  const CONTEXT_CACHE_MS = 5000; // Re-extract context every 5s max

  let settings = { enabled: true, warnOnEveryField: false };

  // Load settings; use try/catch for environments without chrome.storage
  try {
    if (
      typeof chrome !== "undefined" &&
      chrome.storage &&
      chrome.storage.sync
    ) {
      chrome.storage.sync.get(settings, (stored) => {
        settings = { ...settings, ...stored };
      });
    }
  } catch {
    // Running in test environment without chrome API
  }

  // ─── Element Eligibility & Field Resolution ────────────────────

  function isEligible(el) {
    if (!el || (typeof Element !== "undefined" && !(el instanceof Element))) return false;
    if (el.closest && el.closest("[data-pii-guard-ui]")) return false;
    if (el.hasAttribute && (el.hasAttribute("disabled") || el.hasAttribute("readonly"))) return false;
    if (
      el.getAttribute &&
      (el.getAttribute("aria-disabled") === "true" ||
      el.getAttribute("aria-readonly") === "true")
    ) {
      return false;
    }

    if (el.matches && el.matches("input")) {
      const type = (el.getAttribute("type") || "text").toLowerCase();
      if (SAFE_TYPES.has(type)) return false;
      return true;
    }

    if (el.matches && el.matches("textarea")) return true;
    if (el.isContentEditable) return true;

    return el.matches ? el.matches(FIELD_SELECTOR) : false;
  }

  /**
   * Resolve an event target (or descendant/ancestor) to the actual editable field.
   * If an event target contains an <input> or <textarea> (e.g. in search bars or wrappers),
   * this hits the inner <input> tag directly. Also handles contenteditable roots and activeElement.
   */
  function getEditableField(target) {
    if (!target) {
      if (typeof document !== "undefined" && document.activeElement && isEligible(document.activeElement)) {
        return document.activeElement;
      }
      return null;
    }

    if (typeof Node !== "undefined" && target.nodeType === Node.TEXT_NODE) {
      target = target.parentElement;
    }
    if (!target || (typeof Element !== "undefined" && !(target instanceof Element))) {
      if (typeof document !== "undefined" && document.activeElement && isEligible(document.activeElement)) {
        return document.activeElement;
      }
      return null;
    }

    if (target.closest && target.closest("[data-pii-guard-ui]")) return null;

    // 1. Direct match: target is an eligible input, textarea, or contenteditable
    if (isEligible(target)) {
      if (target.isContentEditable) {
        const root = target.closest(
          '[contenteditable]:not([contenteditable="false"]), [role="textbox"], [role="searchbox"], [role="combobox"]'
        );
        if (root && isEligible(root)) return root;
        let curr = target;
        while (curr.parentElement && curr.parentElement.isContentEditable) {
          curr = curr.parentElement;
        }
        if (isEligible(curr)) return curr;
      }
      return target;
    }

    // 2. Look upwards: target is inside an eligible element
    if (target.closest) {
      const closest = target.closest(FIELD_SELECTOR);
      if (closest && isEligible(closest)) return closest;
    }

    // 3. Look downwards: target is a container/wrapper where an <input> or <textarea> is present
    if (target.querySelector) {
      // If current activeElement is inside target and eligible, prefer it
      if (
        typeof document !== "undefined" &&
        document.activeElement &&
        target.contains(document.activeElement) &&
        isEligible(document.activeElement)
      ) {
        return document.activeElement;
      }

      // Check for <input> or <textarea> tag present directly inside target
      const innerInput = target.querySelector(
        "input:not([type='password']), textarea, [contenteditable]:not([contenteditable='false']), [role='textbox'], [role='searchbox'], [role='combobox']"
      );
      if (innerInput && isEligible(innerInput)) {
        return innerInput;
      }
    }

    // 4. Fallback: check document.activeElement
    if (typeof document !== "undefined" && document.activeElement && isEligible(document.activeElement)) {
      return document.activeElement;
    }

    return null;
  }

  // ─── Text Extraction ──────────────────────────────────────────

  function getText(el) {
    if (!el) return "";
    // For standard input and textarea elements, always use .value
    if (
      el.matches("input, textarea") ||
      (typeof el.value === "string" && !el.isContentEditable)
    ) {
      return el.value || "";
    }
    // For contenteditable containers (ChatGPT prompt area, etc.)
    if (el.isContentEditable) {
      return (el.innerText !== undefined ? el.innerText : el.textContent) || "";
    }
    return el.value || el.innerText || el.textContent || "";
  }

  // ─── Context (with caching) ────────────────────────────────────

  function getFieldContext(el) {
    const analyzer = getContextAnalyzer();
    if (!analyzer) return null;

    // Check cache
    const cached = contextCache.get(el);
    if (cached && Date.now() - cached.timestamp < CONTEXT_CACHE_MS) {
      return cached.context;
    }

    const context = analyzer.extractFieldContext(el);
    contextCache.set(el, { context, timestamp: Date.now() });
    return context;
  }

  // ─── Detection ─────────────────────────────────────────────────

  function detect(text, el) {
    const engine = getDetectionEngine();
    const patterns = getPatterns();

    if (engine) {
      const context = getFieldContext(el);
      return engine.detectWithContext(text, context, patterns);
    }

    // Fallback: basic pattern-only detection
    const found = [];
    const seen = new Set();
    for (const item of patterns) {
      if (item.minLength && text.replace(/\s/g, "").length < item.minLength) {
        continue;
      }
      if (item.regex.lastIndex !== undefined) {
        item.regex.lastIndex = 0;
      }
      const match = item.regex.exec(text);
      if (match && !seen.has(item.type)) {
        const matchedText = match[0];
        const context = getFieldContext(el);
        let validated = false;
        if (typeof item.validate === "function") {
          try {
            validated = item.validate(matchedText, context, text);
          } catch {
            validated = false;
          }
        }
        if (item.requireValidation && !validated) {
          continue;
        }
        seen.add(item.type);
        const message =
          validated && typeof item.getDetail === "function"
            ? item.getDetail(matchedText, context, text)
            : item.description || `Detected: ${item.type}`;
        found.push({
          type: item.type,
          severity: item.severity || "warning",
          priority: item.priority || 2,
          confidence: validated ? 0.7 : 0.5,
          confidenceLabel: validated ? "format-validated" : "potential",
          validated,
          contextRelation: "neutral",
          message,
          limitations: item.limitations || "",
        });
      }
    }
    return found.sort((a, b) => b.priority - a.priority);
  }

  // ─── Styles Injection ──────────────────────────────────────────

  function ensureStyles() {
    if (
      typeof document === "undefined" ||
      !document.getElementById ||
      document.getElementById("pii-guard-style")
    ) {
      return;
    }
    try {
      const link = document.createElement("link");
      link.id = "pii-guard-style";
      link.rel = "stylesheet";
      link.href = chrome.runtime.getURL("styles.css");
      (document.head || document.documentElement).appendChild(link);
    } catch {
      // chrome.runtime may not be available in test environments
    }
  }

  // ─── Warning UI ────────────────────────────────────────────────

  function showWarning(el, matches) {
    const old = warned.get(el);
    const key = matches
      .map((m) => m.type + ":" + m.severity + ":" + m.confidenceLabel)
      .join("|");
    if (old === key) return;
    warned.set(el, key);

    // Determine highest priority severity
    const maxPriority = Math.max(...matches.map((m) => m.priority || 1));
    const highestSeverity =
      maxPriority >= 3 ? "danger" : maxPriority === 2 ? "warning" : "info";

    // Mark the input field
    el.dataset.piiFieldStatus = highestSeverity;
    activeWarningElement = el;

    // Remove existing warning (only one at a time)
    document
      .querySelectorAll("[data-pii-guard-ui='warning']")
      .forEach((n) => n.remove());

    const warning = document.createElement("div");
    warning.dataset.piiGuardUi = "warning";
    warning.dataset.piiSeverity = highestSeverity;
    warning.setAttribute("role", "status");

    const titleText =
      highestSeverity === "danger"
        ? "Critical PII Warning"
        : highestSeverity === "warning"
          ? "PII Guard Warning"
          : "PII Notice";

    const badgeLabel =
      highestSeverity === "danger"
        ? "CRITICAL"
        : highestSeverity === "warning"
          ? "MEDIUM RISK"
          : "NOTICE";

    const iconSymbol = highestSeverity === "info" ? "i" : "!";

    // Build pill items with confidence indicator
    const pillsHtml = matches
      .map((m) => {
        const confidenceBadge =
          m.confidenceLabel === "format-validated"
            ? `<span class="piig-confidence piig-confidence-validated" title="Format validated">✓</span>`
            : `<span class="piig-confidence piig-confidence-potential" title="Potential match">?</span>`;
        return `<span class="piig-pill piig-pill-${m.severity}">${confidenceBadge}${escapeHtml(m.type)}</span>`;
      })
      .join("");

    // Use the message from the highest-priority match
    const topMatch = matches[0];
    const detailMessage =
      topMatch.message || "Possible personal information detected.";
    const subtext =
      "Check before submitting. This warning is generated locally by the extension.";

    warning.innerHTML = `
      <div class="piig-header">
        <span class="piig-shield" aria-hidden="true">${iconSymbol}</span>
        <strong>${titleText}</strong>
        <span class="piig-badge">${badgeLabel}</span>
        <button type="button" class="piig-close" aria-label="Dismiss warning">×</button>
      </div>
      <p>${escapeHtml(detailMessage)}</p>
      <div class="piig-items-list">
        ${pillsHtml}
      </div>
      <p class="piig-subtext">${subtext}</p>
      <div class="piig-actions">
        <button type="button" class="piig-review">Review field</button>
        <button type="button" class="piig-dismiss">Dismiss</button>
      </div>`;

    document.documentElement.appendChild(warning);

    const cleanup = () => {
      warning.remove();
      if (el && el.dataset) {
        delete el.dataset.piiFieldStatus;
      }
      if (activeWarningElement === el) {
        activeWarningElement = null;
      }
    };

    warning.querySelector(".piig-close").addEventListener("click", cleanup);
    warning.querySelector(".piig-dismiss").addEventListener("click", cleanup);
    warning.querySelector(".piig-review").addEventListener("click", () => {
      cleanup();
      try {
        el.focus({ preventScroll: false });
      } catch {
        el.focus();
      }
    });
  }

  function clearWarning(el) {
    if (el && el.dataset) {
      delete el.dataset.piiFieldStatus;
    }
    if (el) {
      warned.delete(el);
    }
    if (!el || activeWarningElement === el) {
      const existing = document.querySelector("[data-pii-guard-ui='warning']");
      if (existing) existing.remove();
      activeWarningElement = null;
    }
  }

  function clearAllWarnings() {
    if (activeWarningElement && activeWarningElement.dataset) {
      delete activeWarningElement.dataset.piiFieldStatus;
    }
    activeWarningElement = null;
    const existing = document.querySelector("[data-pii-guard-ui='warning']");
    if (existing) existing.remove();
  }

  // ─── HTML Escaping ─────────────────────────────────────────────

  function escapeHtml(value) {
    return String(value).replace(
      /[&<>"']/g,
      (ch) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        })[ch],
    );
  }

  // ─── Debounced Input & Action Handlers ─────────────────────────

  function processField(el, overrideText) {
    if (!settings.enabled || !isEligible(el)) return;

    const text = typeof overrideText === "string" ? overrideText : getText(el);
    if (!text.trim()) {
      clearWarning(el);
      return;
    }

    const found = detect(text, el);
    if (found.length) {
      showWarning(el, found);
    } else {
      clearWarning(el);
    }
  }

  function handleInput(event) {
    const el =
      getEditableField(event.target) ||
      getEditableField(typeof document !== "undefined" ? document.activeElement : null);
    if (!el) return;

    // Cancel any pending debounce for this element
    const existingTimer = debounceTimers.get(el);
    if (existingTimer) {
      clearTimeout(existingTimer);
    }

    // Debounce: wait before processing
    const timer = setTimeout(() => {
      debounceTimers.delete(el);
      processField(el);
    }, DEBOUNCE_MS);
    debounceTimers.set(el, timer);
  }

  function handlePaste(event) {
    const el =
      getEditableField(event.target) ||
      getEditableField(typeof document !== "undefined" ? document.activeElement : null);

    // Read clipboard data directly for instantaneous detection
    let pastedText = "";
    if (event.clipboardData && typeof event.clipboardData.getData === "function") {
      try {
        pastedText = event.clipboardData.getData("text") || "";
      } catch {
        pastedText = "";
      }
    }

    if (el) {
      if (pastedText && pastedText.trim()) {
        const currentText = getText(el);
        const combinedText = currentText ? (currentText + " " + pastedText) : pastedText;
        const foundCombined = detect(combinedText, el);
        const foundPastedOnly = detect(pastedText, el);
        const matches = foundCombined.length ? foundCombined : foundPastedOnly;
        if (matches.length) {
          showWarning(el, matches);
        }
      }
      // Re-check after DOM update across multiple microtask cycles to handle all frameworks
      setTimeout(() => processField(el), 10);
      setTimeout(() => processField(el), 60);
      setTimeout(() => processField(el), 180);
    } else if (pastedText && pastedText.trim()) {
      // Fallback: check if activeElement or any input exists
      if (typeof document !== "undefined") {
        const focused =
          document.querySelector("input:focus, textarea:focus, [contenteditable]:focus") ||
          document.querySelector("input:not([type='password']), textarea");
        if (focused && isEligible(focused)) {
          const found = detect(pastedText, focused);
          if (found.length) {
            showWarning(focused, found);
          }
          setTimeout(() => processField(focused), 60);
        }
      }
    }
  }

  function handleCopyCut(event) {
    const el =
      getEditableField(event.target) ||
      getEditableField(typeof document !== "undefined" ? document.activeElement : null);
    if (!el) return;

    let selectedText = "";
    if (typeof window !== "undefined" && window.getSelection) {
      selectedText = window.getSelection().toString();
    }
    if (!selectedText && typeof el.selectionStart === "number" && typeof el.selectionEnd === "number") {
      const val = getText(el);
      selectedText = val.slice(el.selectionStart, el.selectionEnd);
    }
    if (!selectedText) {
      selectedText = getText(el);
    }

    if (selectedText && selectedText.trim()) {
      const found = detect(selectedText, el);
      if (found.length) {
        showWarning(el, found);
      }
    }

    if (event.type === "cut") {
      setTimeout(() => processField(el), 40);
    }
  }

  // ─── MutationObserver for Dynamic Fields & Value Changes ──────

  function observeDynamicFields() {
    const observer = new MutationObserver((mutations) => {
      // If currently warned element was cleared programmatically (e.g. ChatGPT submit or React reset)
      if (activeWarningElement) {
        const currentText = getText(activeWarningElement);
        if (!currentText.trim()) {
          clearWarning(activeWarningElement);
        }
      }

      for (const mutation of mutations) {
        if (mutation.type !== "childList") continue;
        for (const node of mutation.addedNodes) {
          if (!(node instanceof Element)) continue;
          // Check the node itself
          if (isEligible(node)) {
            // Invalidate context cache for new elements
            contextCache.delete(node);
          }
          // Check descendants
          const fields = node.querySelectorAll
            ? node.querySelectorAll(FIELD_SELECTOR)
            : [];
          for (const field of fields) {
            contextCache.delete(field);
          }
        }
      }
    });

    observer.observe(document.body || document.documentElement, {
      childList: true,
      subtree: true,
      characterData: true,
    });
  }

  // ─── Initialization ────────────────────────────────────────────

  ensureStyles();
  document.addEventListener("input", handleInput, true);
  document.addEventListener("keyup", handleInput, true);
  document.addEventListener("change", handleInput, true);
  document.addEventListener("paste", handlePaste, true);
  document.addEventListener("copy", handleCopyCut, true);
  document.addEventListener("cut", handleCopyCut, true);
  document.addEventListener("drop", handlePaste, true);
  document.addEventListener("focusin", handleInput, true);
  document.addEventListener("submit", clearAllWarnings, true);
  document.addEventListener("reset", clearAllWarnings, true);

  // When Enter is pressed without Shift (e.g. ChatGPT send or search bar enter),
  // re-check field in case it was cleared by the application
  document.addEventListener(
    "keydown",
    (event) => {
      if (event.key === "Enter" && !event.shiftKey) {
        const el = getEditableField(event.target);
        if (el) {
          setTimeout(() => {
            processField(el);
          }, 150);
        }
      }
    },
    true
  );

  // Start observing for dynamic fields
  if (document.body) {
    observeDynamicFields();
  } else {
    document.addEventListener("DOMContentLoaded", observeDynamicFields);
  }

  // ─── Exports (for testing) ─────────────────────────────────────

  const PIIGuardContent = {
    isEligible,
    getEditableField,
    getText,
    detect,
    processField,
    getFieldContext,
    escapeHtml,
    clearWarning,
    clearAllWarnings,
  };

  if (typeof window !== "undefined") {
    window.PIIGuardContent = PIIGuardContent;
  }
  if (typeof globalThis !== "undefined") {
    globalThis.PIIGuardContent = PIIGuardContent;
  }
})();
