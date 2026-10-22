/**
 * PII Guard — Context Analyzer
 * Extracts and normalizes contextual clues from HTML input fields
 * to assist the detection engine in reducing false positives.
 *
 * Inspects: labels, placeholder, name, id, type, autocomplete,
 * aria-label, aria-labelledby, fieldset legends, nearby headings.
 *
 * Does NOT scan the entire page — uses targeted DOM inspection.
 */
(() => {
  "use strict";

  // ─── Keyword Groups ──────────────────────────────────────────────
  // Each group maps a PII category to an array of keyword tokens.
  // Matching is case-insensitive and tokenized (words, not substrings).
  // The analyzer checks whether ANY token from a group appears in
  // the normalized context text.

  const KEYWORD_GROUPS = {
    email: [
      "email", "e-mail", "mail", "gmail", "yahoo mail", "outlook",
      "email address", "mail id", "email id", "e mail",
    ],
    phone: [
      "contact", "contact no", "contact num", "contact number",
      "contact details", "contact person", "contacts", "emergency contact",
      "phone", "phone no", "phone number", "phone num",
      "mobile", "mobile no", "mobile number", "mobile num",
      "cell", "cellphone", "cell phone", "telephone", "tel", "landline",
      "whatsapp", "sms", "caller", "call", "helpline", "toll free",
      "country code", "calling code", "dial code", "dialing code", "isd", "std",
      "isd code", "std code", "area code", "intl", "international",
    ],
    credit_card: [
      "card number", "card no", "credit card", "debit card",
      "payment card", "card num", "cc number", "cc num",
      "cardholder", "card holder", "card details", "card info",
    ],
    aadhaar: [
      "aadhaar", "aadhar", "uidai", "uid number", "aadhaar number",
      "aadhar number", "aadhaar no",
    ],
    pan: [
      "pan", "pan number", "pan no", "pan card", "permanent account",
    ],
    passport: [
      "passport", "passport number", "passport no",
    ],
    ssn: [
      "ssn", "social security", "social security number",
    ],
    iban: [
      "iban", "bank account", "account number", "bank account number",
    ],
    dob: [
      "date of birth", "dob", "birth date", "birthday",
    ],
    address: [
      "address", "street", "city", "zip", "postal", "pin code",
      "pincode", "zip code", "zipcode",
    ],
    ip: [
      "ip address", "ip", "ipv4", "ipv6",
    ],
    driving_license: [
      "driving license", "driving licence", "dl number", "dl no",
      "driver license", "driver licence",
    ],
    voter_id: [
      "voter id", "voter", "epic", "election id",
    ],
    ifsc: [
      "ifsc", "ifsc code", "bank code",
    ],
    crypto: [
      "wallet", "crypto", "bitcoin", "ethereum", "wallet address",
    ],
    // Negative context — fields that are clearly NOT PII-related
    non_pii: [
      "product id", "product code", "order id", "order number",
      "reference", "reference number", "ref", "ref no", "ref number",
      "sku", "item number", "item id", "serial", "serial number",
      "invoice", "invoice number", "tracking", "tracking number",
      "ticket", "ticket number", "transaction id", "coupon",
      "coupon code", "promo", "promo code", "discount code",
      "captcha", "otp", "verification code", "quantity", "qty",
      "amount", "price", "total", "subtotal",
    ],
  };

  // Map PII category keywords to the pattern type names used in patterns.js
  const CATEGORY_TO_PATTERN_TYPE = {
    email: "Email address",
    phone: [
      "Contact / Phone number",
      "Contact number",
      "Mobile number",
      "Phone number",
    ],
    credit_card: "Credit/debit card-like number",
    aadhaar: "Indian Aadhaar-like number",
    pan: "PAN-like number",
    passport: "Passport number",
    ssn: "US Social Security Number (SSN)",
    iban: "International Bank Account Number (IBAN)",
    dob: "Date of Birth (DD/MM/YYYY)",
    ip: "IPv4 address",
    driving_license: "Indian Driving License",
    voter_id: "Indian Voter ID (EPIC)",
    ifsc: "Indian IFSC Code",
    crypto: "Cryptocurrency wallet address",
    address: ["Indian PIN code", "US ZIP+4 code"],
  };

  /**
   * Normalize text for keyword matching.
   * Lowercases, replaces punctuation/separators with spaces, collapses whitespace.
   * @param {string} text
   * @returns {string}
   */
  function normalizeText(text) {
    if (!text) return "";
    return text
      .toLowerCase()
      .replace(/[_\-./]+/g, " ")   // Replace common separators with space
      .replace(/[^a-z0-9\s]/g, "") // Remove remaining non-alphanumeric
      .replace(/\s+/g, " ")        // Collapse whitespace
      .trim();
  }

  /**
   * Extract all context strings from an input element.
   * Returns an object with raw attribute values and a combined normalized string.
   * @param {Element} el
   * @returns {Object}
   */
  function extractFieldContext(el) {
    if (!el || (typeof Element !== "undefined" && !(el instanceof Element))) {
      return { raw: {}, normalized: "", categories: [], nonPii: false };
    }

    const raw = {};

    // Direct attributes
    raw.type = (el.getAttribute("type") || "").toLowerCase();
    raw.name = el.getAttribute("name") || "";
    raw.id = el.getAttribute("id") || "";
    raw.placeholder =
      el.getAttribute("placeholder") ||
      el.getAttribute("data-placeholder") ||
      el.getAttribute("aria-placeholder") ||
      "";
    raw.autocomplete = el.getAttribute("autocomplete") || "";
    raw.ariaLabel = el.getAttribute("aria-label") || "";

    // aria-labelledby — resolve to text
    const labelledById = el.getAttribute("aria-labelledby");
    if (labelledById) {
      const parts = labelledById.split(/\s+/);
      raw.ariaLabelledBy = parts
        .map((id) => {
          const ref = document.getElementById(id);
          return ref ? (ref.textContent || "").trim() : "";
        })
        .filter(Boolean)
        .join(" ");
    } else {
      raw.ariaLabelledBy = "";
    }

    // Associated <label> via `for` attribute or wrapping <label>
    raw.label = "";
    if (el.id) {
      const labelEl = document.querySelector(`label[for="${CSS.escape(el.id)}"]`);
      if (labelEl) {
        raw.label = (labelEl.textContent || "").trim();
      }
    }
    if (!raw.label) {
      const wrappingLabel = el.closest("label");
      if (wrappingLabel) {
        // Get label text excluding the input's own content
        const clone = wrappingLabel.cloneNode(true);
        const inputs = clone.querySelectorAll("input, textarea, select");
        inputs.forEach((inp) => inp.remove());
        raw.label = (clone.textContent || "").trim();
      }
    }

    // Fieldset legend
    raw.legend = "";
    const fieldset = el.closest("fieldset");
    if (fieldset) {
      const legend = fieldset.querySelector("legend");
      if (legend) {
        raw.legend = (legend.textContent || "").trim();
      }
    }

    // Nearby heading (look for preceding heading in the same parent, max 3 siblings up)
    raw.nearbyHeading = "";
    let sibling = el.previousElementSibling;
    let hops = 0;
    while (sibling && hops < 3) {
      if (/^H[1-6]$/i.test(sibling.tagName)) {
        raw.nearbyHeading = (sibling.textContent || "").trim();
        break;
      }
      // Also check inside the sibling for a heading
      const innerH = sibling.querySelector("h1,h2,h3,h4,h5,h6");
      if (innerH) {
        raw.nearbyHeading = (innerH.textContent || "").trim();
        break;
      }
      sibling = sibling.previousElementSibling;
      hops++;
    }
    // Also check parent's previous siblings (one level up)
    if (!raw.nearbyHeading && el.parentElement) {
      let parentSibling = el.parentElement.previousElementSibling;
      let pHops = 0;
      while (parentSibling && pHops < 2) {
        if (/^H[1-6]$/i.test(parentSibling.tagName)) {
          raw.nearbyHeading = (parentSibling.textContent || "").trim();
          break;
        }
        const innerH = parentSibling.querySelector("h1,h2,h3,h4,h5,h6");
        if (innerH) {
          raw.nearbyHeading = (innerH.textContent || "").trim();
          break;
        }
        parentSibling = parentSibling.previousElementSibling;
        pHops++;
      }
    }

    // Build combined normalized string
    const combined = [
      raw.label,
      raw.placeholder,
      raw.name,
      raw.id,
      raw.autocomplete,
      raw.ariaLabel,
      raw.ariaLabelledBy,
      raw.legend,
      raw.nearbyHeading,
    ]
      .filter(Boolean)
      .join(" ");

    const normalized = normalizeText(combined);

    // Determine matching categories
    const categories = matchCategories(normalized, raw.type, raw.autocomplete);
    const nonPii = isNonPiiContext(normalized);

    return { raw, normalized, categories, nonPii };
  }

  /**
   * Match the normalized context string against keyword groups.
   * Also considers HTML type and autocomplete attributes.
   * @param {string} normalized
   * @param {string} inputType
   * @param {string} autocomplete
   * @returns {string[]} Array of matched PII category keys
   */
  function matchCategories(normalized, inputType, autocomplete) {
    const matched = [];

    // HTML input type mapping
    if (inputType === "email") matched.push("email");
    if (inputType === "tel") matched.push("phone");

    // Autocomplete attribute mapping
    const ac = (autocomplete || "").toLowerCase();
    if (ac.includes("email")) matched.push("email");
    if (ac.includes("tel")) matched.push("phone");
    if (ac.includes("cc-number")) matched.push("credit_card");
    if (ac.includes("bday")) matched.push("dob");
    if (ac.includes("postal-code")) matched.push("address");
    if (ac.includes("street-address")) matched.push("address");

    if (!normalized) return [...new Set(matched)];

    // Keyword matching: check if any keyword phrase appears in the normalized text
    for (const [category, keywords] of Object.entries(KEYWORD_GROUPS)) {
      if (category === "non_pii") continue; // handled separately
      for (const keyword of keywords) {
        const normKeyword = normalizeText(keyword);
        if (containsPhrase(normalized, normKeyword)) {
          matched.push(category);
          break; // One keyword match per category is sufficient
        }
      }
    }

    return [...new Set(matched)];
  }

  /**
   * Check if the context suggests a non-PII field.
   * @param {string} normalized
   * @returns {boolean}
   */
  function isNonPiiContext(normalized) {
    if (!normalized) return false;
    const nonPiiKeywords = KEYWORD_GROUPS.non_pii;
    for (const keyword of nonPiiKeywords) {
      const normKeyword = normalizeText(keyword);
      if (containsPhrase(normalized, normKeyword)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Check if a phrase (potentially multi-word) appears in the text
   * as a word boundary match.
   * @param {string} text — normalized text to search in
   * @param {string} phrase — normalized phrase to search for
   * @returns {boolean}
   */
  function containsPhrase(text, phrase) {
    if (!text || !phrase) return false;
    // Use word boundary matching via regex
    // Escape regex special chars in the phrase
    const escaped = phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp("(?:^|\\s)" + escaped + "(?:\\s|$)");
    return re.test(" " + text + " ");
  }

  /**
   * Get the pattern type names that correspond to a context category.
   * @param {string} category
   * @returns {string[]}
   */
  function getPatternTypesForCategory(category) {
    const mapping = CATEGORY_TO_PATTERN_TYPE[category];
    if (!mapping) return [];
    return Array.isArray(mapping) ? mapping : [mapping];
  }

  // ─── Exports ─────────────────────────────────────────────────────
  const ContextAnalyzer = {
    extractFieldContext,
    normalizeText,
    matchCategories,
    isNonPiiContext,
    getPatternTypesForCategory,
    KEYWORD_GROUPS,
    CATEGORY_TO_PATTERN_TYPE,
  };

  if (typeof window !== "undefined") {
    window.PIIContextAnalyzer = ContextAnalyzer;
  }
  if (typeof globalThis !== "undefined") {
    globalThis.PIIContextAnalyzer = ContextAnalyzer;
  }
  if (typeof module !== "undefined" && module.exports) {
    module.exports = ContextAnalyzer;
  }
})();
