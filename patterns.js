/**
 * PII Guard — Enhanced Pattern Definitions
 * Each pattern defines:
 *   type     — Human-readable PII category name
 *   regex    — RegExp for initial candidate detection (no global flag to avoid stateful issues)
 *   severity — 'danger' | 'warning' | 'info'
 *   priority — 1 (low) | 2 (medium) | 3 (critical)
 *   minLength — Minimum input length before this pattern is evaluated
 *   validate — Optional function(matchedText) => boolean for format/checksum validation
 *   description — Brief explanation shown in warnings
 *   limitations — Documents what this detector cannot verify
 *
 * IMPORTANT: Regexes must NOT use the 'g' or 'y' flags to avoid
 * stateful lastIndex issues when called repeatedly via .test().
 */

// ─── Validation Helpers ──────────────────────────────────────────

/**
 * Luhn checksum algorithm for credit/debit card validation.
 * @param {string} numStr — digits only
 * @returns {boolean}
 */
function luhnCheck(numStr) {
  const digits = numStr.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

/**
 * Identify card network from prefix (BIN range) and valid network length.
 * Returns network name or null if unrecognized.
 * @param {string} digits — digits only
 * @returns {string|null}
 */
function identifyCardNetwork(digits) {
  if (!digits || digits.length < 13) return null;
  const d = digits.replace(/\D/g, "");
  const len = d.length;

  // Visa: starts with 4 (13, 16, or 19 digits)
  if (/^4/.test(d) && (len === 13 || len === 16 || len === 19)) return "Visa";

  // Mastercard: 51-55 or 2221-2720 (16 digits)
  if (len === 16) {
    if (/^5[1-5]/.test(d)) return "Mastercard";
    const prefix4 = parseInt(d.substring(0, 4), 10);
    if (prefix4 >= 2221 && prefix4 <= 2720) return "Mastercard";
  }

  // Amex: 34 or 37 (15 digits)
  if (/^3[47]/.test(d) && len === 15) return "Amex";

  // Diners Club: 300-305, 36, 38 (14-16 digits)
  if (/^3(?:0[0-5]|[68])/.test(d) && len >= 14 && len <= 16) return "Diners Club";

  // JCB: 3528-3589 (16 digits)
  if (len === 16) {
    const prefix4 = parseInt(d.substring(0, 4), 10);
    if (prefix4 >= 3528 && prefix4 <= 3589) return "JCB";
  }

  // Discover: 6011, 644-649, 65, 622126-622925 (16 or 19 digits)
  if (len === 16 || len === 19) {
    if (/^(6011|64[4-9]|65)/.test(d)) return "Discover";
    const prefix6 = parseInt(d.substring(0, 6), 10);
    if (prefix6 >= 622126 && prefix6 <= 622925) return "Discover";
  }

  // RuPay: 60, 65, 81, 82, 508 (16 digits)
  if (len === 16 && /^(60|65|81|82|508)/.test(d)) return "RuPay";

  // Maestro: 50, 56-58, 6 (12-19 digits)
  if (/^(50|5[6-8]|6)/.test(d) && len >= 12 && len <= 19) return "Maestro";

  return null;
}

/**
 * Validate payment card (Credit/Debit) plausibility and format.
 * - Rejects dummy/sequential/repeated numbers.
 * - Must belong to a known card network (Visa, Mastercard, Amex, Discover, RuPay, etc.).
 * - Must pass Luhn checksum.
 * @param {string} text
 * @returns {boolean}
 */
function validateCreditCard(text) {
  const digits = text.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;

  // Reject all identical digits (e.g. 0000000000000000, 8888888888888888)
  if (/^(\d)\1+$/.test(digits)) return false;

  // Reject trivial sequential digits
  if (digits.startsWith("0123456789") || digits.startsWith("1234567890")) return false;

  // Must belong to a recognized card network
  const network = identifyCardNetwork(digits);
  if (!network) return false;

  // Must pass Luhn checksum
  return luhnCheck(digits);
}

/**
 * IBAN MOD-97 checksum validation.
 * @param {string} iban — raw IBAN string (may contain spaces/hyphens)
 * @returns {boolean}
 */
function validateIBAN(iban) {
  const cleaned = iban.replace(/[\s-]/g, "").toUpperCase();
  if (cleaned.length < 5 || cleaned.length > 34) return false;

  // Country-specific length validation (common countries)
  const countryLengths = {
    AL: 28, AD: 24, AT: 20, AZ: 28, BH: 22, BY: 28, BE: 16, BA: 20,
    BR: 29, BG: 22, CR: 22, HR: 21, CY: 28, CZ: 24, DK: 18, DO: 28,
    EE: 20, FO: 18, FI: 18, FR: 27, GE: 22, DE: 22, GI: 23, GR: 27,
    GL: 18, GT: 28, HU: 28, IS: 26, IQ: 23, IE: 22, IL: 23, IT: 27,
    JO: 30, KZ: 20, XK: 20, KW: 30, LV: 21, LB: 28, LI: 21, LT: 20,
    LU: 20, MT: 31, MR: 27, MU: 30, MD: 24, MC: 27, ME: 22, NL: 18,
    MK: 19, NO: 15, PK: 24, PS: 29, PL: 28, PT: 25, QA: 29, RO: 24,
    LC: 32, SM: 27, ST: 25, SA: 24, RS: 22, SC: 31, SK: 24, SI: 19,
    ES: 24, SE: 24, CH: 21, TL: 23, TN: 24, TR: 26, UA: 29, AE: 23,
    GB: 22, VA: 22, VG: 24,
  };
  const country = cleaned.substring(0, 2);
  const expectedLength = countryLengths[country];
  if (expectedLength && cleaned.length !== expectedLength) return false;

  // MOD-97 check: move first 4 chars to end, convert letters to numbers
  const rearranged = cleaned.substring(4) + cleaned.substring(0, 4);
  const numStr = rearranged.replace(/[A-Z]/g, (ch) => (ch.charCodeAt(0) - 55).toString());

  // Compute mod 97 using chunks (avoid BigInt for compatibility)
  let remainder = "";
  for (const digit of numStr) {
    remainder += digit;
    remainder = (parseInt(remainder, 10) % 97).toString();
  }
  return parseInt(remainder, 10) === 1;
}

/**
 * Validate IPv4: each octet must be 0-255, no leading zeros.
 * @param {string} ip
 * @returns {boolean}
 */
function validateIPv4(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return false;
    const num = parseInt(part, 10);
    if (num < 0 || num > 255) return false;
    // Reject leading zeros (e.g., "01" is not valid standard notation)
    if (part.length > 1 && part[0] === "0") return false;
  }
  return true;
}

/**
 * Validate phone / contact number format and plausibility.
 * Supports national formats (10-11 digits) and international E.164 formats with
 * country codes (+, 00, or (+countryCode) prefix; 8-15 digits).
 * For raw unformatted 10-digit numbers, requires context support (contact/phone/mobile)
 * to prevent random numbers in generic fields from triggering false alarms.
 * @param {string} text — matched phone text
 * @param {string} text — phone string candidate
 * @param {Object} [fieldContext] — context extracted by ContextAnalyzer
 * @param {string} [fullText] — full input text of the field
 * @returns {boolean}
 */
function validatePhone(text, fieldContext, fullText) {
  const digits = text.replace(/\D/g, "");
  // Phone numbers must have at least 8 digits (international) and at most 15 digits (ITU-T E.164)
  if (digits.length < 8 || digits.length > 15) return false;

  // Reject all identical digits or runs of 7+ identical digits (e.g. +91 1111111111, +1 0000000000)
  if (/^(\d)\1+$/.test(digits) || /(\d)\1{6,}/.test(digits)) return false;

  // Reject trivial sequential digits (e.g. 1234567890, 0123456789, 123456789012)
  if (digits === "1234567890" || digits === "0123456789" || digits === "123456789012") return false;

  // Check if text has explicit international prefix (+, 00, or (+...))
  const hasIntlPrefix = /^\s*(?:\+|\(\+|00|\(00)/.test(text);

  // Check if text has phone formatting evidence (parentheses, hyphens, dots, spaces, leading +)
  const hasFormatting = /[\(\)\-.\s+]/.test(text.trim());

  // Check if field context indicates contact/phone/mobile
  const contextSupports = Boolean(
    fieldContext &&
    fieldContext.categories &&
    fieldContext.categories.includes("phone")
  );

  // Check if surrounding/full text contains phone-related keywords
  const textHasPhoneKeyword = Boolean(
    fullText &&
    /\b(phone|mobile|contact|call|cell|tel|telephone|whatsapp|sms|caller|helpline)\b/i.test(fullText)
  );

  // If international country code prefix is present (+91..., 0091..., (+1)...),
  // E.164 valid lengths are 8 to 15 digits
  if (hasIntlPrefix) {
    return digits.length >= 8 && digits.length <= 15;
  }

  // Without international prefix, require at least 10 digits
  if (digits.length < 10) return false;

  // Indian mobile: 10 digits starting with 6, 7, 8, 9 (e.g. 9876543210)
  if (digits.length === 10 && /^[6-9]/.test(digits)) return true;

  // Numbers with STD / area code or national trunk 0 (e.g. 09876543210, 011-..., 080-...)
  if (text.trim().startsWith("0") && digits.length >= 10 && digits.length <= 11) return true;

  // Indian mobile prefixed with 91: 12 digits (e.g. 919876543210 or 91-9876543210)
  if (digits.length === 12 && /^91[6-9]\d{9}$/.test(digits)) return true;

  // Formatted with separators and 10+ digits (e.g. (555) 123-4567, 555-123-4567, 98765-43210)
  if (hasFormatting && digits.length >= 10) return true;

  // North American format / generic 10-11 digits when field or surrounding text has phone context
  if (contextSupports || textHasPhoneKeyword) {
    if (digits.length === 10 && /^[2-9]/.test(digits)) return true;
    if (digits.length === 11 && digits.startsWith("1") && /^1[2-9]/.test(digits)) return true;
  }

  return false;
}

/**
 * Validate PAN structure: AAAAA9999A
 * 4th character indicates holder type.
 * @param {string} pan
 * @returns {boolean}
 */
function validatePAN(pan) {
  const cleaned = pan.trim().toUpperCase();
  if (!/^[A-Z]{5}\d{4}[A-Z]$/.test(cleaned)) return false;
  // 4th character must be a valid entity type
  const validTypes = "ABCFGHLJPT";
  return validTypes.includes(cleaned[3]);
}

// ─── Verhoeff Algorithm Tables ──────────────────────────────────
// Dihedral group D5 multiplication table
const VERHOEFF_D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

// Permutation table
const VERHOEFF_P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

// Multiplicative inverse table in D5
const VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

/**
 * Validate a numeric string using the Verhoeff algorithm.
 * @param {string} numStr — digits string (can include spaces/separators)
 * @returns {boolean}
 */
function verhoeffCheck(numStr) {
  let c = 0;
  const digits = numStr.replace(/\D/g, "");
  if (!digits) return false;
  const reversed = digits.split("").reverse().map(Number);
  for (let i = 0; i < reversed.length; i++) {
    c = VERHOEFF_D[c][VERHOEFF_P[i % 8][reversed[i]]];
  }
  return c === 0;
}

/**
 * Calculate the Verhoeff check digit for an 11-digit or general numeric string.
 * @param {string} numStr — digits string without check digit
 * @returns {number} — the check digit (0-9)
 */
function verhoeffGenerate(numStr) {
  let c = 0;
  const digits = numStr.replace(/\D/g, "");
  const reversed = digits.split("").reverse().map(Number);
  for (let i = 0; i < reversed.length; i++) {
    c = VERHOEFF_D[c][VERHOEFF_P[(i + 1) % 8][reversed[i]]];
  }
  return VERHOEFF_INV[c];
}

/**
 * Validate Indian Aadhaar number using Mathematical and Format Logic:
 * 1. Length and Structure: Exactly 12 numeric digits.
 * 2. Cannot start with 0 or 1 (the first digit must range from 2 to 9).
 * 3. Verhoeff Algorithm: The 12th digit is a check digit calculated using
 *    the Verhoeff algorithm to catch human typos and single-digit/transposition errors.
 * 4. Repetition check: Reject numbers with 12 identical digits.
 * @param {string} text — matched text (may include separators)
 * @returns {boolean}
 */
function validateAadhaar(text, fieldContext, fullText) {
  // Reject if digits are part of an email address local-part (e.g. 212072531248@gmail.com)
  if (fullText && (fullText.includes(text + "@") || /@\S*$/.test(text))) {
    return false;
  }
  const digits = text.replace(/\D/g, "");
  // Exactly 12 numeric digits
  if (digits.length !== 12) return false;
  // First digit cannot be 0 or 1 (must be 2-9)
  const firstDigit = digits.charCodeAt(0) - 48;
  if (firstDigit < 2 || firstDigit > 9) return false;
  // Repetition check — all identical digits is invalid
  if (/^(\d)\1{11}$/.test(digits)) return false;
  // Verhoeff checksum validation
  return verhoeffCheck(digits);
}

/**
 * Validate SSN structure beyond regex.
 * @param {string} text
 * @returns {boolean}
 */
function validateSSN(text) {
  const digits = text.replace(/\D/g, "");
  if (digits.length !== 9) return false;
  // Already handled by regex: area != 000, 666, 9xx; group != 00; serial != 0000
  return true;
}

/**
 * Validate Indian Driving License format.
 * @param {string} text
 * @returns {boolean}
 */
function validateDrivingLicense(text) {
  const cleaned = text.replace(/[\s-]/g, "").toUpperCase();
  // Format: SS-DD-YYYY-NNNNNNN (state code, district, year, serial)
  if (cleaned.length < 15 || cleaned.length > 16) return false;
  return true;
}

// ─── Pattern Definitions ─────────────────────────────────────────

const PATTERNS = [
  // --- Critical / High Priority (Danger) ---
  {
    type: "Credit/debit card-like number",
    regex: /(?<!\d)\b[1-9](?:[ -]?\d){12,18}\b(?!\d)/,
    severity: "danger",
    priority: 3,
    minLength: 13,
    requireValidation: false,
    validate: validateCreditCard,
    getDetail(text) {
      const digits = text.replace(/\D/g, "");
      const network = identifyCardNetwork(digits);
      return `Matches ${network || "payment"} card format and passes Luhn checksum.`;
    },
    description: "This value matches a payment card format.",
    limitations: "Luhn and card network validation confirm format plausibility, not active issuance.",
  },
  {
    type: "US Social Security Number (SSN)",
    regex: /\b(?!000|666|9\d{2})\d{3}[ -](?!00)\d{2}[ -](?!0000)\d{4}\b/,
    severity: "danger",
    priority: 3,
    minLength: 9,
    validate: validateSSN,
    description: "This value matches the US Social Security Number format.",
    limitations: "Format match only; cannot verify SSN issuance.",
  },
  {
    type: "Indian Aadhaar-like number",
    regex: /(?<![+\d@.])(?<!\d{4}[ -])\b[1-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b(?!\d)(?![ -]\d{4})(?![@.])/,
    severity: "danger",
    priority: 3,
    minLength: 12,
    requireValidation: false,
    validate: validateAadhaar,
    getDetail(text) {
      return "Matches 12-digit format and passes Verhoeff checksum.";
    },
    description: "This value matches the 12-digit Indian Aadhaar number format.",
    limitations: "Mathematical & format validation confirms checksum and structural validity. Cannot verify issuance without authorized UIDAI API access.",
  },
  {
    type: "Passport number",
    regex: /\b[A-Z][1-9]\d{7}\b/i,
    severity: "danger",
    priority: 3,
    minLength: 8,
    validate(text) {
      const cleaned = text.trim().toUpperCase();
      return /^[A-Z][1-9]\d{7}$/.test(cleaned);
    },
    description: "This value matches a common passport number format.",
    limitations: "Format match only; passport numbering conventions vary by country.",
  },
  {
    type: "PAN-like number",
    regex: /\b[A-Z]{5}\d{4}[A-Z]\b/i,
    severity: "danger",
    priority: 3,
    minLength: 10,
    requireValidation: false,
    validate: validatePAN,
    description: "This value matches the Indian PAN (Permanent Account Number) format.",
    limitations: "Validates structure and entity type character. Cannot confirm issuance.",
  },
  {
    type: "International Bank Account Number (IBAN)",
    regex: /\b(?:AL|AD|AT|AZ|BH|BY|BE|BA|BR|BG|CR|HR|CY|CZ|DK|DO|EE|FO|FI|FR|GE|DE|GI|GR|GL|GT|HU|IS|IQ|IE|IL|IT|JO|KZ|XK|KW|LV|LB|LI|LT|LU|MT|MR|MU|MD|MC|ME|NL|MK|NO|PK|PS|PL|PT|QA|RO|LC|SM|ST|SA|RS|SC|SK|SI|ES|SE|CH|TL|TN|TR|UA|AE|GB|VA|VG)\d{2}[ -]?(?:[A-Z0-9]{4}[ -]?){2,7}[A-Z0-9]{1,4}\b/i,
    severity: "danger",
    priority: 3,
    minLength: 15,
    requireValidation: true,
    validate: validateIBAN,
    getDetail(text) {
      return "Matches IBAN format and passes MOD-97 checksum.";
    },
    description: "This value matches an IBAN format.",
    limitations: "Validates country length and MOD-97 checksum. Cannot verify the account exists.",
  },
  {
    type: "Cryptocurrency wallet address",
    regex: /\b(?:0x[a-fA-F0-9]{40}|(?:1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,62})\b/,
    severity: "danger",
    priority: 3,
    minLength: 26,
    validate(text) {
      const trimmed = text.trim();
      // Ethereum: 0x + 40 hex chars
      if (/^0x[a-fA-F0-9]{40}$/.test(trimmed)) return true;
      // Bitcoin legacy (1 or 3 prefix) or bech32 (bc1 prefix)
      if (/^(1|3)[a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(trimmed)) return true;
      if (/^bc1[a-z0-9]{25,62}$/.test(trimmed)) return true;
      return false;
    },
    description: "This value matches a cryptocurrency wallet address format.",
    limitations: "Format validation only. Cannot verify blockchain existence.",
  },

  // --- Medium Priority (Warning) ---
  {
    type: "Indian Driving License",
    regex: /\b[A-Z]{2}[-\s]?\d{2}[-\s]?(?:19|20)\d{2}\d{7}\b/i,
    severity: "warning",
    priority: 2,
    minLength: 15,
    validate: validateDrivingLicense,
    description: "This value matches the Indian Driving License format.",
    limitations: "Format match based on known state code + year + serial structure.",
  },
  {
    type: "Indian Voter ID (EPIC)",
    regex: /\b[A-Z]{3}[0-9]{7}\b/i,
    severity: "warning",
    priority: 2,
    minLength: 10,
    validate(text) {
      const cleaned = text.trim().toUpperCase();
      return /^[A-Z]{3}\d{7}$/.test(cleaned);
    },
    description: "This value matches the Indian Voter ID (EPIC) format.",
    limitations: "3-letter + 7-digit pattern can match other identifiers.",
  },
  {
    type: "Indian IFSC Code",
    regex: /\b[A-Z]{4}0[A-Z0-9]{6}\b/i,
    severity: "warning",
    priority: 2,
    minLength: 11,
    validate(text) {
      const cleaned = text.trim().toUpperCase();
      // IFSC: 4 alpha (bank code) + 0 (reserved) + 6 alphanumeric (branch)
      return /^[A-Z]{4}0[A-Z0-9]{6}$/.test(cleaned);
    },
    description: "This value matches the Indian IFSC Code format.",
    limitations: "Validates structure. The 5th character must be 0 per RBI convention.",
  },
  {
    type: "Date of Birth (DD/MM/YYYY)",
    regex: /\b(?:0[1-9]|[12]\d|3[01])[-/.](?:0[1-9]|1[0-2])[-/.](?:19|20)\d{2}\b/,
    severity: "warning",
    priority: 2,
    minLength: 8,
    requireValidation: true,
    validate(text) {
      const match = text.match(/(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})/);
      if (!match) return false;
      const [, d, m, y] = match;
      const day = parseInt(d, 10);
      const month = parseInt(m, 10);
      const year = parseInt(y, 10);
      if (month < 1 || month > 12) return false;
      if (day < 1 || day > 31) return false;
      if (year < 1900 || year > new Date().getFullYear()) return false;
      // Basic month-day validation
      const daysInMonth = new Date(year, month, 0).getDate();
      return day <= daysInMonth;
    },
    description: "This value matches a date of birth format.",
    limitations: "Validates calendar correctness. Cannot confirm it is actually a birth date.",
  },
  {
    type: "Contact / Phone number",
    regex:
      /(?<!\d)(?:(?:\+(?:\d[ -]?){1,4}|00[ -]?(?:\d[ -]?){1,4}|\(\+?\d{1,4}\)[ -]?)(?:\(\d{1,5}\)[ -]?)?(?:\d[ -.]?){6,14}\d|(?:1[ -.]?)?(?:(?:\(\d{3}\)[ -]?|\b\d{3}[ -.]?)\d{3}[ -.]?\d{4}\b)|\b91[ -]?[6-9]\d{4}[ -]?\d{5}\b|\b0?[6-9]\d{4}[ -]?\d{5}\b|\b[6-9]\d{9}\b|\b0\d{2,4}[ -]?\d{6,8}\b)(?!\d)/i,
    severity: "warning",
    priority: 2,
    minLength: 8,
    requireValidation: true,
    validate: validatePhone,
    getDetail(text, fieldContext, fullText) {
      const norm = ((fieldContext && fieldContext.normalized) || "") + " " + ((fullText && fullText.toLowerCase()) || "");
      const hasIntl = /^\s*(?:\+|\(\+|00|\(00)/.test(text);
      const suffix = hasIntl ? " (with country code)." : ".";
      if (norm.includes("mobile")) {
        return "Matches mobile number format" + suffix;
      }
      if (norm.includes("contact")) {
        return "Matches contact number format" + suffix;
      }
      return "Matches supported contact/phone number format" + suffix;
    },
    description: "This value matches a supported contact/phone number format.",
    limitations: "Validates digit count and prefix. Cannot verify number assignment.",
  },

  // --- Low Priority (Info / Notice) ---
  {
    type: "Email address",
    regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i,
    severity: "info",
    priority: 1,
    minLength: 5,
    validate(text) {
      const trimmed = text.trim();
      // Must have local part, @, domain, TLD
      const parts = trimmed.split("@");
      if (parts.length !== 2) return false;
      const [local, domain] = parts;
      if (!local || local.length > 64) return false;
      if (!domain || !domain.includes(".")) return false;
      // TLD must be at least 2 chars
      const tld = domain.split(".").pop();
      if (!tld || tld.length < 2) return false;
      // No consecutive dots in local part
      if (/\.{2,}/.test(local)) return false;
      return true;
    },
    description: "This text appears to contain an email address.",
    limitations: "Format validation only. Cannot verify the mailbox exists.",
  },
  {
    type: "IPv4 address",
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/,
    severity: "info",
    priority: 1,
    minLength: 7,
    requireValidation: true,
    validate: validateIPv4,
    description: "This value matches an IPv4 address format.",
    limitations: "Validates octet ranges (0-255). Does not check if the address is routable or assigned.",
  },
  {
    type: "Indian PIN code",
    regex: /\b[1-9]\d{5}\b/,
    severity: "info",
    priority: 1,
    minLength: 6,
    validate(text) {
      const digits = text.replace(/\D/g, "");
      if (digits.length !== 6) return false;
      // Indian PIN codes start with 1-9
      if (digits[0] === "0") return false;
      return true;
    },
    description: "This value matches an Indian 6-digit postal PIN code format.",
    limitations: "Many 6-digit numbers can match. Context is important for confidence.",
  },
  {
    type: "US ZIP+4 code",
    regex: /\b\d{5}-\d{4}\b/,
    severity: "info",
    priority: 1,
    minLength: 10,
    validate(text) {
      return /^\d{5}-\d{4}$/.test(text.trim());
    },
    description: "This value matches a US ZIP+4 postal code format.",
    limitations: "Cannot verify if the ZIP code exists without a postal database.",
  },
];

// ─── Exports ────────────────────────────────────────────────────

if (typeof window !== "undefined") {
  window.PII_PATTERNS = PATTERNS;
  window.luhnCheck = luhnCheck;
  window.identifyCardNetwork = identifyCardNetwork;
  window.validateCreditCard = validateCreditCard;
  window.verhoeffCheck = verhoeffCheck;
  window.verhoeffGenerate = verhoeffGenerate;
  window.validateAadhaar = validateAadhaar;
  window.validatePhone = validatePhone;
}
if (typeof globalThis !== "undefined") {
  globalThis.PII_PATTERNS = PATTERNS;
  globalThis.luhnCheck = luhnCheck;
  globalThis.identifyCardNetwork = identifyCardNetwork;
  globalThis.validateCreditCard = validateCreditCard;
  globalThis.verhoeffCheck = verhoeffCheck;
  globalThis.verhoeffGenerate = verhoeffGenerate;
  globalThis.validateAadhaar = validateAadhaar;
  globalThis.validatePhone = validatePhone;
}
if (typeof module !== "undefined" && module.exports) {
  module.exports = PATTERNS;
  module.exports.PATTERNS = PATTERNS;
  module.exports.luhnCheck = luhnCheck;
  module.exports.identifyCardNetwork = identifyCardNetwork;
  module.exports.validateCreditCard = validateCreditCard;
  module.exports.verhoeffCheck = verhoeffCheck;
  module.exports.verhoeffGenerate = verhoeffGenerate;
  module.exports.validateAadhaar = validateAadhaar;
  module.exports.validatePhone = validatePhone;
}
