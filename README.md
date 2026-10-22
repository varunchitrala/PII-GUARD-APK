# PII Guard — Chrome Extension

PII Guard displays an on-page warning when it detects text resembling common personally identifiable information (PII) in a form field.

## Features

- Runs on regular websites using Chrome Manifest V3.
- Works on standard inputs, empty/generic fields, search bars (`role="searchbox"`, `role="combobox"`, `type="search"`), and rich-text AI chat interfaces like **ChatGPT** (`contenteditable`, `role="textbox"`).
- Detects email addresses, phone-number-like strings (Indian mobile, international formats, and formatted numbers), Aadhaar numbers (Verhoeff checksum validated), PAN-like strings, payment-card numbers, Indian PIN codes, US SSNs, Passports, Driving Licenses, Voter IDs, IFSC codes, IBANs, ZIP+4 codes, Date of Births, IPv4 addresses, and crypto wallet addresses.
- Dynamic danger colors based on priority: displays vivid red alerts and pulsing indicators for crucial PII (Cards, SSN, Aadhaar, Passports, Bank Accounts), amber for medium-risk data, and blue for basic notices.
- Form field highlighting: applies a color-coded priority outline around the active input field or chat prompt box.
- Shows a warning with **Review field** and **Dismiss** actions.
- Lets the user turn protection on or off.
- Performs pattern matching locally in the browser. This extension does not transmit typed text to a server.
- Uses no external libraries or build step.

## Install in Chrome

1. Download and unzip `PII-Guard-Chrome-Extension.zip`.
2. Open `chrome://extensions` in Chrome.
3. Turn on **Developer mode** (top-right).
4. Select **Load unpacked**.
5. Choose the unzipped `PII-Guard-Chrome-Extension` folder — the folder that contains `manifest.json`.
6. Pin **PII Guard** from the Extensions menu if you want quick access.

## Test it

1. Open a regular website with a text field (or use a local HTML form).
2. Type a test value such as `alex@example.com` or `ABCDE1234F`.
3. A PII Guard warning should appear.
4. Open the extension popup to turn protection off and on.

**Use synthetic test values only. Do not test with real identity or payment information.**

## Files

- `manifest.json` — extension permissions, content-script setup, and popup.
- `patterns.js` — defines regex detection patterns for PII.
- `content.js` — listens for input and renders warnings.
- `styles.css` — warning-card styling.
- `popup.html`, `popup.js` — toolbar popup and protection toggle.
- `options.html`, `options.js` — settings and detection limitations.
- `icons/` — reserved for optional extension icons.

## Important security and privacy notes

- This extension is a warning aid, not a DLP/security boundary. It does not prevent submission and cannot guarantee complete PII detection.
- Pattern matching can create false positives and false negatives.
- It requests access to all websites (`<all_urls>`) so it can inspect form fields broadly. Chrome does not permit extensions to run on certain restricted pages, including browser-internal pages and Chrome Web Store pages.
- It does not inspect password fields.
- Page scripts can interfere with injected UI, and some complex editors may behave differently.
- Review the source code before installing. For organizational deployment, have the extension reviewed and tested by your security/privacy team.
