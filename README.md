# PII Guard Desktop — System-Wide Data Protection & DLP Sentinel

**PII Guard Desktop** is an autonomous, real-time desktop application built with Electron that continuously monitors your system to protect sensitive Personally Identifiable Information (PII) from accidental exposure or unauthorized leakage.

Unlike a browser extension that only works inside a specific browser window, **PII Guard Desktop protects your entire operating system** — monitoring the clipboard and text activities across all desktop applications including browsers, Office apps, text editors, chat applications (Teams, Slack, Discord), and terminal windows.

---

## Key Capabilities

- **System-Wide Clipboard Sentinel**: Runs silently in the background (or minimized to the system tray), continuously inspecting text copied or cut anywhere across Windows.
- **On-Screen Floating Alert Overlay**: Whenever sensitive PII is detected in an external application, an always-on-top, glowing alert banner appears in the corner of your screen with an audible warning chime and instant remediation actions.
- **Auto-Mask / Sanitize**: 1-click clipboard sanitization that immediately redacts credit card numbers, Aadhaar numbers, SSNs, phone numbers, or emails before they can be pasted into public chats or insecure forms.
- **Live Text & Input Inspector**: An interactive playground to test text snippets, examine confidence scores, simulate form contexts, and copy redacted versions.
- **Document & File Auditor**: Drag and drop text files, logs, CSVs, or JSON to scan entire documents for PII and export a sanitized copy with 1 click.
- **Comprehensive Audit Trail**: Searchable, filterable threat history log of all intercepted PII events with CSV export.
- **Mathematical & Checksum Validation**:
  - Payment cards validated via the **Luhn algorithm** and card network BIN verification (Visa, Mastercard, Amex, RuPay, etc.).
  - 12-digit Indian Aadhaar numbers validated using the official **Verhoeff checksum algorithm**.
  - International Bank Account Numbers validated via **IBAN MOD-97**.
  - Strict format validation for US SSN, PAN cards, Passports, Driving Licenses, Voter IDs, and Phone numbers.
- **Zero Cloud Transmission**: All detection happens 100% locally on your machine in JavaScript/Node.js. No text or sensitive data is ever sent over the network.

---

## Supported PII Categories

| Category | Detection & Validation Level | Danger Level |
| :--- | :--- | :--- |
| **Payment Cards** | Luhn Checksum + BIN Network Detection (Visa, Mastercard, Amex, RuPay) | Critical (Danger) |
| **Indian Aadhaar** | 12-Digit Verhoeff Checksum Algorithm | Critical (Danger) |
| **US Social Security (SSN)** | Area & Group Number Format Validation | Critical (Danger) |
| **Indian PAN Card** | 10-Character Alphanumeric Tax ID Format | Critical (Danger) |
| **International Bank Account (IBAN)** | MOD-97 Country-Specific Length Checksum | Critical (Danger) |
| **Passport Numbers** | Alpha-Numeric Passport Format | Critical (Danger) |
| **Cryptocurrency Wallets** | Bitcoin (1/3/bc1) & Ethereum (0x) Addresses | Critical (Danger) |
| **Indian Driving Licenses** | State Code & Year Format Validation | Medium (Warning) |
| **Indian Voter ID (EPIC)** | 3-Letter + 7-Digit Format | Medium (Warning) |
| **Bank IFSC Codes** | 11-Character RBI IFSC Standard | Medium (Warning) |
| **Phone / Mobile Numbers** | International E.164 & National 10-Digit Formats | Medium (Warning) |
| **Email Addresses** | RFC-Compliant Standard Email Formats | Low (Notice) |
| **IPv4 Addresses** | Octet Range 0–255 Plausibility Check | Low (Notice) |
| **Postal Codes** | Indian 6-Digit PIN & US ZIP+4 Codes | Low (Notice) |

---

## Getting Started

### Prerequisites

- Node.js (version 18 or newer recommended)
- Windows, macOS, or Linux

### Launching the Application

1. Open a terminal in the project directory:
   ```bash
   cd "PII-GUARD-APK"
   ```

2. Start the desktop application:
   ```bash
   npm start
   ```

3. **Global Shortcut**: Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on macOS) anywhere on your computer at any time to summon PII Guard.

---

## Project Structure

```
├── main.js             # Electron main process (system tray, clipboard sentinel, overlay window, IPC)
├── preload.js          # Secure ContextBridge IPC bridge
├── index.html          # Main desktop dashboard & inspector layout
├── styles.css          # Cybersecurity dark theme styling & micro-animations
├── renderer.js         # Frontend controller (synthesized Web Audio, live inspector, file auditor)
├── overlay.html        # Floating always-on-top desktop alert overlay
├── patterns.js         # PII regex patterns, Luhn check, Verhoeff check, and validators
├── detection-engine.js # Confidence scoring, context relations, and decision engine
└── package.json        # Electron application manifest and scripts
```
