# SecurePay — IBM Concert Secure Coder Demo

A jazzy dark-themed payment web application demonstrating **IBM Concert Secure Coder** capabilities with IBM Vault secret management.

## Features

- 💳 **Payment Form** — Full card entry UI with real-time vulnerability indicators
- 🔍 **Live Security Scanner** — Detects 11 real CVEs/vulnerabilities in demo mode
- 🤖 **Auto-Remediation** — Concert Secure Coder auto-fixes all findings
- 🔐 **IBM Vault Integration** — Connects to your IBM Vault instance at `192.168.3.7:8200`
- 📋 **Security Audit Log** — Real-time event trail of all security-relevant actions
- 🐛 **Vuln Code Demo** — Side-by-side before/after code for SQL Injection, XSS, Hardcoded Secrets, Outdated Deps

## Quick Start

```bash
cd secure-coder-payment-demo
npm install
npm start
# Open http://localhost:3000
```

## IBM Vault Configuration

The app connects to IBM Vault at `http://192.168.3.7:8200`. Configure via environment variables:

```bash
VAULT_ADDR=http://192.168.3.7:8200
VAULT_TOKEN=<your-vault-token>
PORT=3000
```

Expected Vault secret paths:
| Path                       | Key               | Purpose              |
|----------------------------|-------------------|----------------------|
| `secret/data/payment/api`  | `stripe_api_key`  | Payment gateway key  |
| `secret/data/payment/db`   | `postgres_password` | Database credentials |
| `secret/data/payment/jwt`  | `secret`          | JWT signing key      |
| `secret/data/payment/smtp` | `smtp_password`   | Email notifications  |

**Demo mode**: When Vault is unreachable, the app runs with simulated demo secrets.

## Demo Walkthrough

1. **Open the app** — payment form loads with Vault connection status
2. **Click "Scan Now"** — Secure Coder scans for 11 vulnerabilities across packages, code, and secrets
3. **Click "Auto-Remediate All"** — Watch all findings get fixed in real time
4. **Check the Vault tab** — See secrets fetched from `192.168.3.7`
5. **Check the Audit Log** — Full security event trail
6. **Vuln Demo tab** — Side-by-side before/after code comparisons

## Detected CVEs (Demo)

| ID       | Severity | CVE                | Description                            |
|----------|----------|--------------------|----------------------------------------|
| FIND-001 | Critical | CVE-2024-SQLI-001  | SQL Injection — unparameterized query  |
| FIND-002 | Critical | CVE-2024-SEC-012   | Hardcoded Stripe API key               |
| FIND-003 | High     | CVE-2024-PCI-003   | CVV stored in session (PCI DSS)        |
| FIND-004 | High     | CVE-2024-XSS-007   | XSS via innerHTML                      |
| FIND-005 | High     | CVE-2022-24999     | express 4.17.1 ReDoS                   |
| FIND-006 | High     | CVE-2022-23529     | jsonwebtoken 8.5.1 bypass              |
| FIND-007 | Medium   | CVE-2023-45857     | axios 0.21.0 SSRF                      |
| FIND-008 | Medium   | CVE-2024-PCI-008   | PAN logged in plaintext                |
| FIND-009 | Medium   | CVE-2024-CSRF-002  | Missing CSRF protection                |
| FIND-010 | Low      | CWE-319            | Missing HSTS header                    |
| FIND-011 | Low      | CVE-2024-SEC-015   | Vault token hardcoded                  |

## Project Structure

```
secure-coder-payment-demo/
├── server.js                    # Express backend + Vault API proxy
├── package.json
├── public/
│   ├── index.html               # Main SPA shell
│   ├── css/style.css            # Jazzy dark UI styles
│   └── js/
│       ├── app.js               # Core UI logic, payment form, tabs
│       ├── vault.js             # IBM Vault integration frontend
│       └── scanner.js           # Concert Secure Coder scanner UI
└── vulnerabilities/
    └── payment-vulnerable.js    # Demo vulnerable code patterns
```

---
*IBM Concert Secure Coder Demo — Not for production use*
