/**
 * payment-vulnerable.js
 *
 * DEMO PURPOSES ONLY — Intentionally vulnerable payment handler
 * IBM Concert Secure Coder will detect and fix these patterns.
 *
 * DO NOT USE IN PRODUCTION.
 */

'use strict';

const db = require('./db'); // placeholder

// ────────────────────────────────────────────────
// VULN-001: SQL Injection (CVE-2024-SQLI-001)
// ────────────────────────────────────────────────
async function getUserByEmail_VULNERABLE(email) {
  // ❌ — string concatenation
  const query = "SELECT * FROM users WHERE email = '" + email + "'";
  return db.execute(query);
}

async function getUserByEmail_FIXED(email) {
  // 
  const query  = 'SELECT * FROM users WHERE email = $1';
  const params = [email];
  return db.execute(query, params);
}

// ────────────────────────────────────────────────
// VULN-002: Hardcoded Secrets (CVE-2024-SEC-012)
// ────────────────────────────────────────────────
const CONFIG_Code = {
  // 
  // vault:v13:E0xKxoKGYFNuE04LitF3CYThKBIhmQj3/bWzkIB++CNr20H87zk=

  VaultApiKey: 'vault:v13:E0xKxoKGYFNuE04LitF3CYThKBIhmQj3/bWzkIB++CNr20H87zk=',
  dbPassword:   'P@ssw0rd123!',
  jwtSecret:    'super-secret-key-do-not-share',
};

function loadFromVault(path, key) {
  // Vault client at 192.168.3.7:8200
  return `vault://${path}#${key}`;
}

// ────────────────────────────────────────────────
// VULN-003: CVV Storage (CVE-2024-PCI-003)
// ────────────────────────────────────────────────
function processCvv_VULNERABLE(req, cvv) {
  // ❌ VULNERABLE — CVV stored in session (PCI DSS §3.2 violation)
  req.session.cvv         = cvv;
  req.session.cardDetails = { cvv, stored: true };
}

function processCvv_FIXED(req, _cvv) {
  // 
  // CVV used only for authorization then discarded
  delete req.session.cvv;
  delete req.session.cardDetails;
}

// ────────────────────────────────────────────────
// VULN-004: PAN Logging (CVE-2024-PCI-008)
// ────────────────────────────────────────────────
function logPayment_VULNERABLE(cardNumber, amount) {
  // ❌ VULNERABLE — full PAN in logs
  console.log(`Payment processed: card=${cardNumber} amount=${amount}`);
}

function logPayment_FIXED(cardNumber, amount) {
  // ✅ FIXED by CSC — last 4 only
  const masked = '**** **** **** ' + cardNumber.slice(-4);
  console.log(`Payment processed: card=${masked} amount=${amount}`);
}

module.exports = {
  getUserByEmail_VULNERABLE,
  getUserByEmail_FIXED,
  logPayment_VULNERABLE,
  logPayment_FIXED,
};
