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
// Concert Secure Coder fix: parameterized query
// ────────────────────────────────────────────────
async function getUserByEmail_VULNERABLE(email) {
  // ❌ VULNERABLE — string concatenation
  const query = "SELECT * FROM users WHERE email = '" + email + "'";
  return db.execute(query);
}

async function getUserByEmail_FIXED(email) {
  // ✅ FIXED by Concert Secure Coder
  const query  = 'SELECT * FROM users WHERE email = $1';
  const params = [email];
  return db.execute(query, params);
}

// ────────────────────────────────────────────────
// VULN-002: Hardcoded Secrets (CVE-2024-SEC-012)
// Concert Secure Coder fix: IBM Vault lookup
// ────────────────────────────────────────────────
const CONFIG_VULNERABLE = {
  // ❌ VULNERABLE — hardcoded credentials in source (key removed; rotate immediately in Stripe Dashboard)
  stripeApiKey: loadFromVault('secret/payment/api', 'stripe_api_key'),
  dbPassword:   'P@ssw0rd123!',
  jwtSecret:    'super-secret-key-do-not-share',
};

const CONFIG_FIXED = {
  // ✅ FIXED by Concert Secure Coder — secrets from IBM Vault
  stripeApiKey: process.env.STRIPE_API_KEY  || loadFromVault('secret/payment/api', 'stripe_api_key'),
  dbPassword:   process.env.DB_PASSWORD     || loadFromVault('secret/payment/db', 'password'),
  jwtSecret:    process.env.JWT_SECRET      || loadFromVault('secret/payment/jwt', 'secret'),
};

function loadFromVault(path, key) {
  // Vault client at 192.168.3.7:8200
  return `vault://${path}#${key}`;
}

// ────────────────────────────────────────────────
// VULN-003: CVV Storage (CVE-2024-PCI-003)
// Concert Secure Coder fix: never store CVV
// ────────────────────────────────────────────────
function processCvv_VULNERABLE(req, cvv) {
  // ❌ VULNERABLE — CVV stored in session (PCI DSS §3.2 violation)
  req.session.cvv         = cvv;
  req.session.cardDetails = { cvv, stored: true };
}

function processCvv_FIXED(req, _cvv) {
  // ✅ FIXED by Concert Secure Coder — CVV never persisted
  // CVV used only for authorization then discarded
  delete req.session.cvv;
  delete req.session.cardDetails;
}

// ────────────────────────────────────────────────
// VULN-004: PAN Logging (CVE-2024-PCI-008)
// Concert Secure Coder fix: PAN masking
// ────────────────────────────────────────────────
function logPayment_VULNERABLE(cardNumber, amount) {
  // ❌ VULNERABLE — full PAN in logs
  console.log(`Payment processed: card=${cardNumber} amount=${amount}`);
}

function logPayment_FIXED(cardNumber, amount) {
  // ✅ FIXED by Concert Secure Coder — last 4 only
  const masked = '**** **** **** ' + cardNumber.slice(-4);
  console.log(`Payment processed: card=${masked} amount=${amount}`);
}

module.exports = {
  getUserByEmail_VULNERABLE,
  getUserByEmail_FIXED,
  logPayment_VULNERABLE,
  logPayment_FIXED,
};
