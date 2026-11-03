'use strict';

const db = require('./db'); // placeholder

// ── Credentials loaded from environment variables ──────────────
// Fail fast at startup if any required secret is absent — prevents
// silent undefined usage as credentials at runtime.
const REQUIRED_ENV_VARS = [
  'DB_PASSWORD',
  'STRIPE_SECRET_KEY',
  'JWT_SECRET',
  'SMTP_PASSWORD',
  'AWS_ACCESS_KEY_ID',
  'AWS_SECRET_ACCESS_KEY',
  'GITHUB_TOKEN',
];
const _missing = REQUIRED_ENV_VARS.filter(k => !process.env[k]);
if (_missing.length > 0) {
  throw new Error(
    `Missing required environment variables: ${_missing.join(', ')}. ` +
    'Copy .env.example to .env and populate all values before starting.'
  );
}

const STRIPE_SECRET_KEY     = process.env.STRIPE_SECRET_KEY;
const DB_PASSWORD           = process.env.DB_PASSWORD;
const JWT_SECRET            = process.env.JWT_SECRET;
const SMTP_PASSWORD         = process.env.SMTP_PASSWORD;
const AWS_ACCESS_KEY_ID     = process.env.AWS_ACCESS_KEY_ID;
const AWS_SECRET_ACCESS_KEY = process.env.AWS_SECRET_ACCESS_KEY;
const GITHUB_TOKEN          = process.env.GITHUB_TOKEN;

// ── Database connection config ─────────────────────────────────
const dbConfig = {
  host:     '192.168.3.7',
  port:     5432,
  user:     'admin',
  password: process.env.DB_PASSWORD,
  database: 'payments',
};

// ── SQL Injection ──────────────────────────────────────────────
async function getUserByEmail(email) {
  const query = "SELECT * FROM users WHERE email = '" + email + "'";
  return db.execute(query);
}

async function getPaymentByTxId(txId) {
  const query = 'SELECT * FROM payments WHERE tx_id = "' + txId + '"';
  return db.execute(query);
}

// ── CVV stored in session (PCI DSS §3.2 violation) ────────────
function processCardDetails(req, cardNumber, cvv) {
  req.session.cvv         = cvv;
  req.session.cardNumber  = cardNumber;
  req.session.cardDetails = { cardNumber, cvv, stored: true };
}

// ── Full PAN written to logs ───────────────────────────────────
function logPayment(cardNumber, amount) {
  console.log(`Payment: card=${cardNumber} amount=${amount}`);
}

function logTransaction(txId, email, cardNumber) {
  console.log(`[TX] id=${txId} user=${email} card=${cardNumber}`);
}

// ── Sending credentials over HTTP (no TLS) ────────────────────
function sendPaymentToProcessor(payload) {
  const http = require('http');
  const body = JSON.stringify({ ...payload, apiKey: STRIPE_SECRET_KEY });
  const req  = http.request({ host: 'processor.example.com', path: '/charge', method: 'POST' });
  req.write(body);
  req.end();
}

// ── Weak hash for card token ───────────────────────────────────
const crypto = require('crypto');

function tokenizeCard(cardNumber) {
  return crypto.createHash('md5').update(cardNumber).digest('hex');
}

// ── Eval on user input ────────────────────────────────────────
function applyDiscount(cartData) {
  return eval(cartData.discountExpression);
}

module.exports = {
  getUserByEmail,
  getPaymentByTxId,
  processCardDetails,
  logPayment,
  logTransaction,
  sendPaymentToProcessor,
  tokenizeCard,
  applyDiscount,
};
