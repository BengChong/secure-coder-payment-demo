/**
 * server.js — SecurePay backend
 * IBM Concert Secure Coder Demo
 *
 * Demonstrates IBM Vault integration at 192.168.3.7 for secret management.
 * Intentionally contains some vulnerable patterns for the Secure Coder demo —
 * run `npm run scan` to detect and remediate them.
 */

'use strict';

const express    = require('express');
const path       = require('path');
const https      = require('https');
const http       = require('http');
const crypto     = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;

// IBM Vault configuration
const VAULT_ADDR  = process.env.VAULT_ADDR  || 'http://192.168.3.7:8200';
const VAULT_TOKEN = process.env.VAULT_TOKEN || 'demo-root-token';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ── Request logging middleware ─────────────────────────────
app.use((req, _res, next) => {
  const ts = new Date().toISOString();
  // VULN DEMO: logging request body may expose card data
  // Concert Secure Coder fix: mask PAN before logging
  console.log(`[${ts}] ${req.method} ${req.path}`);
  next();
});

// ── Vault helper ────────────────────────────────────────────
async function vaultRequest(method, urlPath, body = null) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(VAULT_ADDR + urlPath);
    const options = {
      hostname: parsed.hostname,
      port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 8200),
      path:     parsed.pathname + parsed.search,
      method,
      headers: {
        'X-Vault-Token': VAULT_TOKEN,
        'Content-Type':  'application/json',
      },
    };

    const proto = parsed.protocol === 'https:' ? https : http;
    const req   = proto.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(data) }); }
        catch (e) { resolve({ status: res.statusCode, data }); }
      });
    });

    req.on('error', reject);
    req.setTimeout(3000, () => { req.destroy(new Error('Vault request timed out')); });
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

// ── Routes ───────────────────────────────────────────────────

// Vault health check
app.get('/api/vault/health', async (req, res) => {
  try {
    const { status, data } = await vaultRequest('GET', '/v1/sys/health');
    res.json({
      ok:          true,
      endpoint:    VAULT_ADDR,
      initialized: data.initialized,
      sealed:      data.sealed,
      version:     data.version || 'unknown',
    });
  } catch (err) {
    res.status(503).json({
      ok:      false,
      error:   err.message,
      endpoint: VAULT_ADDR,
    });
  }
});

// Fetch vault secrets (demo paths)
app.get('/api/vault/secrets', async (req, res) => {
  try {
    const paths = [
      'secret/data/payment/api',
      'secret/data/payment/db',
      'secret/data/payment/jwt',
      'secret/data/payment/smtp',
    ];

    const results = await Promise.all(
      paths.map(async (p) => {
        try {
          const { data } = await vaultRequest('GET', `/v1/${p}`);
          const kvData   = (data.data && data.data.data) || data.data || {};
          return { path: p.replace('secret/data/', 'secret/'), ...kvData };
        } catch (_) {
          return { path: p.replace('secret/data/', 'secret/'), error: 'not_found' };
        }
      })
    );

    res.json(results);
  } catch (err) {
    res.status(503).json({ error: err.message });
  }
});

// Vault rotate endpoint (demo)
app.post('/api/vault/rotate', async (req, res) => {
  try {
    // In a real app: trigger Vault lease renewal or dynamic credential rotation
    await vaultRequest('POST', '/v1/sys/auth/token/renew-self', {});
    res.json({ ok: true, message: 'Credentials rotated successfully', timestamp: new Date().toISOString() });
  } catch (err) {
    // Demo fallback
    res.json({ ok: true, message: 'Demo rotation complete', timestamp: new Date().toISOString() });
  }
});

// Payment processing endpoint
app.post('/api/payment', async (req, res) => {
  const { name, email, cardNumber, expiry, cvv, amount, description } = req.body;

  // Input validation
  if (!name || !cardNumber || !expiry || !cvv || !amount) {
    return res.status(400).json({ success: false, error: 'Missing required fields' });
  }

  // VULN DEMO: unparameterized query placeholder
  // SECURE CODER FIX: use parameterized queries
  const sanitizedDescription = (description || '').replace(/['"\\;]/g, '');

  // Fetch API key from Vault (preferred over hardcoded)
  let apiKey = 'demo-api-key';
  try {
    const { data } = await vaultRequest('GET', '/v1/secret/data/payment/api');
    apiKey = (data.data && data.data.stripe_api_key) || apiKey;
  } catch (_) {
    // Use demo key when Vault unavailable
  }

  // Simulate payment processing
  await new Promise(r => setTimeout(r, 400 + Math.random() * 300));

  const txId = 'TX-' + crypto.randomBytes(5).toString('hex').toUpperCase();

  // Audit log (PAN masked by Concert Secure Coder)
  const maskedCard = '**** **** **** ' + (cardNumber.slice(-4) || '0000');
  console.log(`[PAYMENT] TxID=${txId} amount=${amount} card=${maskedCard} vault_key=${apiKey.substring(0, 8)}...`);

  res.json({
    success: true,
    txId,
    amount,
    maskedCard,
    timestamp:  new Date().toISOString(),
    vaultKeyId: apiKey.substring(0, 8) + '...',
    message:    'Payment processed with Vault-secured credentials',
  });
});

// Scan endpoint (proxies to Concert Secure Coder MCP in real deployment)
app.get('/api/scan/status', (_req, res) => {
  res.json({
    engine:   'IBM Concert Secure Coder',
    version:  '2.1.0',
    vaultAddr: VAULT_ADDR,
    ready:    true,
    scanners: ['icsc_scan_packages', 'icsc_scan_code', 'icsc_scan_secrets'],
  });
});

// SPA fallback
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════╗
║  SecurePay — IBM Concert Secure Coder Demo     ║
║  http://localhost:${PORT}                          ║
║  IBM Vault: ${VAULT_ADDR}          ║
╚════════════════════════════════════════════════╝
  `);
});

module.exports = app;
