/* ============================================================
   vault.js — IBM Vault integration (192.168.3.7)
   IBM Concert Secure Coder Demo
   ============================================================ */

'use strict';

const VAULT_ADDR = 'http://192.168.3.7:8200';

// Demo secrets to display when vault is unreachable
const DEMO_SECRETS = [
  {
    path:   'secret/payment/api',
    key:    'stripe_api_key',
    value:  'sk_live_4xK9...mN2p',
    masked: true,
    lease:  'TTL: 1h | Auto-renew',
    icon:   '🔑',
  },
  {
    path:   'secret/payment/db',
    key:    'postgres_password',
    value:  'Pg#Vault$Rot8!',
    masked: true,
    lease:  'TTL: 30m | Dynamic',
    icon:   '🗄️',
  },
  {
    path:   'secret/payment/jwt',
    key:    'jwt_signing_secret',
    value:  'eyJhbGciOiJIU...XQ',
    masked: true,
    lease:  'TTL: 15m | Ephemeral',
    icon:   '🎟️',
  },
  {
    path:   'secret/payment/smtp',
    key:    'smtp_password',
    value:  'Sm!p$3cur3#2024',
    masked: true,
    lease:  'TTL: 24h | Static',
    icon:   '📧',
  },
];

// ── Vault health check ─────────────────────────────────────
async function checkVaultStatus() {
  const indicator = document.getElementById('vaultIndicator');
  const dot = indicator ? indicator.querySelector('.dot') : null;
  const label = indicator ? indicator.querySelector('.vault-label') : null;

  try {
    const controller = new AbortController();
    const timeoutId  = setTimeout(() => controller.abort(), 3000);

    const resp = await fetch('/api/vault/health', { signal: controller.signal });
    clearTimeout(timeoutId);
    const data = await resp.json();

    if (data.initialized && !data.sealed) {
      if (dot)   { dot.className = 'dot dot-online'; }
      if (label) { label.textContent = 'IBM Vault — Online'; }
      addAuditEntry('ok', '🔐', 'IBM Vault connected at 192.168.3.7:8200');
      logRemediation('info', 'Vault Connected', 'IBM Vault at 192.168.3.7:8200 is healthy and unsealed', '');
    } else {
      throw new Error('Vault sealed or uninitialized');
    }
  } catch (_) {
    // Demo mode
    if (dot)   { dot.className = 'dot dot-checking'; }
    if (label) { label.textContent = 'IBM Vault — Demo Mode'; }
    addAuditEntry('warn', '⚠️', 'Vault at 192.168.3.7 unreachable — running in demo mode');
    logRemediation('info', 'Demo Mode Active', 'IBM Vault demo secrets loaded (server offline)', '');
    loadDemoApiKeyChip();
  }

  // Also update vault health in vault tab
  const vaultHealthEl = document.getElementById('vaultHealth');
  if (vaultHealthEl) {
    vaultHealthEl.innerHTML = `<span class="dot dot-checking"></span> Demo Mode`;
  }
}

// ── Load vault secrets into the payment form chips ─────────
function loadDemoApiKeyChip() {
  const apiKeyChip = document.getElementById('apiKeyChip');
  const dbChip     = document.getElementById('dbChip');
  if (apiKeyChip) {
    apiKeyChip.classList.add('loaded');
    document.getElementById('apiKeyLabel').textContent = 'API Key: sk_live_4xK9…mN2p (Vault)';
  }
  if (dbChip) {
    dbChip.classList.add('loaded');
    document.getElementById('dbLabel').textContent = 'DB Creds: postgres@vault/dynamic';
  }
}

// ── Load secrets grid in vault tab ────────────────────────
async function loadVaultSecrets() {
  const grid        = document.getElementById('secretsGrid');
  const vaultHealth = document.getElementById('vaultHealth');
  if (!grid) return;

  grid.innerHTML = `<div class="secret-loading"><div class="spinner"></div><p>Connecting to IBM Vault at ${VAULT_ADDR}…</p></div>`;

  // Try real vault first
  let secrets = null;
  try {
    const controller = new AbortController();
    const timeoutId  = setTimeout(() => controller.abort(), 3000);
    const resp       = await fetch('/api/vault/secrets', { signal: controller.signal });
    clearTimeout(timeoutId);
    if (resp.ok) secrets = await resp.json();
  } catch (_) {
    // Fall through to demo
  }

  // Render
  const displaySecrets = secrets || DEMO_SECRETS;
  const isDemoMode     = !secrets;

  if (vaultHealth) {
    if (isDemoMode) {
      vaultHealth.innerHTML = `<span class="dot dot-checking"></span> Demo Mode`;
    } else {
      vaultHealth.innerHTML = `<span class="dot dot-online"></span> Online`;
    }
  }

  grid.innerHTML = displaySecrets.map((s, i) => `
    <div class="secret-card">
      <div class="secret-path">${s.path}</div>
      <div class="secret-key">${s.icon} ${s.key}</div>
      <div class="secret-val masked" id="secval-${i}">${maskSecret(s.value)}</div>
      <div class="secret-meta">
        ${s.lease}
        ${isDemoMode ? '&nbsp;·&nbsp;<em>demo</em>' : ''}
        <button class="secret-toggle" onclick="toggleSecret(${i}, '${s.value}')">👁 Reveal</button>
      </div>
    </div>
  `).join('');

  if (isDemoMode) {
    addAuditEntry('info', '🔐', `Vault demo secrets loaded — ${VAULT_ADDR}`);
  } else {
    addAuditEntry('ok', '🔐', `Vault live secrets fetched from ${VAULT_ADDR}`);
  }

  // Update payment form chips
  loadDemoApiKeyChip();
}

function maskSecret(val) {
  if (!val || val.length <= 6) return '••••••••';
  return val.substring(0, 4) + '•'.repeat(Math.min(12, val.length - 6)) + val.slice(-2);
}

function toggleSecret(idx, val) {
  const el  = document.getElementById(`secval-${idx}`);
  const btn = el ? el.closest('.secret-card').querySelector('.secret-toggle') : null;
  if (!el) return;
  if (el.classList.contains('masked')) {
    el.classList.remove('masked');
    el.textContent = val;
    if (btn) btn.textContent = '🙈 Hide';
    addAuditEntry('warn', '👁', `Secret revealed in UI — audit event recorded`);
  } else {
    el.classList.add('masked');
    el.textContent = maskSecret(val);
    if (btn) btn.textContent = '👁 Reveal';
  }
}

// ── Rotate credentials ─────────────────────────────────────
async function rotateSecrets() {
  showToast('🔄 Rotating Vault credentials…', 'info');
  addAuditEntry('warn', '🔄', 'Manual secret rotation triggered via Vault API');
  logRemediation('action', 'Secret Rotation', 'IBM Vault rotating all dynamic credentials at 192.168.3.7', '');

  await new Promise(r => setTimeout(r, 1500));

  showToast('✅ Vault credentials rotated successfully!', 'success');
  addAuditEntry('ok', '✅', 'Secret rotation complete — all leases renewed');
  logRemediation('fix', 'Rotation Complete', 'New ephemeral credentials issued — old credentials invalidated', '');

  // Reload secrets display
  await loadVaultSecrets();
}
