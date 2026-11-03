/* ============================================================
   app.js — Core payment app logic
   IBM Concert Secure Coder Demo
   ============================================================ */

'use strict';

// ── Particles ──────────────────────────────────────────────
(function initParticles() {
  const container = document.getElementById('particles');
  const count = 30;
  for (let i = 0; i < count; i++) {
    const p = document.createElement('div');
    p.className = 'particle';
    p.style.cssText = `
      left: ${Math.random() * 100}%;
      width: ${Math.random() * 3 + 1}px;
      height: ${Math.random() * 3 + 1}px;
      animation-duration: ${Math.random() * 15 + 8}s;
      animation-delay: ${Math.random() * 10}s;
      opacity: ${Math.random() * 0.5};
    `;
    container.appendChild(p);
  }
})();

// ── Tab switching ──────────────────────────────────────────
function switchTab(btn, tabId) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  btn.classList.add('active');
  const tab = document.getElementById('tab-' + tabId);
  if (tab) {
    tab.classList.add('active');
    if (tabId === 'vault') loadVaultSecrets();
    if (tabId === 'vulncode') showVulnCode(document.querySelector('.vuln-tab.active'), 'sqli');
  }
}

// ── Card formatting ────────────────────────────────────────
function formatCard(input) {
  let v = input.value.replace(/\D/g, '').substring(0, 16);
  input.value = v.replace(/(.{4})/g, '$1 ').trim();
}

function formatExpiry(input) {
  let v = input.value.replace(/\D/g, '').substring(0, 4);
  if (v.length >= 3) v = v.substring(0, 2) + '/' + v.substring(2);
  input.value = v;
}

// ── Payment processing ─────────────────────────────────────
async function processPayment(evt) {
  evt.preventDefault();
  const btn = document.getElementById('payBtn');
  const result = document.getElementById('paymentResult');

  const payload = {
    name:        document.getElementById('cardName').value,
    email:       document.getElementById('cardEmail').value,
    cardNumber:  document.getElementById('cardNumber').value.replace(/\s/g, ''),
    expiry:      document.getElementById('cardExpiry').value,
    cvv:         document.getElementById('cardCvv').value,
    amount:      document.getElementById('amount').value,
    description: document.getElementById('description').value,
  };

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner" style="width:16px;height:16px;border-width:2px"></span> Processing…';
  result.style.display = 'none';

  addAuditEntry('info', '💳', `Payment initiated: $${payload.amount} for ${payload.name}`);
  addAuditEntry('warn', '⚠️', `VULN: Card number may be logged in plaintext — CVE-2024-DEMO-001`);

  try {
    const resp = await fetch('/api/payment', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();

    if (resp.ok && data.success) {
      result.className = 'payment-result success';
      result.innerHTML = `✅ Payment of <strong>$${payload.amount}</strong> processed successfully!<br>
        <small>Transaction ID: ${data.txId} | Vault-secured API key used</small>`;
      addAuditEntry('ok', '✅', `Payment SUCCESS — TxID: ${data.txId}`);
      showToast('Payment processed securely!', 'success');
      logRemediation('info', 'Payment completed', 'Transaction signed with Vault-issued ephemeral key', '');
    } else {
      throw new Error(data.error || 'Payment failed');
    }
  } catch (err) {
    // Demo mode: simulate success when server is not running
    const txId = 'TX-' + Math.random().toString(36).substring(2, 10).toUpperCase();
    result.className = 'payment-result success';
    result.innerHTML = `✅ <strong>Demo Mode</strong>: Payment of <strong>$${payload.amount}</strong> simulated!<br>
      <small>Transaction ID: ${txId} | IBM Vault secret rotation demonstrated</small>`;
    addAuditEntry('ok', '✅', `Demo Payment SUCCESS — TxID: ${txId}`);
    addAuditEntry('warn', '🔓', `VULN DEMO: CVV stored in session storage — PCI DSS §3.2 violation`);
    showToast('Demo payment processed!', 'success');
    logRemediation('fix', 'CVV Storage Fixed', 'Concert Secure Coder removed CVV from session — PCI DSS compliant', 'CVE-2024-PCI-001');
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="1" y="4" width="22" height="16" rx="2" ry="2"/><line x1="1" y1="10" x2="23" y2="10"/></svg> Process Payment`;
    result.style.display = 'block';
  }
}

// ── Audit log ──────────────────────────────────────────────
let auditEntries = [];

function addAuditEntry(type, icon, msg) {
  auditEntries.unshift({ type, icon, msg, ts: new Date() });
  renderAuditLog();
}

function renderAuditLog() {
  const log = document.getElementById('auditLog');
  if (!log) return;
  if (auditEntries.length === 0) {
    log.innerHTML = '<div class="audit-empty">No events yet. Make a payment or run a scan.</div>';
    return;
  }
  log.innerHTML = auditEntries.slice(0, 50).map(e => `
    <div class="audit-entry">
      <span class="audit-ts">${e.ts.toLocaleTimeString()}</span>
      <span class="audit-icon">${e.icon}</span>
      <span class="audit-msg ${e.type}">${e.msg}</span>
    </div>
  `).join('');
}

function clearAudit() {
  auditEntries = [];
  renderAuditLog();
}

// ── Remediation log ────────────────────────────────────────
function logRemediation(type, title, msg, cve) {
  const log = document.getElementById('remediationLog');
  const welcome = log.querySelector('.rlog-welcome');
  if (welcome) welcome.remove();

  const entry = document.createElement('div');
  entry.className = `rlog-entry ${type}`;
  const typeLabels = { fix: 'Fixed', warn: 'Warning', info: 'Info', action: 'Action' };
  entry.innerHTML = `
    <div class="rlog-entry-header">
      <span class="rlog-entry-type">${typeLabels[type] || type}</span>
      <span class="rlog-entry-ts">${new Date().toLocaleTimeString()}</span>
    </div>
    <div class="rlog-entry-msg"><strong>${title}</strong> — ${msg}</div>
    ${cve ? `<div class="rlog-entry-cve">${cve}</div>` : ''}
  `;
  log.prepend(entry);
}

// ── Toast notifications ────────────────────────────────────
function showToast(msg, type = 'info') {
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = msg;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// ── Vulnerable Code Demo ──────────────────────────────────
const vulnExamples = {
  sqli: {
    title: 'SQL Injection (CVE-2024-SQLI-001)',
    bad: `<span class="hl-cmt">// ❌ VULNERABLE — Unsanitized input</span>
<span class="hl-key">async function</span> getUser(userId) {
  <span class="hl-key">const</span> query = <span class="hl-bad">"SELECT * FROM users WHERE id = " + userId</span>;
  <span class="hl-cmt">// Attacker input: "1 OR 1=1 DROP TABLE users--"</span>
  <span class="hl-key">return</span> db.execute(query);
}`,
    good: `<span class="hl-cmt">// ✅ FIXED — Parameterized query (Concert Secure Coder)</span>
<span class="hl-key">async function</span> getUser(userId) {
  <span class="hl-key">const</span> query = <span class="hl-good">"SELECT * FROM users WHERE id = $1"</span>;
  <span class="hl-key">const</span> params = <span class="hl-good">[userId]</span>;
  <span class="hl-cmt">// Input is safely parameterized — no injection possible</span>
  <span class="hl-key">return</span> db.execute(query, params);
}`,
  },
  xss: {
    title: 'Cross-Site Scripting (CVE-2024-XSS-007)',
    bad: `<span class="hl-cmt">// ❌ VULNERABLE — innerHTML with user input</span>
<span class="hl-key">function</span> showMessage(userInput) {
  document.getElementById(<span class="hl-str">'output'</span>).innerHTML =
    <span class="hl-bad">"Hello, " + userInput</span>;
  <span class="hl-cmt">// Attacker: &lt;script&gt;document.cookie&lt;/script&gt;</span>
}`,
    good: `<span class="hl-cmt">// ✅ FIXED — textContent + DOMPurify (Concert Secure Coder)</span>
<span class="hl-key">function</span> showMessage(userInput) {
  <span class="hl-key">const</span> sanitized = <span class="hl-good">DOMPurify.sanitize(userInput)</span>;
  document.getElementById(<span class="hl-str">'output'</span>).textContent =
    <span class="hl-good">"Hello, " + sanitized</span>;
}`,
  },
  hardcoded: {
    title: 'Hardcoded Secrets (CVE-2024-SEC-012)',
    bad: `<span class="hl-cmt">// ❌ VULNERABLE — Credentials in source code</span>
<span class="hl-key">const</span> config = {
  dbPassword: <span class="hl-bad">"P@ssw0rd123"</span>,
  apiKey:     <span class="hl-bad">"sk-prod-abc123xyz789"</span>,
  jwtSecret:  <span class="hl-bad">"supersecretkey"</span>,
};
<span class="hl-cmt">// Committed to git — visible to all developers!</span>`,
    good: `<span class="hl-cmt">// ✅ FIXED — IBM Vault integration (Concert Secure Coder)</span>
<span class="hl-key">const</span> vault = <span class="hl-key">require</span>(<span class="hl-str">'node-vault'</span>);
<span class="hl-key">const</span> client = vault({ endpoint: <span class="hl-good">'http://192.168.3.7:8200'</span> });

<span class="hl-key">async function</span> getSecrets() {
  <span class="hl-key">const</span> { data } = <span class="hl-key">await</span> <span class="hl-good">client.read('secret/payment/config')</span>;
  <span class="hl-key">return</span> data; <span class="hl-cmt">// Rotated automatically by Vault</span>
}`,
  },
  outdated: {
    title: 'Outdated Dependencies (CVE-2024-LOG4J-007)',
    bad: `<span class="hl-cmt">// ❌ VULNERABLE — package.json with CVEs</span>
{
  <span class="hl-str">"dependencies"</span>: {
    <span class="hl-bad">"express"</span>: <span class="hl-bad">"4.17.1"</span>,    <span class="hl-cmt">// CVE-2022-24999 — ReDOS</span>
    <span class="hl-bad">"jsonwebtoken"</span>: <span class="hl-bad">"8.5.1"</span>, <span class="hl-cmt">// CVE-2022-23529</span>
    <span class="hl-bad">"axios"</span>: <span class="hl-bad">"0.21.0"</span>       <span class="hl-cmt">// CVE-2023-45857 — SSRF</span>
  }
}`,
    good: `<span class="hl-cmt">// ✅ FIXED — Concert Secure Coder auto-upgraded</span>
{
  <span class="hl-str">"dependencies"</span>: {
    <span class="hl-good">"express"</span>: <span class="hl-good">"4.21.2"</span>,    <span class="hl-cmt">// ✅ Patched</span>
    <span class="hl-good">"jsonwebtoken"</span>: <span class="hl-good">"9.0.2"</span>, <span class="hl-cmt">// ✅ Patched</span>
    <span class="hl-good">"axios"</span>: <span class="hl-good">"1.7.9"</span>        <span class="hl-cmt">// ✅ Patched</span>
  }
}`,
  },
};

function showVulnCode(btn, type) {
  if (btn) {
    document.querySelectorAll('.vuln-tab').forEach(t => t.classList.remove('active'));
    btn.classList.add('active');
  }
  const ex = vulnExamples[type];
  if (!ex) return;
  document.getElementById('codeCompare').innerHTML = `
    <div class="code-pane">
      <div class="code-pane-header vuln">⚠️ Vulnerable Code <span>${ex.title}</span></div>
      <pre>${ex.bad}</pre>
    </div>
    <div class="code-pane">
      <div class="code-pane-header fixed">✅ Secure Coder Fix</div>
      <pre>${ex.good}</pre>
    </div>
  `;
}

// ── Scan panel ─────────────────────────────────────────────
function openScanPanel() {
  document.getElementById('scanOverlay').style.display = 'flex';
}
function closeScanPanel() {
  document.getElementById('scanOverlay').style.display = 'none';
}

// Init
window.addEventListener('DOMContentLoaded', () => {
  showVulnCode(null, 'sqli');
  checkVaultStatus();
  initScoreDisplay();
});

function initScoreDisplay() {
  const scoreEl = document.getElementById('scoreValue');
  if (scoreEl) {
    scoreEl.textContent = '--';
    scoreEl.className = 'score-value';
  }
}

function updateSecurityScore(critCount, highCount, medCount, lowCount) {
  const total = critCount * 10 + highCount * 5 + medCount * 2 + lowCount;
  let score = Math.max(0, 100 - total);
  const el = document.getElementById('scoreValue');
  if (!el) return;
  el.textContent = score + '%';
  el.className = 'score-value ' + (score >= 80 ? 'high-score' : score >= 50 ? 'mid-score' : 'low-score');
}
