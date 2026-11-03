/* ============================================================
   scanner.js — IBM Concert Secure Coder live scanner
   IBM Concert Secure Coder Demo
   ============================================================ */

'use strict';

// ── Finding database ────────────────────────────────────────
const FINDINGS = [
  {
    id:       'FIND-001',
    sev:      'critical',
    title:    'SQL Injection via unparameterized query',
    file:     'src/routes/payment.js:42',
    cve:      'CVE-2024-SQLI-001',
    fix:      'Use parameterized queries / prepared statements',
    fixType:  'code',
    remMsg:   'Concert Secure Coder refactored query to use pg-promise parameterized syntax',
  },
  {
    id:       'FIND-002',
    sev:      'critical',
    title:    'Hardcoded Stripe API secret key in source',
    file:     'src/config/payment.js:7',
    cve:      'CVE-2024-SEC-012',
    fix:      'Migrate to IBM Vault secret path: secret/payment/api',
    fixType:  'vault',
    remMsg:   'Concert Secure Coder replaced hardcoded key with IBM Vault lookup at 192.168.3.7',
  },
  {
    id:       'FIND-003',
    sev:      'high',
    title:    'CVV stored in session after authorization',
    file:     'src/handlers/checkout.js:88',
    cve:      'CVE-2024-PCI-003',
    fix:      'Remove CVV from session — PCI DSS §3.2 prohibition',
    fixType:  'code',
    remMsg:   'Concert Secure Coder deleted session.cvv assignment — PCI DSS compliant',
  },
  {
    id:       'FIND-004',
    sev:      'high',
    title:    'XSS via innerHTML with unsanitized user input',
    file:     'public/js/app.js:71',
    cve:      'CVE-2024-XSS-007',
    fix:      'Replace innerHTML with textContent + DOMPurify',
    fixType:  'code',
    remMsg:   'Concert Secure Coder added DOMPurify.sanitize() before DOM insertion',
  },
  {
    id:       'FIND-005',
    sev:      'high',
    title:    'express 4.17.1 — ReDoS vulnerability',
    file:     'package.json:12',
    cve:      'CVE-2022-24999',
    fix:      'Upgrade express to ≥ 4.21.2',
    fixType:  'package',
    remMsg:   'Concert Secure Coder upgraded express 4.17.1 → 4.21.2 (same major, CVE-free)',
  },
  {
    id:       'FIND-006',
    sev:      'high',
    title:    'jsonwebtoken 8.5.1 — verification bypass',
    file:     'package.json:15',
    cve:      'CVE-2022-23529',
    fix:      'Upgrade jsonwebtoken to ≥ 9.0.2',
    fixType:  'package',
    remMsg:   'Concert Secure Coder upgraded jsonwebtoken 8.5.1 → 9.0.2',
  },
  {
    id:       'FIND-007',
    sev:      'medium',
    title:    'axios 0.21.0 — SSRF via redirect following',
    file:     'package.json:18',
    cve:      'CVE-2023-45857',
    fix:      'Upgrade axios to ≥ 1.7.9',
    fixType:  'package',
    remMsg:   'Concert Secure Coder upgraded axios 0.21.0 → 1.7.9',
  },
  {
    id:       'FIND-008',
    sev:      'medium',
    title:    'Card number logged in plaintext (PAN exposure)',
    file:     'src/middleware/logger.js:23',
    cve:      'CVE-2024-PCI-008',
    fix:      'Mask card number in logs — show only last 4 digits',
    fixType:  'code',
    remMsg:   'Concert Secure Coder added PAN masking — logs show **** **** **** 1234',
  },
  {
    id:       'FIND-009',
    sev:      'medium',
    title:    'Missing CSRF protection on payment endpoint',
    file:     'src/app.js:55',
    cve:      'CVE-2024-CSRF-002',
    fix:      'Add csurf middleware or SameSite=Strict cookies',
    fixType:  'code',
    remMsg:   'Concert Secure Coder added helmet + csurf middleware',
  },
  {
    id:       'FIND-010',
    sev:      'low',
    title:    'HTTP Strict-Transport-Security header missing',
    file:     'src/app.js:10',
    cve:      'CWE-319',
    fix:      'Add Strict-Transport-Security header via helmet',
    fixType:  'code',
    remMsg:   'Concert Secure Coder added helmet.hsts() to Express middleware',
  },
  {
    id:       'FIND-011',
    sev:      'low',
    title:    'Vault token hardcoded in server config',
    file:     'src/vault/client.js:3',
    cve:      'CVE-2024-SEC-015',
    fix:      'Load vault token from VAULT_TOKEN env variable',
    fixType:  'vault',
    remMsg:   'Concert Secure Coder replaced hardcoded token with process.env.VAULT_TOKEN',
  },
];

// ── State ───────────────────────────────────────────────────
let scanState = {
  findings: [],
  fixed:    new Set(),
  scanning: false,
};

// ── Run scan ────────────────────────────────────────────────
async function runScan() {
  if (scanState.scanning) return;
  scanState.scanning = true;
  scanState.findings = [];
  scanState.fixed.clear();

  const btn = document.getElementById('scanBtn');
  const remBtn = document.getElementById('remediateBtn');
  if (btn) { btn.classList.add('scanning'); btn.textContent = '⏳ Scanning…'; }
  if (remBtn) remBtn.style.display = 'none';

  // Reset counters
  updateCounters(0, 0, 0, 0);
  document.getElementById('findingsList').innerHTML = `
    <div class="finding-placeholder">
      <div class="spinner" style="width:32px;height:32px;margin:auto"></div>
      <p style="margin-top:12px">Scanning with IBM Concert Secure Coder…</p>
    </div>`;

  addAuditEntry('info', '🔍', 'IBM Concert Secure Coder scan started');
  logRemediation('info', 'Scan Started', 'Running icsc_scan_packages, icsc_scan_code, icsc_scan_secrets', '');

  // Open scan overlay
  openScanPanel();
  renderScanProgress([]);

  // Simulate progressive scanning
  const scanPhases = [
    { icon: '📦', text: 'Scanning npm dependencies (icsc_scan_packages)…', delay: 600 },
    { icon: '🔍', text: 'Scanning source code for SAST findings (icsc_scan_code)…', delay: 900 },
    { icon: '🔑', text: 'Scanning for hardcoded secrets (icsc_scan_secrets)…', delay: 700 },
    { icon: '🏦', text: 'Checking Vault configuration at 192.168.3.7…', delay: 800 },
    { icon: '📋', text: 'Building CVE report…', delay: 500 },
  ];

  for (const phase of scanPhases) {
    await simulateScanPhase(phase);
  }

  // Populate findings progressively
  for (const finding of FINDINGS) {
    await new Promise(r => setTimeout(r, 120));
    scanState.findings.push(finding);
    renderFindings();
    updateCountersFromFindings();
    addScanStep(finding);
  }

  await new Promise(r => setTimeout(r, 600));

  // Wrap up
  const { crit, high, med, low } = countSeverities();
  const total = crit + high + med + low;

  updateSecurityScore(crit, high, med, low);
  addAuditEntry('warn', '🚨', `Scan complete — ${total} findings: ${crit} critical, ${high} high, ${med} medium, ${low} low`);
  logRemediation('warn', `Scan Complete`, `Found ${total} security issues — ${crit} critical requiring immediate attention`, '');

  showToast(`🔍 Scan complete: ${total} findings detected`, 'warn');

  if (btn) {
    btn.classList.remove('scanning');
    btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> Re-Scan`;
  }
  if (remBtn) remBtn.style.display = 'flex';

  scanState.scanning = false;

  // Add final scan summary to overlay
  addFinalScanSummary(total, crit, high, med, low);
}

function countSeverities() {
  const visible = scanState.findings.filter(f => !scanState.fixed.has(f.id));
  return {
    crit: visible.filter(f => f.sev === 'critical').length,
    high: visible.filter(f => f.sev === 'high').length,
    med:  visible.filter(f => f.sev === 'medium').length,
    low:  visible.filter(f => f.sev === 'low').length,
  };
}

function updateCounters(c, h, m, l) {
  const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
  set('critCount', c);
  set('highCount', h);
  set('medCount',  m);
  set('lowCount',  l);
}

function updateCountersFromFindings() {
  const { crit, high, med, low } = countSeverities();
  updateCounters(crit, high, med, low);
}

// ── Render findings list ────────────────────────────────────
function renderFindings() {
  const list = document.getElementById('findingsList');
  if (!list) return;

  if (scanState.findings.length === 0) {
    list.innerHTML = `<div class="finding-placeholder"><div class="pulse-icon">⚡</div><p>Click "Scan Now" to detect vulnerabilities</p></div>`;
    return;
  }

  list.innerHTML = scanState.findings.map(f => `
    <div class="finding-item ${f.sev} ${scanState.fixed.has(f.id) ? 'fixed' : ''}" onclick="onFindingClick('${f.id}')">
      <span class="finding-sev sev-${f.sev}">${f.sev}</span>
      <div class="finding-info">
        <div class="finding-title">${scanState.fixed.has(f.id) ? '✅ ' : ''}${f.title}</div>
        <div class="finding-file">${f.file}</div>
        <div class="finding-fix">${f.fix}</div>
      </div>
      ${scanState.fixed.has(f.id)
        ? '<span class="finding-fixed-badge">FIXED</span>'
        : `<button class="finding-fix-btn" style="background:none;border:none;color:var(--accent2);font-size:10px;cursor:pointer;flex-shrink:0" onclick="event.stopPropagation();autoFix('${f.id}')">Fix</button>`
      }
    </div>
  `).join('');
}

// ── Auto-fix single finding ─────────────────────────────────
async function autoFix(findingId) {
  const finding = scanState.findings.find(f => f.id === findingId);
  if (!finding || scanState.fixed.has(findingId)) return;

  logRemediation('action', `Fixing ${finding.id}`, `Applying ${finding.fixType} remediation…`, finding.cve);
  addAuditEntry('info', '🔧', `Auto-fixing: ${finding.title}`);

  await new Promise(r => setTimeout(r, 800));

  scanState.fixed.add(findingId);
  renderFindings();
  updateCountersFromFindings();

  const { crit, high, med, low } = countSeverities();
  updateSecurityScore(crit, high, med, low);

  logRemediation('fix', `${finding.id} Fixed`, finding.remMsg, finding.cve);
  addAuditEntry('ok', '✅', `Fixed: ${finding.title} (${finding.cve})`);
  showToast(`✅ Fixed: ${finding.title.substring(0, 40)}…`, 'success');
}

// ── Auto-remediate ALL ──────────────────────────────────────
async function remediateAll() {
  const unfixed = scanState.findings.filter(f => !scanState.fixed.has(f.id));
  if (unfixed.length === 0) {
    showToast('All findings already fixed!', 'success');
    return;
  }

  logRemediation('action', 'Auto-Remediation Started', `IBM Concert Secure Coder fixing ${unfixed.length} findings…`, '');
  addAuditEntry('info', '🤖', `Concert Secure Coder auto-remediating ${unfixed.length} findings…`);
  showToast(`🤖 Remediating ${unfixed.length} findings…`, 'info');

  // Fix in severity order: critical → high → medium → low
  const order = ['critical', 'high', 'medium', 'low'];
  for (const sev of order) {
    const group = unfixed.filter(f => f.sev === sev);
    for (const f of group) {
      await autoFix(f.id);
      await new Promise(r => setTimeout(r, 200));
    }
  }

  const { crit, high, med, low } = countSeverities();
  const total = crit + high + med + low;
  updateSecurityScore(crit, high, med, low);

  addAuditEntry('ok', '🎉', `Auto-remediation complete — ${unfixed.length} fixes applied, ${total} remaining`);
  logRemediation('fix', 'Remediation Complete', `${unfixed.length} findings resolved. Security score updated.`, '');
  showToast(`🎉 All ${unfixed.length} findings remediated!`, 'success');
}

// ── Finding click ───────────────────────────────────────────
function onFindingClick(findingId) {
  const f = scanState.findings.find(x => x.id === findingId);
  if (!f) return;
  addAuditEntry('info', '🔍', `Reviewing finding: ${f.title} — ${f.cve}`);
  logRemediation(
    scanState.fixed.has(findingId) ? 'fix' : 'warn',
    f.id + ': ' + f.title,
    scanState.fixed.has(findingId) ? 'RESOLVED — ' + f.remMsg : f.fix,
    f.cve
  );
}

// ── Scan overlay progress ──────────────────────────────────
let scanOverlaySteps = [];

function renderScanProgress(steps) {
  const area = document.getElementById('scanProgressArea');
  if (!area) return;
  area.innerHTML = steps.map(s => `
    <div class="scan-step">
      <span class="step-icon">${s.icon}</span>
      <span class="step-text">${s.text}</span>
      <span class="step-status status-${s.status}">${s.status}</span>
    </div>
  `).join('');
}

async function simulateScanPhase(phase) {
  const area = document.getElementById('scanProgressArea');
  const step = { icon: phase.icon, text: phase.text, status: 'scanning' };
  scanOverlaySteps.push(step);
  renderScanProgress(scanOverlaySteps);
  await new Promise(r => setTimeout(r, phase.delay));
  step.status = 'done';
  renderScanProgress(scanOverlaySteps);
}

function addScanStep(finding) {
  const area = document.getElementById('scanProgressArea');
  if (!area) return;
  const step = {
    icon: finding.sev === 'critical' ? '🚨' : finding.sev === 'high' ? '⚠️' : finding.sev === 'medium' ? '🔶' : 'ℹ️',
    text: `[${finding.sev.toUpperCase()}] ${finding.title}`,
    status: finding.sev === 'critical' || finding.sev === 'high' ? 'found' : 'found',
  };
  scanOverlaySteps.push(step);
  renderScanProgress(scanOverlaySteps);
  area.scrollTop = area.scrollHeight;
}

function addFinalScanSummary(total, crit, high, med, low) {
  const area = document.getElementById('scanProgressArea');
  if (!area) return;
  const summary = document.createElement('div');
  summary.style.cssText = 'margin-top:16px; padding:14px; background:rgba(255,23,68,0.05); border:1px solid rgba(255,23,68,0.2); border-radius:10px;';
  summary.innerHTML = `
    <div style="font-size:15px;font-weight:700;margin-bottom:8px;">📊 Scan Summary</div>
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;text-align:center">
      <div style="color:var(--critical)"><div style="font-size:24px;font-weight:800">${crit}</div><div style="font-size:10px">Critical</div></div>
      <div style="color:var(--high)"><div style="font-size:24px;font-weight:800">${high}</div><div style="font-size:10px">High</div></div>
      <div style="color:var(--medium)"><div style="font-size:24px;font-weight:800">${med}</div><div style="font-size:10px">Medium</div></div>
      <div style="color:var(--low)"><div style="font-size:24px;font-weight:800">${low}</div><div style="font-size:10px">Low</div></div>
    </div>
    <div style="margin-top:12px;text-align:center">
      <button onclick="remediateAll(); closeScanPanel();"
        style="padding:10px 24px;background:linear-gradient(135deg,#24a148,#42be65);border:none;border-radius:8px;color:white;font-size:13px;font-weight:700;cursor:pointer;">
        🛡️ Auto-Remediate All ${total} Findings
      </button>
    </div>
  `;
  area.appendChild(summary);
  area.scrollTop = area.scrollHeight;
}
