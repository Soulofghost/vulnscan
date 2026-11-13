let currentFindingFilter = 'ALL';

document.addEventListener('DOMContentLoaded', () => {
  loadPostureSummary();
  loadAssets();
  loadFindings();

  // Refresh button
  document.getElementById('refreshDataBtn').addEventListener('click', () => {
    loadPostureSummary();
    loadAssets();
    loadFindings();
  });

  // Tab switching
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

      e.target.classList.add('active');
      const tabId = e.target.getAttribute('data-tab');
      document.getElementById(tabId).classList.add('active');
    });
  });

  // Finding filter chips
  document.querySelectorAll('.f-chip').forEach(chip => {
    chip.addEventListener('click', (e) => {
      document.querySelectorAll('.f-chip').forEach(c => c.classList.remove('active'));
      e.target.classList.add('active');
      currentFindingFilter = e.target.getAttribute('data-filter');
      loadFindings();
    });
  });

  // New Asset submission
  document.getElementById('newAssetForm').addEventListener('submit', handleCreateAsset);

  // CVSS Calculator inputs
  const calcInputs = ['calcAV', 'calcAC', 'calcPR', 'calcUI', 'calcS', 'calcC', 'calcI', 'calcA'];
  calcInputs.forEach(id => {
    document.getElementById(id).addEventListener('change', updateCVSSCalculation);
  });
  updateCVSSCalculation();
});

async function loadPostureSummary() {
  try {
    const res = await fetch('/api/v1/findings/summary/posture');
    if (!res.ok) return;
    const data = await res.json();
    document.getElementById('statAssets').textContent = data.total_assets;
    document.getElementById('statTotalFindings').textContent = data.total_findings;
    document.getElementById('statCritical').textContent = data.critical_count;
    document.getElementById('statHigh').textContent = data.high_count;
    document.getElementById('statPostureScore').textContent = data.overall_posture_score;
  } catch (err) {
    console.error('Failed to load posture summary:', err);
  }
}

async function loadAssets() {
  try {
    const res = await fetch('/api/v1/assets');
    if (!res.ok) return;
    const assets = await res.json();
    const container = document.getElementById('assetContainer');

    if (!assets || assets.length === 0) {
      container.innerHTML = '<div class="empty-state">No assets registered. Click + Register Asset to add one.</div>';
      return;
    }

    container.innerHTML = assets.map(a => `
      <div class="asset-item" id="asset-${a.id}">
        <div class="asset-top">
          <span class="asset-title">${escapeHtml(a.name)}</span>
          <span class="env-pill env-${a.environment}">${a.environment}</span>
        </div>
        <div class="asset-meta">
          <span>IP: <strong>${escapeHtml(a.ip_address)}</strong> [${a.criticality}]</span>
          <span>Ports: <code>${escapeHtml(a.open_ports)}</code></span>
          <span>Last Audit: ${a.last_scanned ? new Date(a.last_scanned).toLocaleString() : 'Never Scanned'}</span>
        </div>
        <div class="asset-actions">
          <button class="btn-scan" onclick="runAuditScan('${a.id}')">Audit Asset</button>
        </div>
      </div>
    `).join('');
  } catch (err) {
    console.error('Failed to load assets:', err);
  }
}

async function runAuditScan(assetId) {
  const btn = document.querySelector(`#asset-${assetId} .btn-scan`);
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Auditing...';
  }

  try {
    const res = await fetch(`/api/v1/assets/${assetId}/scan`, { method: 'POST' });
    if (res.ok) {
      await loadAssets();
      await loadFindings();
      await loadPostureSummary();
    }
  } catch (err) {
    console.error('Scan failed:', err);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Audit Asset';
    }
  }
}

async function loadFindings() {
  try {
    let url = '/api/v1/findings';
    if (currentFindingFilter === 'UNREMEDIATED') {
      url += '?status=UNREMEDIATED';
    } else if (currentFindingFilter === 'CRITICAL' || currentFindingFilter === 'HIGH') {
      url += `?severity=${currentFindingFilter}`;
    }

    const res = await fetch(url);
    if (!res.ok) return;
    const findings = await res.json();
    const container = document.getElementById('findingsContainer');

    if (!findings || findings.length === 0) {
      container.innerHTML = `<div class="empty-state">No findings matching filter [${currentFindingFilter}].</div>`;
      return;
    }

    container.innerHTML = findings.map(f => `
      <div class="finding-card" id="find-${f.id}">
        <div class="finding-top">
          <span class="cve-badge">${escapeHtml(f.cve_id)}</span>
          <span class="cvss-score-pill pill-${f.severity}">${f.base_score} • ${f.severity}</span>
        </div>
        <div class="finding-title">${escapeHtml(f.title)}</div>
        <div class="finding-meta">
          <span>Target: <strong>${escapeHtml(f.asset_ip)}</strong></span>
          <span>Port: <strong>${f.port}</strong> (${escapeHtml(f.service)})</span>
          <span>Vector: <code>${escapeHtml(f.cvss_vector)}</code></span>
          <span>Status: <strong>${f.status}</strong></span>
        </div>
        <p class="finding-desc">${escapeHtml(f.description)}</p>
        <div class="remediation-box">
          <span class="rem-label">REMEDIATION PLAYBOOK:</span>
          <span class="rem-text">${escapeHtml(f.remediation)}</span>
        </div>
        <div class="finding-actions">
          ${f.status === 'UNREMEDIATED' ? `
            <button class="btn btn-sm btn-patch" onclick="updateFindingStatus('${f.id}', 'PATCH_APPLIED')">Mark Patch Applied</button>
          ` : ''}
          ${f.status === 'PATCH_APPLIED' ? `
            <button class="btn btn-sm btn-verify" onclick="updateFindingStatus('${f.id}', 'VERIFIED')">Verify Remediation</button>
          ` : ''}
          ${f.status === 'VERIFIED' ? `
            <button class="btn btn-sm btn-secondary" onclick="updateFindingStatus('${f.id}', 'UNREMEDIATED')">Reopen Finding</button>
          ` : ''}
        </div>
      </div>
    `).join('');
  } catch (err) {
    console.error('Failed to load findings:', err);
  }
}

async function updateFindingStatus(findingId, newStatus) {
  try {
    const res = await fetch(`/api/v1/findings/${findingId}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus })
    });
    if (res.ok) {
      loadFindings();
      loadPostureSummary();
    }
  } catch (err) {
    console.error('Failed to update status:', err);
  }
}

function toggleAddAssetModal() {
  const panel = document.getElementById('addAssetPanel');
  panel.classList.toggle('hidden');
}

async function handleCreateAsset(e) {
  e.preventDefault();
  const payload = {
    name: document.getElementById('assetName').value.trim(),
    ip_address: document.getElementById('assetIp').value.trim(),
    environment: document.getElementById('assetEnv').value,
    criticality: document.getElementById('assetCrit').value,
    open_ports: document.getElementById('assetPorts').value.trim()
  };

  try {
    const res = await fetch('/api/v1/assets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (res.ok) {
      document.getElementById('newAssetForm').reset();
      toggleAddAssetModal();
      loadAssets();
      loadPostureSummary();
    }
  } catch (err) {
    console.error('Failed to create asset:', err);
  }
}

async function updateCVSSCalculation() {
  const req = {
    av: document.getElementById('calcAV').value,
    ac: document.getElementById('calcAC').value,
    pr: document.getElementById('calcPR').value,
    ui: document.getElementById('calcUI').value,
    s: document.getElementById('calcS').value,
    c: document.getElementById('calcC').value,
    i: document.getElementById('calcI').value,
    a: document.getElementById('calcA').value
  };

  try {
    const res = await fetch('/api/v1/cvss/calculate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req)
    });
    if (!res.ok) return;
    const data = await res.json();

    document.getElementById('calcScoreVal').textContent = data.base_score;
    const badge = document.getElementById('calcSevBadge');
    badge.textContent = data.severity;
    badge.className = `calc-sev-badge pill-${data.severity}`;

    document.getElementById('calcVectorString').textContent = data.vector;
    document.getElementById('calcImpactVal').textContent = data.impact_score;
    document.getElementById('calcExploitVal').textContent = data.exploitability_score;
  } catch (err) {
    console.error('CVSS calculation failed:', err);
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
