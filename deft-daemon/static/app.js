// DEFT Console
const API_BASE = window.location.origin;
let refreshInterval = null;
let cachedPartners = [];
let cachedVirtualFiles = [];
let clientConnected = false;
let refreshPaused = false;

// Pause refresh when any modal is open or form input is focused
function pauseRefresh() { refreshPaused = true; }
function resumeRefresh() { refreshPaused = false; }

// Tab navigation
document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(btn.dataset.tab).classList.add('active');
    });
});

// ============ Utilities ============
function formatUptime(seconds) {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${mins}m`;
    return `${mins}m`;
}

function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

async function apiFetch(endpoint, options = {}) {
    try {
        const response = await fetch(`${API_BASE}${endpoint}`, {
            headers: { 'Content-Type': 'application/json', ...options.headers },
            ...options
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return options.method === 'DELETE' ? true : await response.json();
    } catch (error) {
        console.error(`API error (${endpoint}):`, error);
        return null;
    }
}

async function apiPost(endpoint, data) {
    return apiFetch(endpoint, { method: 'POST', body: JSON.stringify(data) });
}

async function apiPut(endpoint, data) {
    return apiFetch(endpoint, { method: 'PUT', body: JSON.stringify(data) });
}

async function apiDelete(endpoint) {
    return apiFetch(endpoint, { method: 'DELETE' });
}

// ============ Modal Management ============
function showModal(id) {
    document.getElementById(id).classList.add('active');
    pauseRefresh();
}

function closeModal(id) {
    document.getElementById(id).classList.remove('active');
    resumeRefresh();
}

// Close modal on backdrop click
document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeModal(modal.id);
    });
});

// ============ Status Updates ============
async function updateStatus() {
    const data = await apiFetch('/api/status');
    const badge = document.getElementById('connection-status');

    if (data) {
        badge.textContent = 'Connected';
        badge.classList.add('connected');
        badge.classList.remove('error');
        document.getElementById('stat-uptime').textContent = formatUptime(data.uptime_seconds);
        document.getElementById('stat-connections').textContent = data.active_connections;
        document.getElementById('stat-transfers').textContent = data.active_transfers;
        document.getElementById('stat-version').textContent = `v${data.version}`;
        document.getElementById('footer-version').textContent = data.version;
    } else {
        badge.textContent = 'Disconnected';
        badge.classList.remove('connected');
        badge.classList.add('error');
    }
    document.getElementById('last-update').textContent = `Last update: ${new Date().toLocaleTimeString()}`;
}

// ============ Partners ============
async function updatePartners() {
    const data = await apiFetch('/api/partners');
    cachedPartners = data || [];
    const tbody = document.getElementById('partners-table');

    if (!data || data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty">No partners configured</td></tr>';
        return;
    }

    tbody.innerHTML = data.map(p => `
        <tr>
            <td><strong>${escapeHtml(p.id)}</strong></td>
            <td>${(p.endpoints || []).map(e => `<code>${escapeHtml(e)}</code>`).join('<br>') || '--'}</td>
            <td>
                ${(p.virtual_files || []).map(vf => `<span class="badge badge-info">${escapeHtml(vf)}</span>`).join(' ') || '<span class="badge badge-warning">None</span>'}
            </td>
            <td>
                ${(p.allowed_certs || []).length > 0
            ? `<span class="badge badge-success" title="Client certs:\n${(p.allowed_certs || []).map(c => escapeHtml(c.substring(0, 16) + '...')).join('\n')}">🔐 ${(p.allowed_certs || []).length} client</span>`
            : '<span class="badge badge-warning">No client mTLS</span>'}
                ${(p.allowed_server_certs || []).length > 0
            ? `<span class="badge badge-info" title="Server certs:\n${(p.allowed_server_certs || []).map(c => escapeHtml(c.substring(0, 16) + '...')).join('\n')}">🔒 ${(p.allowed_server_certs || []).length} server</span>`
            : ''}
            </td>
            <td>
                <span class="badge ${p.connected ? 'badge-success' : 'badge-warning'}">
                    ${p.connected ? 'Connected' : 'Idle'}
                </span>
            </td>
            <td class="action-btns">
                <button class="btn btn-sm btn-secondary" onclick="editPartner('${escapeHtml(p.id)}')">Edit</button>
                <button class="btn btn-sm btn-danger" onclick="deletePartner('${escapeHtml(p.id)}')">Delete</button>
            </td>
        </tr>
    `).join('');
}

function showPartnerModal(partner = null) {
    document.getElementById('partner-modal-title').textContent = partner ? 'Edit Partner' : 'Add Partner';
    document.getElementById('partner-edit-id').value = partner?.id || '';
    document.getElementById('partner-id').value = partner?.id || '';
    document.getElementById('partner-id').disabled = !!partner;
    document.getElementById('partner-endpoints').value = (partner?.endpoints || []).join('\n');
    document.getElementById('partner-certs').value = (partner?.allowed_certs || []).join('\n');
    document.getElementById('partner-server-certs').value = (partner?.allowed_server_certs || []).join('\n');

    // Populate VF checkboxes
    const container = document.getElementById('partner-vf-checkboxes');
    const partnerVfs = partner?.virtual_files || [];
    container.innerHTML = cachedVirtualFiles.map(vf => `
        <label>
            <input type="checkbox" value="${escapeHtml(vf.name)}" ${partnerVfs.includes(vf.name) ? 'checked' : ''}>
            ${escapeHtml(vf.name)}
        </label>
    `).join('') || '<span class="empty">No virtual files defined</span>';

    showModal('partner-modal');
}

async function editPartner(id) {
    const partner = cachedPartners.find(p => p.id === id);
    if (partner) showPartnerModal(partner);
}

async function deletePartner(id) {
    if (!confirm(`Delete partner "${id}"?`)) return;
    const result = await apiDelete(`/api/partners/${id}`);
    if (result) {
        addLogEntry(`Deleted partner: ${id}`);
        await updatePartners();
    }
}

document.getElementById('partner-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const editId = document.getElementById('partner-edit-id').value;
    const partnerId = document.getElementById('partner-id').value;
    const endpoints = document.getElementById('partner-endpoints').value.split('\n').filter(e => e.trim());
    const certs = document.getElementById('partner-certs').value.split('\n').filter(c => c.trim());
    const serverCerts = document.getElementById('partner-server-certs').value.split('\n').filter(c => c.trim());
    const vfs = Array.from(document.querySelectorAll('#partner-vf-checkboxes input:checked')).map(cb => cb.value);

    const data = { id: partnerId, endpoints, allowed_certs: certs, allowed_server_certs: serverCerts, virtual_files: vfs };

    const result = editId
        ? await apiPut(`/api/partners/${editId}`, data)
        : await apiPost('/api/partners', data);

    if (result) {
        closeModal('partner-modal');
        addLogEntry(`${editId ? 'Updated' : 'Created'} partner: ${partnerId}`);
        await updatePartners();
    }
});

// ============ Virtual Files ============
async function updateVirtualFiles() {
    const data = await apiFetch('/api/virtual-files');
    cachedVirtualFiles = data || [];
    const tbody = document.getElementById('virtual-files-table');

    if (!data || data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty">No virtual files configured</td></tr>';
        return;
    }

    tbody.innerHTML = data.map(vf => `
        <tr>
            <td><strong>${escapeHtml(vf.name)}</strong></td>
            <td><code>${escapeHtml(vf.path)}</code></td>
            <td>
                <span class="badge ${vf.direction === 'send' ? 'badge-info' : 'badge-success'}">
                    ${vf.direction === 'send' ? '↑ Send' : '↓ Receive'}
                </span>
            </td>
            <td>${formatBytes(vf.size)}</td>
            <td>
                ${(vf.partners || []).map(p => `<span class="badge badge-warning">${escapeHtml(p)}</span>`).join(' ') || '<span class="badge badge-secondary">All</span>'}
            </td>
            <td class="action-btns">
                <button class="btn btn-sm btn-secondary" onclick="editVirtualFile('${escapeHtml(vf.name)}')">Edit</button>
                <button class="btn btn-sm btn-danger" onclick="deleteVirtualFile('${escapeHtml(vf.name)}')">Delete</button>
            </td>
        </tr>
    `).join('');
}

function showVirtualFileModal(vf = null) {
    document.getElementById('vf-modal-title').textContent = vf ? 'Edit Virtual File' : 'Add Virtual File';
    document.getElementById('vf-edit-name').value = vf?.name || '';
    document.getElementById('vf-name').value = vf?.name || '';
    document.getElementById('vf-name').disabled = !!vf;
    document.getElementById('vf-path').value = vf?.path || '';
    document.getElementById('vf-direction').value = vf?.direction || 'receive';
    document.getElementById('vf-pattern').value = vf?.pattern || '';

    // Compute which partners have access to this VF from cachedPartners
    const vfPartners = vf ? cachedPartners
        .filter(p => (p.virtual_files || []).includes(vf.name))
        .map(p => p.id) : [];

    // Populate partner checkboxes
    const container = document.getElementById('vf-partner-checkboxes');
    container.innerHTML = cachedPartners.map(p => `
        <label>
            <input type="checkbox" value="${escapeHtml(p.id)}" ${vfPartners.includes(p.id) ? 'checked' : ''}>
            ${escapeHtml(p.id)}
        </label>
    `).join('') || '<span class="empty">No partners defined</span>';

    showModal('vf-modal');
}

async function editVirtualFile(name) {
    const vf = cachedVirtualFiles.find(v => v.name === name);
    if (vf) showVirtualFileModal(vf);
}

async function deleteVirtualFile(name) {
    if (!confirm(`Delete virtual file "${name}"?`)) return;
    const result = await apiDelete(`/api/virtual-files/${name}`);
    if (result) {
        addLogEntry(`Deleted virtual file: ${name}`);
        await updateVirtualFiles();
    }
}

document.getElementById('vf-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const editName = document.getElementById('vf-edit-name').value;
    const name = document.getElementById('vf-name').value;
    const path = document.getElementById('vf-path').value;
    const direction = document.getElementById('vf-direction').value;
    const pattern = document.getElementById('vf-pattern').value;
    const partners = Array.from(document.querySelectorAll('#vf-partner-checkboxes input:checked')).map(cb => cb.value);

    const data = { name, path, direction, pattern: pattern || null, partners };

    const result = editName
        ? await apiPut(`/api/virtual-files/${editName}`, data)
        : await apiPost('/api/virtual-files', data);

    if (result) {
        closeModal('vf-modal');
        addLogEntry(`${editName ? 'Updated' : 'Created'} virtual file: ${name}`);
        await updateVirtualFiles();
    }
});

// ============ Transfers ============
async function updateTransfers() {
    const data = await apiFetch('/api/transfers');
    const tbody = document.getElementById('transfers-table');

    if (!data || data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty">No active transfers</td></tr>';
        return;
    }

    tbody.innerHTML = data.map(t => `
        <tr>
            <td><code>${escapeHtml(t.id.substring(0, 8))}</code></td>
            <td>${escapeHtml(t.virtual_file)}</td>
            <td>${escapeHtml(t.partner_id)}</td>
            <td>
                <span class="badge ${t.direction === 'send' ? 'badge-info' : 'badge-success'}">
                    ${t.direction === 'send' ? '↑ Send' : '↓ Receive'}
                </span>
            </td>
            <td>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: ${t.progress_percent}%"></div>
                </div>
                <small>${t.progress_percent}% (${formatBytes(t.bytes_transferred)} / ${formatBytes(t.total_bytes)})</small>
            </td>
            <td>
                <span class="badge badge-${t.status === 'active' ? 'success' : (t.status === 'interrupted' ? 'warning' : 'error')}">${t.status}</span>
            </td>
            <td class="action-btns">
                ${t.status === 'interrupted' ?
            `<button class="btn btn-sm btn-primary" onclick="resumeTransfer('${escapeHtml(t.id)}')">Resume</button>` :
            `<button class="btn btn-sm btn-warning" onclick="interruptTransfer('${escapeHtml(t.id)}')">Interrupt</button>`
        }
                <button class="btn btn-sm btn-danger" onclick="cancelTransfer('${escapeHtml(t.id)}')">Cancel</button>
            </td>
        </tr>
    `).join('');
}

async function cancelTransfer(id) {
    if (!confirm('Cancel this transfer?')) return;
    const result = await apiDelete(`/api/transfers/${id}`);
    if (result) {
        addLogEntry(`Cancelled transfer: ${id.substring(0, 8)}`);
        await updateTransfers();
    }
}

async function interruptTransfer(id) {
    const result = await apiPost(`/api/transfers/${id}/interrupt`, {});
    if (result && result.status === 'interrupted') {
        addLogEntry(`Interrupted transfer: ${id.substring(0, 8)}`);
        showNotification('Transfer interrupted - can be resumed later', 'warning');
        await updateTransfers();
    } else {
        showNotification(result?.error || 'Failed to interrupt transfer', 'error');
    }
}

async function resumeTransfer(id) {
    const result = await apiPost(`/api/transfers/${id}/resume`, {});
    if (result && result.status === 'resumed') {
        addLogEntry(`Resumed transfer: ${id.substring(0, 8)}`);
        showNotification('Transfer resumed', 'success');
        await updateTransfers();
    } else {
        showNotification(result?.error || 'Failed to resume transfer', 'error');
    }
}

// ============ History ============
async function updateHistory() {
    const data = await apiFetch('/api/history');
    const tbody = document.getElementById('history-table');

    if (!data || data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty">No transfer history</td></tr>';
        return;
    }

    const sorted = [...data].reverse();
    tbody.innerHTML = sorted.slice(0, 50).map(t => `
        <tr>
            <td><code>${escapeHtml(t.id.substring(0, 12))}</code></td>
            <td>${escapeHtml(t.virtual_file)}</td>
            <td>${escapeHtml(t.partner_id)}</td>
            <td>
                <span class="badge ${t.direction === 'send' ? 'badge-info' : 'badge-success'}">
                    ${t.direction === 'send' ? '↑ Send' : '↓ Receive'}
                </span>
            </td>
            <td>${formatBytes(t.total_bytes)}</td>
            <td>
                <span class="badge ${t.status === 'complete' ? 'badge-success' : 'badge-error'}">${t.status}</span>
            </td>
            <td>${t.completed_at ? new Date(t.completed_at).toLocaleString() : '--'}</td>
        </tr>
    `).join('');
}

// ============ Client ============
document.getElementById('connect-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const server = document.getElementById('client-server').value.trim();
    const partnerId = document.getElementById('client-partner-id').value.trim();
    const cert = document.getElementById('client-cert').value.trim();
    const key = document.getElementById('client-key').value.trim();
    const statusDiv = document.getElementById('client-status');

    if (!server || !partnerId) {
        statusDiv.className = 'client-status error';
        statusDiv.textContent = 'Server address and Partner ID are required';
        return;
    }

    statusDiv.className = 'client-status';
    statusDiv.textContent = 'Connecting...';

    // Try to connect and list files
    const result = await apiPost('/api/client/connect', {
        server,
        partner_id: partnerId,
        cert: cert || undefined,
        key: key || undefined
    });

    if (result && result.success) {
        clientConnected = true;
        statusDiv.className = 'client-status connected';
        statusDiv.textContent = `Connected to ${server} as ${partnerId}`;
        updateRemoteFiles(result.virtual_files || []);
        addLogEntry(`Connected to ${server} as ${partnerId}`);
    } else {
        statusDiv.className = 'client-status error';
        statusDiv.textContent = result?.error || 'Connection failed';
    }
});

function updateRemoteFiles(files) {
    const container = document.getElementById('remote-files-list');
    const pullSelect = document.getElementById('pull-vf');
    const pushSelect = document.getElementById('push-vf');

    if (!files || files.length === 0) {
        container.innerHTML = '<div class="empty">No virtual files available</div>';
        pullSelect.innerHTML = '<option value="">No files available</option>';
        pushSelect.innerHTML = '<option value="">No files available</option>';
        return;
    }

    container.innerHTML = files.map(f => `
        <div class="file-item">
            <div class="file-info">
                <span class="file-name">${escapeHtml(f.name)}</span>
                <span class="file-meta">${formatBytes(f.size)} • ${f.direction}</span>
            </div>
            <span class="badge ${f.direction === 'send' ? 'badge-info' : 'badge-success'}">
                ${f.direction === 'send' ? '↑' : '↓'}
            </span>
        </div>
    `).join('');

    // Files we can pull (direction=send on remote = they send to us)
    const pullableFiles = files.filter(f => f.direction === 'send');
    pullSelect.innerHTML = '<option value="">Select file...</option>' +
        pullableFiles.map(f => `<option value="${escapeHtml(f.name)}">${escapeHtml(f.name)}</option>`).join('');

    // Files we can push to (direction=receive/recv on remote = they receive from us)
    const pushableFiles = files.filter(f => f.direction === 'receive' || f.direction === 'recv');
    pushSelect.innerHTML = '<option value="">Select file...</option>' +
        pushableFiles.map(f => `<option value="${escapeHtml(f.name)}">${escapeHtml(f.name)}</option>`).join('');
}

document.getElementById('pull-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const vf = document.getElementById('pull-vf').value;
    const path = document.getElementById('pull-path').value;
    const btn = e.target.querySelector('button[type="submit"]');

    if (!vf || !path) {
        alert('Please select a file and specify output path');
        return;
    }

    btn.disabled = true;
    btn.textContent = 'Pulling...';

    try {
        const result = await apiPost('/api/client/pull', { virtual_file: vf, output_path: path });
        if (result && result.success) {
            addLogEntry(`✓ Pull complete: ${vf} -> ${path} (${formatBytes(result.bytes)})`);
            showNotification(`Pull successful: ${result.bytes} bytes`, 'success');
            await updateTransfers();
        } else {
            addLogEntry(`✗ Pull failed: ${result?.error || 'Unknown error'}`);
            showNotification(result?.error || 'Pull failed', 'error');
        }
    } finally {
        btn.disabled = false;
        btn.textContent = 'Start Pull';
    }
});

document.getElementById('push-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const file = document.getElementById('push-file').value;
    const vf = document.getElementById('push-vf').value;
    const btn = e.target.querySelector('button[type="submit"]');

    if (!file || !vf) {
        alert('Please specify a file and select destination');
        return;
    }

    btn.disabled = true;
    btn.textContent = 'Pushing...';

    try {
        const result = await apiPost('/api/client/push', { file_path: file, virtual_file: vf });
        if (result && result.success) {
            addLogEntry(`✓ Push complete: ${file} -> ${vf} (${formatBytes(result.bytes)})`);
            showNotification(`Push successful: ${result.bytes} bytes`, 'success');
            await updateTransfers();
        } else {
            addLogEntry(`✗ Push failed: ${result?.error || 'Unknown error'}`);
            showNotification(result?.error || 'Push failed', 'error');
        }
    } finally {
        btn.disabled = false;
        btn.textContent = 'Start Push';
    }
});

function showNotification(message, type) {
    const existing = document.querySelector('.notification');
    if (existing) existing.remove();

    const notif = document.createElement('div');
    notif.className = `notification notification-${type}`;
    notif.textContent = message;
    notif.style.cssText = `
        position: fixed; top: 20px; right: 20px; padding: 12px 20px;
        border-radius: 6px; color: white; font-weight: 500; z-index: 1000;
        background: ${type === 'success' ? '#10b981' : '#ef4444'};
        animation: slideIn 0.3s ease;
    `;
    document.body.appendChild(notif);
    setTimeout(() => notif.remove(), 4000);
}

// ============ Settings ============
async function updateSettings() {
    const config = await apiFetch('/api/config');
    if (!config) return;

    // Server config
    document.getElementById('cfg-listen').value = config.server?.listen || '';
    document.getElementById('cfg-api-listen').value = config.limits?.api_listen || '';
    document.getElementById('cfg-chunk-size').value = config.storage?.chunk_size || 262144;
    document.getElementById('cfg-temp-dir').value = config.storage?.temp_dir || '';
    document.getElementById('cfg-server-enabled').checked = config.server?.enabled !== false;

    // Certs
    document.getElementById('cfg-cert').value = config.server?.cert || '';
    document.getElementById('cfg-key').value = config.server?.key || '';
    document.getElementById('cfg-ca').value = config.server?.ca || '';

    // Limits
    document.getElementById('cfg-max-conn').value = config.limits?.max_connections_per_partner || 10;
    document.getElementById('cfg-max-bandwidth').value = config.limits?.max_bandwidth_mbps || 100;
    document.getElementById('cfg-idle-timeout').value = config.limits?.idle_timeout_seconds || 300;
}

document.getElementById('server-config-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const data = {
        server: {
            listen: document.getElementById('cfg-listen').value,
            enabled: document.getElementById('cfg-server-enabled').checked
        },
        storage: {
            chunk_size: parseInt(document.getElementById('cfg-chunk-size').value),
            temp_dir: document.getElementById('cfg-temp-dir').value
        },
        limits: {
            api_listen: document.getElementById('cfg-api-listen').value
        }
    };

    const result = await apiPut('/api/config/server', data);
    if (result) {
        addLogEntry('Server configuration updated');
        alert('Server configuration saved. Some changes may require restart.');
    }
});

document.getElementById('cert-config-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const data = {
        cert: document.getElementById('cfg-cert').value,
        key: document.getElementById('cfg-key').value,
        ca: document.getElementById('cfg-ca').value
    };

    const result = await apiPut('/api/config/certs', data);
    if (result) {
        addLogEntry('Certificate configuration updated');
        alert('Certificate paths saved. Restart required to apply.');
    }
});

document.getElementById('limits-config-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const data = {
        max_connections_per_partner: parseInt(document.getElementById('cfg-max-conn').value),
        max_bandwidth_mbps: parseInt(document.getElementById('cfg-max-bandwidth').value),
        idle_timeout_seconds: parseInt(document.getElementById('cfg-idle-timeout').value)
    };

    const result = await apiPut('/api/config/limits', data);
    if (result) {
        addLogEntry('Rate limits updated');
    }
});

async function reloadConfig() {
    const result = await apiPost('/api/config/reload', {});
    if (result) {
        addLogEntry('Configuration reloaded');
        alert('Configuration reloaded successfully');
        await refreshAll();
    } else {
        alert('Failed to reload configuration');
    }
}

async function exportConfig() {
    const config = await apiFetch('/api/config');
    if (config) {
        const blob = new Blob([JSON.stringify(config, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'deft-config.json';
        a.click();
        URL.revokeObjectURL(url);
    }
}

// ============ Activity Log ============
function addLogEntry(message, type = 'info') {
    const log = document.getElementById('activity-log');
    const empty = log.querySelector('.log-empty');
    if (empty) empty.remove();

    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.innerHTML = `
        <span class="log-time">${new Date().toLocaleTimeString()}</span>
        <span>${escapeHtml(message)}</span>
    `;
    log.insertBefore(entry, log.firstChild);
    while (log.children.length > 50) log.removeChild(log.lastChild);
}

// ============ Refresh ============
async function refreshAll() {
    await Promise.all([
        updateStatus(),
        updatePartners(),
        updateVirtualFiles(),
        updateTransfers(),
        updateHistory()
    ]);
}

// Only refresh active transfers (called by interval)
async function refreshTransfers() {
    if (refreshPaused) return;
    await updateTransfers();
}

// ============ Initialize ============
document.addEventListener('DOMContentLoaded', () => {
    // Pause refresh when any input/textarea/select is focused
    document.querySelectorAll('input, textarea, select').forEach(el => {
        el.addEventListener('focus', pauseRefresh);
        el.addEventListener('blur', resumeRefresh);
    });

    refreshAll();
    updateSettings(); // Load settings once on init
    refreshInterval = setInterval(refreshTransfers, 5000);
    addLogEntry('Console initialized');
});
