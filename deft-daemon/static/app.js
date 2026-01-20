// DEFT Admin Dashboard
const API_BASE = window.location.origin;
let refreshInterval = null;

// Tab navigation
document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));

        btn.classList.add('active');
        document.getElementById(btn.dataset.tab).classList.add('active');
    });
});

// Format uptime
function formatUptime(seconds) {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const mins = Math.floor((seconds % 3600) / 60);

    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${mins}m`;
    return `${mins}m`;
}

// Format bytes
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// Fetch with error handling
async function apiFetch(endpoint) {
    try {
        const response = await fetch(`${API_BASE}${endpoint}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.json();
    } catch (error) {
        console.error(`API error (${endpoint}):`, error);
        return null;
    }
}

// Update status
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

    document.getElementById('last-update').textContent =
        `Last update: ${new Date().toLocaleTimeString()}`;
}

// Update partners table
async function updatePartners() {
    const data = await apiFetch('/api/partners');
    const tbody = document.getElementById('partners-table');

    if (!data || data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty">No partners configured</td></tr>';
        return;
    }

    tbody.innerHTML = data.map(p => `
        <tr>
            <td><strong>${escapeHtml(p.id)}</strong></td>
            <td>${p.endpoints.map(e => `<code>${escapeHtml(e)}</code>`).join('<br>')}</td>
            <td>
                <span class="badge ${p.connected ? 'badge-success' : 'badge-warning'}">
                    ${p.connected ? 'Connected' : 'Idle'}
                </span>
            </td>
            <td>${p.last_seen || '--'}</td>
            <td>${p.transfers_today}</td>
        </tr>
    `).join('');
}

// Update transfers table
async function updateTransfers() {
    const data = await apiFetch('/api/transfers');
    const tbody = document.getElementById('transfers-table');

    if (!data || data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty">No active transfers</td></tr>';
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
                <span class="badge badge-${t.status === 'active' ? 'success' : 'warning'}">
                    ${t.status}
                </span>
            </td>
        </tr>
    `).join('');
}

// Update config display
async function updateConfig() {
    const data = await apiFetch('/api/config');
    const display = document.getElementById('config-display');

    if (data) {
        display.textContent = JSON.stringify(data, null, 2);
    } else {
        display.textContent = 'Failed to load configuration';
    }
}

// Update history table
async function updateHistory() {
    const data = await apiFetch('/api/history');
    const tbody = document.getElementById('history-table');

    if (!data || data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty">No transfer history</td></tr>';
        return;
    }

    // Sort by completed_at descending (most recent first)
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
                <span class="badge ${t.status === 'complete' ? 'badge-success' : 'badge-error'}">
                    ${t.status}
                </span>
            </td>
            <td>${t.completed_at ? new Date(t.completed_at).toLocaleString() : '--'}</td>
        </tr>
    `).join('');
}

// Escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Add activity log entry
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

    // Keep only last 50 entries
    while (log.children.length > 50) {
        log.removeChild(log.lastChild);
    }
}

// Refresh all data
async function refreshAll() {
    await Promise.all([
        updateStatus(),
        updatePartners(),
        updateTransfers(),
        updateConfig(),
        updateHistory()
    ]);
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    refreshAll();
    refreshInterval = setInterval(refreshAll, 5000);
    addLogEntry('Dashboard initialized');
});
