/**
 * SchoolSec - JavaScript pentru dashboard-ul în timp real
 * Gestionează actualizarea live a statisticilor și graficele
 */

// Referința la graficul de protocoale
let protocolChart = null;

/**
 * Inițializează graficul de distribuție a protocoalelor.
 * @param {Object} data - Dicționar protocol -> număr pachete
 */
function initProtocolChart(data) {
    const ctx = document.getElementById('protocolChart');
    if (!ctx) return;

    const labels = Object.keys(data);
    const values = Object.values(data);

    // Culori pentru diferite protocoale
    const colors = [
        '#3fb950', '#58a6ff', '#f78166', '#d29922',
        '#bc8cff', '#39d353', '#ffa657', '#ff7b72'
    ];

    protocolChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: colors.slice(0, labels.length),
                borderColor: '#0d1117',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#c9d1d9',
                        font: { size: 11 },
                        padding: 10
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((context.raw / total) * 100).toFixed(1);
                            return ` ${context.label}: ${context.raw} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

/**
 * Actualizează graficul de protocoale cu date noi.
 * @param {Object} newData - Date noi pentru grafic
 */
function updateProtocolChart(newData) {
    if (!protocolChart) {
        initProtocolChart(newData);
        return;
    }

    const labels = Object.keys(newData);
    const values = Object.values(newData);

    protocolChart.data.labels = labels;
    protocolChart.data.datasets[0].data = values;
    protocolChart.update('none'); // Actualizare fără animație
}

/**
 * Formatează numărul de bytes în unități citibile.
 * @param {number} bytes - Numărul de bytes
 * @returns {string} - Valoarea formatată (ex: "1.5 MB")
 */
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return parseFloat((bytes / Math.pow(1024, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Actualizează statisticile principale din API.
 * Apelată periodic pentru actualizare live.
 */
function updateStats() {
    fetch('/api/stats')
        .then(response => {
            if (!response.ok) throw new Error('Răspuns invalid de la server');
            return response.json();
        })
        .then(data => {
            // Actualizăm cardurile de statistici
            const totalPackets = document.getElementById('totalPackets');
            const activeAlerts = document.getElementById('activeAlerts');
            const blockedIPs = document.getElementById('blockedIPs');

            if (totalPackets) totalPackets.textContent = data.total_packets.toLocaleString();
            if (activeAlerts) activeAlerts.textContent = data.active_alerts;
            if (blockedIPs) blockedIPs.textContent = data.blocked_ips;

            // Actualizăm graficul de protocoale
            if (data.protocols && Object.keys(data.protocols).length > 0) {
                updateProtocolChart(data.protocols);
            }

            // Actualizăm tabelul de pachete recente
            updateRecentPackets(data.last_packets);
        })
        .catch(error => {
            console.warn('[SchoolSec] Eroare la actualizarea statisticilor:', error);
        });
}

/**
 * Actualizează tabelul cu pachetele recente.
 * @param {Array} packets - Lista cu ultimele pachete
 */
function updateRecentPackets(packets) {
    const tbody = document.querySelector('#recentPacketsTable tbody');
    if (!tbody || !packets || packets.length === 0) return;

    // Construim HTML-ul nou
    const rows = packets.slice().reverse().map(pkt => {
        const time = pkt.timestamp ? pkt.timestamp.slice(-8) : '--:--:--';
        return `
            <tr>
                <td><small class="text-muted">${escapeHtml(time)}</small></td>
                <td><code class="text-success small">${escapeHtml(pkt.src_ip || '')}</code></td>
                <td><code class="text-info small">${escapeHtml(pkt.dst_ip || '')}</code></td>
                <td><span class="badge bg-secondary">${escapeHtml(pkt.protocol || '')}</span></td>
            </tr>
        `;
    });

    tbody.innerHTML = rows.join('');
}

/**
 * Sanitizează string-urile pentru inserare în HTML (protecție XSS).
 * @param {string} text - Textul de sanitizat
 * @returns {string} - Textul sanitizat
 */
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return String(text).replace(/[&<>"']/g, function(m) { return map[m]; });
}

/**
 * Inițializare la încărcarea paginii.
 */
document.addEventListener('DOMContentLoaded', function() {
    // Activăm tooltip-urile Bootstrap
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    console.log('[SchoolSec] Dashboard inițializat.');
});
