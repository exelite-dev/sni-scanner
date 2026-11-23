// SNI Scanner Pro - Frontend Application
// Real-time SSE streaming, multi-source resolution, and lowest-latency sorting.

let currentEventSource = null;
let allResults = [];
let isScanning = false;

document.addEventListener('DOMContentLoaded', () => {
    const scanForm = document.getElementById('scanForm');
    const startScanBtn = document.getElementById('startScanBtn');
    const stopScanBtn = document.getElementById('stopScanBtn');
    const tableSearch = document.getElementById('tableSearch');
    const gradeFilter = document.getElementById('gradeFilter');
    const tableSortFilter = document.getElementById('tableSortFilter');
    const categorySelect = document.getElementById('categorySelect');
    const customUrlGroup = document.getElementById('customUrlGroup');
    const exportJsonBtn = document.getElementById('exportJsonBtn');
    const exportCsvBtn = document.getElementById('exportCsvBtn');
    const serverIpInput = document.getElementById('serverIp');

    // Geo detect on load
    if (serverIpInput && serverIpInput.value) {
        detectServerGeo(serverIpInput.value.trim());
    }

    // Debounced geo detect on IP change
    let geoTimeout = null;
    serverIpInput.addEventListener('input', () => {
        clearTimeout(geoTimeout);
        geoTimeout = setTimeout(() => {
            const ip = serverIpInput.value.trim();
            if (ip) {
                detectServerGeo(ip);
            }
        }, 500);
    });

    categorySelect.addEventListener('change', () => {
        if (categorySelect.value === 'custom_url') {
            customUrlGroup.style.display = 'block';
        } else {
            customUrlGroup.style.display = 'none';
        }
    });

    scanForm.addEventListener('submit', (e) => {
        e.preventDefault();
        startScan();
    });

    stopScanBtn.addEventListener('click', () => {
        stopScan();
    });

    tableSearch.addEventListener('input', () => {
        renderFilteredTable();
    });

    gradeFilter.addEventListener('change', () => {
        renderFilteredTable();
    });

    tableSortFilter.addEventListener('change', () => {
        renderFilteredTable();
    });

    exportJsonBtn.addEventListener('click', () => {
        exportJson();
    });

    exportCsvBtn.addEventListener('click', () => {
        exportCsv();
    });
});

function showToast(message) {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.classList.add('show');
    setTimeout(() => {
        toast.classList.remove('show');
    }, 2200);
}

async function detectServerGeo(ip) {
    const geoBadge = document.getElementById('serverGeoInfo');
    const geoFlag = document.getElementById('geoFlag');
    const geoText = document.getElementById('geoText');
    if (!geoBadge) return;

    geoBadge.className = 'geo-status-badge loading';
    geoFlag.textContent = '⏳';
    geoText.textContent = 'در حال استعلام لوکیشن سرور...';

    try {
        const resp = await fetch(`/api/server/detect?ip=${encodeURIComponent(ip)}`);
        const data = await resp.json();
        if (data && data.country) {
            geoBadge.className = 'geo-status-badge';
            geoFlag.textContent = data.flag || '🌐';
            geoText.textContent = `${data.country} (${data.city}) • ${data.org}`;

            // If auto category selected, update category option text to show matched country
            const catOptionAuto = document.querySelector('#categorySelect option[value="auto"]');
            if (catOptionAuto) {
                catOptionAuto.textContent = `🎯 خودکار بر اساس لوکیشن سرور: ${data.country} (${data.flag})`;
            }
        } else {
            geoBadge.className = 'geo-status-badge error';
            geoFlag.textContent = '⚠️';
            geoText.textContent = 'موقعیت سرور نامشخص است.';
        }
    } catch (e) {
        geoBadge.className = 'geo-status-badge error';
        geoFlag.textContent = '⚠️';
        geoText.textContent = 'خطا در ارتباط با سرور استعلام.';
    }
}

function openPanelModal(domain, alpn) {
    const modal = document.getElementById('panelModal');
    const targetInput = document.getElementById('modalTargetVal');
    const sniInput = document.getElementById('modalSniVal');
    const fpInput = document.getElementById('modalFingerprintVal');

    targetInput.value = `${domain}:443`;
    sniInput.value = domain;
    fpInput.value = `Fingerprint: chrome | ALPN: ${alpn || 'h2'},http/1.1`;

    modal.style.display = 'flex';
}

function closePanelModal() {
    const modal = document.getElementById('panelModal');
    if (modal) {
        modal.style.display = 'none';
    }
}

function copyFromInput(inputId) {
    const input = document.getElementById(inputId);
    if (!input) return;
    navigator.clipboard.writeText(input.value).then(() => {
        showToast(`کپی شد: ${input.value}`);
    }).catch(() => {
        showToast('خطا در کپی');
    });
}

function copyAllPanelConfig() {
    const target = document.getElementById('modalTargetVal').value;
    const sni = document.getElementById('modalSniVal').value;
    const text = `Target: ${target}\nSNI: ${sni}\nFingerprint: chrome\nALPN: h2,http/1.1`;
    navigator.clipboard.writeText(text).then(() => {
        showToast('کانفیگ کامل پنل کپی شد!');
    }).catch(() => {
        showToast('خطا در کپی');
    });
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast(`دامنه کپی شد: ${text}`);
    }).catch(() => {
        showToast('خطا در کپی');
    });
}

function startScan() {
    if (isScanning) return;

    const category = document.getElementById('categorySelect').value;
    const customUrl = document.getElementById('customUrlInput').value.trim();
    const limit = document.getElementById('scanLimitSelect').value;
    const sortMode = document.getElementById('sortModeSelect').value;
    const serverIp = document.getElementById('serverIp').value.trim();
    const serverPort = document.getElementById('serverPort').value.trim();
    const concurrency = document.getElementById('concurrencyInput').value;
    const timeout = document.getElementById('timeoutInput').value;
    const customDomains = document.getElementById('customDomains').value.trim();

    // Reset UI
    allResults = [];
    isScanning = true;
    document.getElementById('startScanBtn').disabled = true;
    document.getElementById('stopScanBtn').disabled = false;
    document.getElementById('exportJsonBtn').disabled = true;
    document.getElementById('exportCsvBtn').disabled = true;
    document.getElementById('progressSection').style.display = 'block';
    document.getElementById('resultsTableBody').innerHTML = '';
    document.getElementById('statProgress').textContent = '0 / 0';
    document.getElementById('statTls13').textContent = '0';
    document.getElementById('statMinPing').textContent = '--';
    document.getElementById('statBestSni').textContent = 'در حال ارزیابی...';
    document.getElementById('resultsCountBadge').textContent = '0 نتیجه';

    // Build SSE Query
    const params = new URLSearchParams({
        category: category,
        server_ip: serverIp,
        server_port: serverPort,
        concurrency: concurrency,
        timeout: timeout,
        limit: limit,
        sort_by: sortMode,
    });
    if (customDomains) {
        params.append('custom_domains', customDomains);
    }
    if (category === 'custom_url' && customUrl) {
        params.append('custom_url', customUrl);
    }

    if (currentEventSource) {
        currentEventSource.close();
    }

    currentEventSource = new EventSource(`/api/scan/stream?${params.toString()}`);

    currentEventSource.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            if (data.type === 'result') {
                handleResultItem(data.progress, data.item);
            } else if (data.type === 'finished') {
                handleFinished(data);
            }
        } catch (e) {
            console.error('Error parsing SSE event:', e);
        }
    };

    currentEventSource.onerror = (err) => {
        console.warn('SSE stream error or finished:', err);
        stopScan(false);
    };
}

function handleResultItem(progress, item) {
    allResults.push(item);

    // Update Progress
    document.getElementById('currentStatusText').textContent = `در حال اسکن دامنه: ${progress.current_domain}`;
    document.getElementById('progressPercentage').textContent = `${progress.percent}%`;
    document.getElementById('progressBarFill').style.width = `${progress.percent}%`;

    // Update Metrics
    document.getElementById('statProgress').textContent = `${progress.completed} / ${progress.total}`;
    
    const tls13Count = allResults.filter(r => r.is_tls13).length;
    document.getElementById('statTls13').textContent = tls13Count;

    // Fast working items sorted by latency
    const workingWithPing = allResults.filter(r => r.latency_ms && r.is_tls13 && !r.dns_poisoned);
    if (workingWithPing.length > 0) {
        workingWithPing.sort((a, b) => a.latency_ms - b.latency_ms);
        const minPing = Math.round(workingWithPing[0].latency_ms);
        document.getElementById('statMinPing').textContent = `${minPing} ms`;
        document.getElementById('statBestSni').textContent = `${workingWithPing[0].domain} (${minPing}ms)`;
    }

    document.getElementById('resultsCountBadge').textContent = `${allResults.length} نتیجه`;
    renderFilteredTable();
}

function handleFinished(finalData) {
    isScanning = false;
    document.getElementById('startScanBtn').disabled = false;
    document.getElementById('stopScanBtn').disabled = true;
    document.getElementById('exportJsonBtn').disabled = false;
    document.getElementById('exportCsvBtn').disabled = false;
    document.getElementById('currentStatusText').textContent = '✅ اسکن با موفقیت به پایان رسید.';
    document.getElementById('progressBarFill').style.width = '100%';
    document.getElementById('progressPercentage').textContent = '100%';

    if (currentEventSource) {
        currentEventSource.close();
        currentEventSource = null;
    }

    // Refresh best item
    const working = allResults.filter(r => r.latency_ms && r.is_tls13 && !r.dns_poisoned);
    if (working.length > 0) {
        working.sort((a, b) => a.latency_ms - b.latency_ms);
        document.getElementById('statBestSni').textContent = `${working[0].domain} (${Math.round(working[0].latency_ms)}ms)`;
    }
}

function stopScan(callBackend = true) {
    isScanning = false;
    document.getElementById('startScanBtn').disabled = false;
    document.getElementById('stopScanBtn').disabled = true;

    if (currentEventSource) {
        currentEventSource.close();
        currentEventSource = null;
    }

    if (callBackend) {
        fetch('/api/scan/stop', { method: 'POST' }).catch(() => {});
    }

    document.getElementById('currentStatusText').textContent = '⏹ اسکن متوقف شد.';
    if (allResults.length > 0) {
        document.getElementById('exportJsonBtn').disabled = false;
        document.getElementById('exportCsvBtn').disabled = false;
    }
}

function sortItems(list, sortMode) {
    if (sortMode === 'score') {
        return [...list].sort((a, b) => (b.score || 0) - (a.score || 0));
    }
    // Default: Latency ascending (lowest ping first)
    return [...list].sort((a, b) => {
        const aHealthy = (a.is_tls13 && !a.dns_poisoned && a.latency_ms);
        const bHealthy = (b.is_tls13 && !b.dns_poisoned && b.latency_ms);
        if (aHealthy && !bHealthy) return -1;
        if (!aHealthy && bHealthy) return 1;
        const latA = a.latency_ms || 999999;
        const latB = b.latency_ms || 999999;
        if (latA !== latB) return latA - latB;
        return (b.score || 0) - (a.score || 0);
    });
}

function renderFilteredTable() {
    const tbody = document.getElementById('resultsTableBody');
    const query = document.getElementById('tableSearch').value.toLowerCase().trim();
    const grade = document.getElementById('gradeFilter').value;
    const sortMode = document.getElementById('tableSortFilter').value;

    let filtered = sortItems(allResults, sortMode);

    if (query) {
        filtered = filtered.filter(r => r.domain.toLowerCase().includes(query) || (r.primary_ip && r.primary_ip.includes(query)));
    }

    if (grade !== 'all') {
        if (grade === 'S+') {
            filtered = filtered.filter(r => r.grade === 'S+');
        } else if (grade === 'A') {
            filtered = filtered.filter(r => r.grade === 'S+' || r.grade === 'A');
        } else if (grade === 'B') {
            filtered = filtered.filter(r => ['S+', 'A', 'B'].includes(r.grade));
        }
    }

    if (filtered.length === 0) {
        tbody.innerHTML = `
            <tr class="empty-row">
                <td colspan="11">هیچ نتیجه‌ای مطابق با جستجو یا فیلتر فعلی یافت نشد.</td>
            </tr>
        `;
        return;
    }

    let rowsHtml = '';
    filtered.forEach((item, index) => {
        const isHealthy = item.is_tls13 && !item.dns_poisoned;
        const pingClass = (item.latency_ms && item.latency_ms < 150) ? 'ping-ultra' : (item.latency_ms && item.latency_ms < 300) ? 'ping-good' : 'ping-high';
        const pingDisplay = item.latency_ms ? `<span class="badge ${pingClass} ltr font-mono">${Math.round(item.latency_ms)} ms</span>` : '<span class="text-danger">تایم‌اوت</span>';
        const tcpPingDisplay = item.tcp_latency_ms ? `<span class="text-muted ltr font-mono">${Math.round(item.tcp_latency_ms)} ms</span>` : '--';

        const gradeClass = `grade-${(item.grade || 'F').toLowerCase().replace('+', 'plus')}`;
        const tlsDisplay = item.is_tls13 ? '<span class="badge badge-success">TLS 1.3</span>' : `<span class="badge badge-warning">${item.tls_version || 'Fail'}</span>`;
        const alpnDisplay = item.alpn ? `<span class="badge badge-info font-mono">${item.alpn}</span>` : '<span class="text-muted">None</span>';
        const ipDisplay = item.primary_ip ? `<span class="font-mono ltr">${item.primary_ip}</span>` : '<span class="text-danger">نامعتبر</span>';
        const statusBadge = isHealthy ? '<span class="badge badge-success">مناسب Reality</span>' : '<span class="badge badge-danger">نامناسب</span>';

        let certHealthDisplay = '<span class="text-muted font-mono">--</span>';
        if (item.cert_trusted && item.cert_valid) {
            const issuerShort = (item.issuer || 'Trusted CA').substring(0, 14);
            const daysText = item.cert_expires_days !== null ? `${item.cert_expires_days} روز` : 'معتبر';
            certHealthDisplay = `<span class="badge badge-success font-mono" title="صادرکننده: ${item.issuer || ''} | تاریخ انقضا: ${item.cert_not_after || ''}">✅ ${issuerShort} (${daysText})</span>`;
        } else if (item.cert_expires_days !== null && item.cert_expires_days <= 0) {
            certHealthDisplay = `<span class="badge badge-danger" title="${item.cert_not_after || ''}">❌ منقضی شده</span>`;
        } else if (item.cert_trusted === false) {
            certHealthDisplay = `<span class="badge badge-warning" title="${item.error || 'گواهی بدون اعتماد عمومی'}">⚠️ بدون اعتماد عمومی</span>`;
        } else if (item.cert_san_matched === false && item.cert_san && item.cert_san.length > 0) {
            certHealthDisplay = `<span class="badge badge-warning" title="عدم تطابق با SAN دامنه">⚠️ عدم تطابق SAN</span>`;
        }

        rowsHtml += `
            <tr class="${index === 0 && isHealthy ? 'top-row' : ''}">
                <td class="font-mono text-muted">${index + 1}</td>
                <td>
                    <div class="domain-cell">
                        <strong class="domain-name font-mono ltr">${item.domain}</strong>
                    </div>
                </td>
                <td>${pingDisplay}</td>
                <td>${certHealthDisplay}</td>
                <td>
                    <div class="score-pill score-${Math.floor(item.score / 20)}">
                        ${item.score}/100
                    </div>
                </td>
                <td><span class="badge-grade ${gradeClass}">${item.grade}</span></td>
                <td>${tlsDisplay}</td>
                <td>${alpnDisplay}</td>
                <td>${ipDisplay}</td>
                <td>${statusBadge}</td>
                <td>
                    <div style="display: flex; gap: 6px; flex-wrap: wrap;">
                        <button class="btn btn-sm btn-copy" onclick="copyToClipboard('${item.domain}')" title="کپی نام دامنه">
                            📋 کپی SNI
                        </button>
                        <button class="btn btn-sm btn-panel-cfg" onclick="openPanelModal('${item.domain}', '${item.alpn || 'h2'}')" title="کپی کانفیگ آماده پنل">
                            ⚡️ تنظیم در پنل
                        </button>
                    </div>
                </td>
            </tr>
        `;
    });

    tbody.innerHTML = rowsHtml;
}

function exportJson() {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(allResults, null, 2));
    const dlAnchor = document.createElement('a');
    dlAnchor.setAttribute('href', dataStr);
    dlAnchor.setAttribute('download', `sni_scanner_${Date.now()}.json`);
    dlAnchor.click();
    dlAnchor.remove();
}

function exportCsv() {
    if (allResults.length === 0) return;
    const headers = ['domain', 'latency_ms', 'tcp_latency_ms', 'score', 'grade', 'is_tls13', 'alpn', 'primary_ip', 'tags'];
    let csvContent = 'data:text/csv;charset=utf-8,' + headers.join(',') + '\n';

    allResults.forEach(r => {
        const row = [
            r.domain,
            r.latency_ms || '',
            r.tcp_latency_ms || '',
            r.score,
            r.grade,
            r.is_tls13,
            r.alpn || '',
            r.primary_ip || '',
            `"${(r.tags || []).join(';')}"`
        ];
        csvContent += row.join(',') + '\n';
    });

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `sni_scanner_${Date.now()}.csv`);
    link.click();
    link.remove();
}
