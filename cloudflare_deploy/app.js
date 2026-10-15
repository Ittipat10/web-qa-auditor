// CapiBug QA Auditor Frontend Logic with Corporate Access Protection & Cloudflare Edge Support

let allowedDomain = '@yourcompany.com';
let currentJobId = null;
let pollTimer = null;
let currentResults = null;
let activeFilter = 'all';
let renderedLogsCount = 0;

document.addEventListener('DOMContentLoaded', () => {
  // Auth Elements
  const authModalOverlay = document.getElementById('authModalOverlay');
  const authForm = document.getElementById('authForm');
  const authEmailInput = document.getElementById('authEmailInput');
  const authErrorMsg = document.getElementById('authErrorMsg');
  const userBadge = document.getElementById('userBadge');
  const userEmailText = document.getElementById('userEmailText');
  const logoutBtn = document.getElementById('logoutBtn');

  // Fetch dynamic configuration
  fetch('/api/config')
    .then(r => r.json())
    .then(cfg => {
      if (cfg.allowed_domain) {
        allowedDomain = cfg.allowed_domain.toLowerCase();
        updateAuthDomainUI();
      }
    })
    .catch(() => {});

  function updateAuthDomainUI() {
    const domainNotice = document.getElementById('authDomainNotice');
    if (domainNotice) domainNotice.textContent = allowedDomain;
    if (authEmailInput) authEmailInput.placeholder = `name${allowedDomain}`;
  }

  // Scanner Form Elements
  const scanForm = document.getElementById('scanForm');
  const urlInput = document.getElementById('urlInput');
  const maxPagesSelect = document.getElementById('maxPagesSelect');
  const submitBtn = document.getElementById('submitBtn');
  
  const progressSection = document.getElementById('progressSection');
  const resultsSection = document.getElementById('resultsSection');
  const errorBanner = document.getElementById('errorBanner');
  const errorMessage = document.getElementById('errorMessage');

  const exportCsvBtn = document.getElementById('exportCsvBtn');
  const newScanBtn = document.getElementById('newScanBtn');
  const tableSearch = document.getElementById('tableSearch');

  // Check saved authentication
  let authorizedEmail = localStorage.getItem('capi_authorized_email') || '';
  if (authorizedEmail && authorizedEmail.toLowerCase().endsWith(allowedDomain)) {
    unlockUI(authorizedEmail);
  } else {
    lockUI();
  }

  // Handle Auth Form Submission
  authForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const email = authEmailInput.value.trim().toLowerCase();

    if (!email.endsWith(allowedDomain)) {
      authErrorMsg.textContent = `Zugriff verweigert: Bitte verwenden Sie eine offizielle Firmen-E-Mail mit der Endung ${allowedDomain}`;
      showElement(authErrorMsg);
      authEmailInput.focus();
      return;
    }

    // Authorization success
    localStorage.setItem('capi_authorized_email', email);
    authorizedEmail = email;
    hideElement(authErrorMsg);
    unlockUI(email);
  });

  // Handle Logout
  logoutBtn.addEventListener('click', () => {
    localStorage.removeItem('capi_authorized_email');
    authorizedEmail = '';
    lockUI();
  });

  function lockUI() {
    showElement(authModalOverlay);
    hideElement(userBadge);
    authEmailInput.value = '';
    authEmailInput.focus();
  }

  function unlockUI(email) {
    hideElement(authModalOverlay);
    showElement(userBadge);
    userEmailText.textContent = email;
  }

  // Form Submission for Scanning
  scanForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    // Ensure user is authorized
    if (!authorizedEmail || !authorizedEmail.endsWith(allowedDomain)) {
      lockUI();
      return;
    }

    let url = urlInput.value.trim();
    if (!url) return;

    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
      urlInput.value = url;
    }

    const maxPages = parseInt(maxPagesSelect.value) || 50;

    // Reset UI
    hideElement(errorBanner);
    hideElement(resultsSection);
    showElement(progressSection);
    
    submitBtn.disabled = true;
    submitBtn.querySelector('.btn-text').textContent = 'Prüfung läuft...';
    
    document.getElementById('stageTitle').textContent = 'Sitemap-Erkennung...';
    document.getElementById('targetDisplay').textContent = `Ziel: ${url}`;
    document.getElementById('progressBar').style.width = '5%';
    document.getElementById('percentBadge').textContent = '5%';
    
    const terminalLogs = document.getElementById('terminalLogs');
    terminalLogs.innerHTML = '';
    renderedLogsCount = 0;
    appendLog(`[INFO] QA-Prüfung für ${url} gestartet (Max. ${maxPages} Seiten)`);
    appendLog(`[AUTH] Autorisierter Mitarbeiter: ${authorizedEmail}`);

    const startTime = Date.now();

    try {
      // Step 1: Discover Pages via Sitemap
      appendLog(`[SUCHE] Prüfe auf XML-Sitemap (/wp-sitemap.xml, /sitemap_index.xml, /sitemap.xml)...`);
      const discoverRes = await fetch('/api/discover', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, email: authorizedEmail, max_pages: maxPages })
      });

      if (discoverRes.status === 403) {
        lockUI();
        throw new Error(`Zugriff verweigert: Nur Mitarbeiter mit ${allowedDomain} sind autorisiert.`);
      }

      // If /api/discover is not available (e.g. legacy Python backend), fallback to legacy scan
      if (discoverRes.status === 404) {
        return fallbackLegacyScan(url, maxPages);
      }

      let pagesToCrawl = [url];
      if (discoverRes.ok) {
        const discoverData = await discoverRes.json();
        if (discoverData.sitemap_found && discoverData.pages && discoverData.pages.length > 0) {
          pagesToCrawl = discoverData.pages;
          appendLog(`[SITEMAP] ✅ XML-Sitemap erfolgreich gefunden: ${pagesToCrawl.length} Seiten erfasst`);
        } else {
          appendLog(`[INFO] Keine XML-Sitemap gefunden — Deep-Crawl startet rekursiv auf Startseite`);
        }
      }

      // Step 2: Multi-Page Crawl Loop
      const queue = [...pagesToCrawl];
      const visited = new Set();
      const allBrokenResults = [];
      const allSecurityWarnings = [];
      const allDocuments = [];
      let totalAssetsChecked = 0;
      let totalExternCount = 0;
      let totalImagesCount = 0;
      let totalDocsCount = 0;

      while (queue.length > 0 && visited.size < maxPages) {
        const currentPage = queue.shift();
        if (visited.has(currentPage)) continue;
        visited.add(currentPage);

        const pageNum = visited.size;
        const totalTarget = Math.min(queue.length + visited.size, maxPages);
        const progressPct = Math.min(95, Math.round(10 + (pageNum / totalTarget) * 85));

        document.getElementById('progressBar').style.width = `${progressPct}%`;
        document.getElementById('percentBadge').textContent = `${progressPct}%`;
        document.getElementById('stageTitle').textContent = `Seitenstruktur analysieren (${pageNum}/${totalTarget})`;
        appendLog(`[SEITE ${pageNum}/${totalTarget}] Analysiere: ${currentPage}`);

        try {
          const pageRes = await fetch('/api/scan-page', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              page_url: currentPage,
              root_url: url,
              email: authorizedEmail
            })
          });

          if (pageRes.status === 403) {
            lockUI();
            throw new Error(`Zugriff verweigert: Nur Mitarbeiter mit ${allowedDomain} sind autorisiert.`);
          }

          if (pageRes.ok) {
            const pageData = await pageRes.json();

            // Add newly discovered internal links to queue if not yet visited
            if (pageData.internal_links && Array.isArray(pageData.internal_links)) {
              for (const link of pageData.internal_links) {
                if (!visited.has(link) && !queue.includes(link) && (queue.length + visited.size < maxPages * 2)) {
                  queue.push(link);
                }
              }
            }

            // Aggregate findings
            if (pageData.broken_results && pageData.broken_results.length > 0) {
              allBrokenResults.push(...pageData.broken_results);
              appendLog(`[WARNUNG] ⚠️ ${pageData.broken_results.length} defekte Assets auf: ${currentPage}`);
            }

            if (pageData.security_warnings && pageData.security_warnings.length > 0) {
              allSecurityWarnings.push(...pageData.security_warnings);
            }

            if (pageData.documents && pageData.documents.length > 0) {
              allDocuments.push(...pageData.documents);
            }

            totalAssetsChecked += (pageData.assets_checked_count || 0);
            totalExternCount += (pageData.extern_count || 0);
            totalImagesCount += (pageData.images_count || 0);
            totalDocsCount += (pageData.docs_count || 0);
          }
        } catch (pageErr) {
          appendLog(`[FEHLER] Fehler bei ${currentPage}: ${pageErr.message}`);
        }
      }

      // Step 3: Complete & Render Results
      const elapsed = Math.round((Date.now() - startTime) / 100) / 10;
      document.getElementById('progressBar').style.width = '100%';
      document.getElementById('percentBadge').textContent = '100%';
      document.getElementById('stageTitle').textContent = 'Abgeschlossen';
      appendLog(`[SUCCESS] ✅ Prüfung erfolgreich abgeschlossen in ${elapsed}s!`);
      appendLog(`[SUMMARY] ${visited.size} Seiten gescannt, ${totalAssetsChecked} Assets geprüft, ${allBrokenResults.length} defekte Elemente gefunden`);
      resetSubmitButton();

      const finalResult = {
        target_url: url,
        duration_seconds: elapsed,
        summary: {
          pages_scanned: visited.size,
          total_assets_checked: totalAssetsChecked,
          external_links_count: totalExternCount,
          images_count: totalImagesCount,
          documents_count: totalDocsCount,
          total_broken: allBrokenResults.length,
          broken_links: allBrokenResults.filter(b => b.category === 'EXTERN').length,
          broken_images: allBrokenResults.filter(b => b.category === 'BILD').length,
          broken_docs: allBrokenResults.filter(b => b.category === 'DOKUMENT').length,
          security_warnings_count: allSecurityWarnings.length
        },
        pages: Array.from(visited),
        broken_results: allBrokenResults,
        security_warnings: allSecurityWarnings,
        documents: allDocuments
      };

      setTimeout(() => {
        hideElement(progressSection);
        showElement(resultsSection);
        currentResults = finalResult;
        renderResults(finalResult);
        resultsSection.scrollIntoView({ behavior: 'smooth' });
      }, 500);

    } catch (err) {
      showError(err.message);
      resetSubmitButton();
    }
  });

  async function fallbackLegacyScan(url, maxPages) {
    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, max_pages: maxPages, email: authorizedEmail })
      });
      const data = await response.json();
      if (!response.ok || data.error) throw new Error(data.error || 'Fehler beim Starten');

      if (data.status === 'completed' && data.result) {
        document.getElementById('progressBar').style.width = '100%';
        document.getElementById('percentBadge').textContent = '100%';
        document.getElementById('stageTitle').textContent = 'Abgeschlossen';
        resetSubmitButton();
        setTimeout(() => {
          hideElement(progressSection);
          showElement(resultsSection);
          currentResults = data.result;
          renderResults(data.result);
          resultsSection.scrollIntoView({ behavior: 'smooth' });
        }, 500);
        return;
      }

      currentJobId = data.job_id;
      startPolling(currentJobId);
    } catch (err) {
      showError(err.message);
      resetSubmitButton();
    }
  }

  // Polling Status
  function startPolling(jobId) {
    if (pollTimer) clearInterval(pollTimer);

    pollTimer = setInterval(async () => {
      try {
        const res = await fetch(`/api/status?job_id=${jobId}`);
        if (!res.ok) throw new Error('Statusdaten konnten nicht abgerufen werden');
        const job = await res.json();

        // Update progress bar
        const pct = job.progress || 0;
        document.getElementById('progressBar').style.width = `${pct}%`;
        document.getElementById('percentBadge').textContent = `${pct}%`;
        document.getElementById('stageTitle').textContent = job.stage || 'Wird ausgeführt...';

        // Update logs
        if (job.logs && job.logs.length > renderedLogsCount) {
          const newLogs = job.logs.slice(renderedLogsCount);
          newLogs.forEach(msg => appendLog(msg));
          renderedLogsCount = job.logs.length;
          document.getElementById('logCount').textContent = `${renderedLogsCount} Einträge`;
        }

        if (job.status === 'completed') {
          clearInterval(pollTimer);
          document.getElementById('progressBar').style.width = '100%';
          document.getElementById('percentBadge').textContent = '100%';
          resetSubmitButton();

          setTimeout(() => {
            hideElement(progressSection);
            showElement(resultsSection);
            currentResults = job.result;
            renderResults(job.result);
            resultsSection.scrollIntoView({ behavior: 'smooth' });
          }, 600);
        } else if (job.status === 'error') {
          clearInterval(pollTimer);
          resetSubmitButton();
          showError(job.error || 'Bei der Prüfung ist ein Fehler aufgetreten');
        }
      } catch (err) {
        clearInterval(pollTimer);
        resetSubmitButton();
        showError(err.message);
      }
    }, 600);
  }

  // Export CSV (Works on both Cloudflare and Python Server)
  exportCsvBtn.addEventListener('click', () => {
    if (!currentResults) return;

    // Generate CSV in browser
    let csvContent = '\ufeffFehlertyp / Kategorie,HTTP-Status,Details / Kontext,Defekte oder unsichere Ziel-URL,Gefunden auf Seite (Quell-URL)\r\n';
    
    (currentResults.broken_results || []).forEach(b => {
      const line = [
        `"Defekter ${b.category || 'Asset'}"`,
        `"${b.status || 'Fehler'}"`,
        `"${(b.text || '').replace(/"/g, '""')}"`,
        `"${(b.broken_url || '').replace(/"/g, '""')}"`,
        `"${(b.source || '').replace(/"/g, '""')}"`
      ].join(',');
      csvContent += line + '\r\n';
    });

    (currentResults.security_warnings || []).forEach(w => {
      const line = [
        `"Sicherheitswarnung (Mixed Content)"`,
        `"Unsicheres HTTP"`,
        `"${(w.issue || '').replace(/"/g, '""')}"`,
        `"${(w.url || '').replace(/"/g, '""')}"`,
        `"${(w.source || '').replace(/"/g, '""')}"`
      ].join(',');
      csvContent += line + '\r\n';
    });

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `qa_bericht_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  });

  // New Scan Button
  newScanBtn.addEventListener('click', () => {
    urlInput.focus();
    urlInput.select();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });

  // Filter Tabs
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeFilter = btn.dataset.filter;
      applyFiltersAndRenderTable();
    });
  });

  // Search input
  tableSearch.addEventListener('input', () => {
    applyFiltersAndRenderTable();
  });
});

// Helper: Append log line to terminal
function appendLog(text) {
  const terminal = document.getElementById('terminalLogs');
  const line = document.createElement('div');
  line.className = 'log-line';
  
  if (text.includes('Fehler') || text.includes('Error') || text.includes('404')) {
    line.style.color = '#f87171';
  } else if (text.includes('erfolgreich') || text.includes('abgeschlossen') || text.includes('Autorisiert') || text.includes('SUCCESS')) {
    line.style.color = '#4ade80';
  } else if (text.includes('Sitemap') || text.includes('Analysiere') || text.includes('Gefunden')) {
    line.style.color = '#38bdf8';
  }
  
  line.textContent = `> ${text}`;
  terminal.appendChild(line);
  terminal.scrollTop = terminal.scrollHeight;
}

// Render Results Dashboard
function renderResults(result) {
  if (!result) return;
  const summary = result.summary || {};

  document.getElementById('scanDurationText').textContent = 
    `Prüfung vor wenigen Sekunden abgeschlossen • Dauer: ${result.duration_seconds || 0} Sekunden (${result.target_url})`;

  document.getElementById('metricPages').textContent = summary.pages_scanned || 0;
  document.getElementById('metricAssets').textContent = `Insgesamt ${summary.total_assets_checked || 0} Assets & Links geprüft`;
  
  document.getElementById('metricBrokenLinks').textContent = summary.broken_links || 0;
  document.getElementById('metricBrokenImages').textContent = summary.broken_images || 0;
  document.getElementById('metricBrokenDocs').textContent = summary.broken_docs || 0;
  document.getElementById('metricSecurity').textContent = summary.security_warnings_count || 0;

  const brokenResults = result.broken_results || [];
  const securityWarnings = result.security_warnings || [];

  const linkCount = brokenResults.filter(b => b.category === 'EXTERN').length;
  const imgCount = brokenResults.filter(b => b.category === 'BILD').length;
  const docCount = brokenResults.filter(b => b.category === 'DOKUMENT').length;
  const secCount = securityWarnings.length;
  const totalCount = brokenResults.length + secCount;

  document.getElementById('countAll').textContent = totalCount;
  document.getElementById('countLinks').textContent = linkCount;
  document.getElementById('countImages').textContent = imgCount;
  document.getElementById('countDocs').textContent = docCount;
  document.getElementById('countSecurity').textContent = secCount;

  applyFiltersAndRenderTable();
}

function applyFiltersAndRenderTable() {
  if (!currentResults) return;
  const tbody = document.getElementById('issuesTableBody');
  const emptyState = document.getElementById('emptyState');
  const searchTerm = (document.getElementById('tableSearch').value || '').toLowerCase();

  tbody.innerHTML = '';

  const broken = currentResults.broken_results || [];
  const security = currentResults.security_warnings || [];

  let items = [];

  broken.forEach(b => {
    items.push({
      type: b.category,
      status: b.status,
      targetUrl: b.broken_url,
      sourceUrl: b.source,
      label: b.text || ''
    });
  });

  security.forEach(s => {
    items.push({
      type: 'SECURITY',
      status: 'HTTP Alert',
      targetUrl: s.url,
      sourceUrl: s.source,
      label: s.issue || 'Mixed Content'
    });
  });

  if (activeFilter !== 'all') {
    items = items.filter(item => item.type === activeFilter);
  }

  if (searchTerm) {
    items = items.filter(item => 
      (item.targetUrl && item.targetUrl.toLowerCase().includes(searchTerm)) ||
      (item.sourceUrl && item.sourceUrl.toLowerCase().includes(searchTerm)) ||
      (item.label && item.label.toLowerCase().includes(searchTerm)) ||
      (String(item.status).toLowerCase().includes(searchTerm))
    );
  }

  if (items.length === 0) {
    hideElement(tbody);
    showElement(emptyState);
    return;
  }

  hideElement(emptyState);
  showElement(tbody);

  items.forEach(item => {
    const tr = document.createElement('tr');

    let badgeHtml = '';
    if (item.type === 'EXTERN') {
      badgeHtml = `<span class="badge badge-link">🔗 Defekter Link</span>`;
    } else if (item.type === 'BILD') {
      badgeHtml = `<span class="badge badge-image">🖼️ Defektes Bild</span>`;
    } else if (item.type === 'DOKUMENT') {
      badgeHtml = `<span class="badge badge-doc">📄 Defektes Dokument</span>`;
    } else if (item.type === 'SECURITY') {
      badgeHtml = `<span class="badge badge-sec">🛡️ Sicherheitswarnung</span>`;
    }

    let statusClass = 'status-warn';
    if (item.status === 404) statusClass = 'status-404';
    else if (item.status >= 500) statusClass = 'status-500';

    const statusHtml = `<span class="status-tag ${statusClass}">${item.status}</span>`;

    tr.innerHTML = `
      <td>${badgeHtml}</td>
      <td>${statusHtml}</td>
      <td>
        <a href="${escapeHtml(item.targetUrl)}" target="_blank" rel="noopener noreferrer" class="url-link">
          ${escapeHtml(item.targetUrl)}
        </a>
        ${item.label ? `<div style="font-size: 11px; color: #94a3b8; margin-top: 3px;">Kontext: ${escapeHtml(item.label)}</div>` : ''}
      </td>
      <td>
        <a href="${escapeHtml(item.sourceUrl)}" target="_blank" rel="noopener noreferrer" class="source-link">
          ${escapeHtml(item.sourceUrl)}
        </a>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function setExampleUrl(url) {
  const input = document.getElementById('urlInput');
  input.value = url;
  input.focus();
}

function showElement(el) {
  if (el) el.classList.remove('hidden');
}

function hideElement(el) {
  if (el) el.classList.add('hidden');
}

function showError(msg) {
  const banner = document.getElementById('errorBanner');
  const msgEl = document.getElementById('errorMessage');
  msgEl.textContent = msg;
  showElement(banner);
}

function resetSubmitButton() {
  const btn = document.getElementById('submitBtn');
  btn.disabled = false;
  btn.querySelector('.btn-text').textContent = 'Prüfung jetzt starten';
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
