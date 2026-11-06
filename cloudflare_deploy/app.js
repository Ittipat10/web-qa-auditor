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

  // Scanner Form Elements
  const scanForm = document.getElementById('scanForm');
  const urlInput = document.getElementById('urlInput');
  const maxPagesSelect = document.getElementById('maxPagesSelect');
  const submitBtn = document.getElementById('submitBtn');

  const progressSection = document.getElementById('progressSection');
  const resultsSection = document.getElementById('resultsSection');
  const errorBanner = document.getElementById('errorBanner');

  const exportCsvBtn = document.getElementById('exportCsvBtn');
  const newScanBtn = document.getElementById('newScanBtn');
  const tableSearch = document.getElementById('tableSearch');

  let authorizedEmail = (localStorage.getItem('capi_authorized_email') || '').trim().toLowerCase();

  function updateAuthDomainUI() {
    const domainNotice = document.getElementById('authDomainNotice');
    if (domainNotice) domainNotice.textContent = allowedDomain;
    if (authEmailInput) authEmailInput.placeholder = `vorname.nachname${allowedDomain}`;
  }

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

  // Load dynamic domain config BEFORE validating saved session to avoid premature logout
  (async function initAuth() {
    try {
      const r = await fetch('/api/config');
      if (r.ok) {
        const cfg = await r.json();
        if (cfg.allowed_domain) {
          allowedDomain = cfg.allowed_domain.trim().toLowerCase();
        }
      }
    } catch {}
    updateAuthDomainUI();
    if (authorizedEmail && authorizedEmail.endsWith(allowedDomain)) {
      unlockUI(authorizedEmail);
    } else {
      lockUI();
    }
  })();

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

  // Form Submission for Scanning
  scanForm.addEventListener('submit', async (e) => {
    e.preventDefault();

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
    document.getElementById('logCount').textContent = '0 Einträge';

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

      // Fallback to Python server job mode if /api/discover is not present
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

      // Phase 1: Crawl HTML Pages & Collect Unique Links/Assets
      const queue = [...pagesToCrawl];
      const queuedSet = new Set(pagesToCrawl);
      const visited = new Set();

      // Track where each internal link was first seen so broken internal pages show exact referring URL
      const linkSourceMap = new Map();
      pagesToCrawl.forEach((p, idx) => {
        linkSourceMap.set(p, {
          source: idx === 0 ? url : `${url} (XML-Sitemap)`,
          label: idx === 0 ? '[Startseite]' : '[Sitemap-Eintrag]'
        });
      });

      // Deduplicated global maps
      const uniqueAssetsMap = new Map(); // assetUrl -> { url, category, label, sources: Set }
      const discoveredInternalMap = new Map(); // internalUrl -> { url, label, sources: Set }
      const securityWarningsMap = new Map();
      const documentsMap = new Map();
      const allBrokenResults = [];
      const brokenDedupeSet = new Set();

      function recordBroken(entry) {
        const key = `${entry.source}||${entry.broken_url}`;
        if (!brokenDedupeSet.has(key)) {
          brokenDedupeSet.add(key);
          allBrokenResults.push(entry);
        }
      }

      while (queue.length > 0 && visited.size < maxPages) {
        const currentPage = queue.shift();
        if (visited.has(currentPage)) continue;
        visited.add(currentPage);

        const pageNum = visited.size;
        const totalTarget = Math.min(queue.length + visited.size, maxPages);
        const progressPct = Math.min(58, Math.round(8 + (pageNum / Math.max(1, totalTarget)) * 50));

        document.getElementById('progressBar').style.width = `${progressPct}%`;
        document.getElementById('percentBadge').textContent = `${progressPct}%`;
        document.getElementById('stageTitle').textContent = `Seitenstruktur analysieren (${pageNum}/${totalTarget})`;
        appendLog(`[SEITE ${pageNum}/${totalTarget}] Analysiere HTML: ${currentPage}`);

        const refInfo = linkSourceMap.get(currentPage) || { source: url, label: '[Interner Link]' };

        try {
          const pageRes = await fetch('/api/scan-page', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              page_url: currentPage,
              root_url: url,
              source_url: refInfo.source,
              link_label: refInfo.label,
              email: authorizedEmail
            })
          });

          if (pageRes.status === 403) {
            lockUI();
            throw new Error(`Zugriff verweigert: Nur Mitarbeiter mit ${allowedDomain} sind autorisiert.`);
          }

          if (pageRes.ok) {
            const pageData = await pageRes.json();

            // Record if the crawled page itself returned 404 / 500 / dead domain
            if (Array.isArray(pageData.broken_results)) {
              for (const b of pageData.broken_results) {
                recordBroken(b);
                appendLog(`[FEHLER] ❌ Defekte Seite (${b.status}): ${b.broken_url}`);
              }
            }

            // Process internal links discovered on this page
            const linkDetails = Array.isArray(pageData.internal_link_details)
              ? pageData.internal_link_details
              : (pageData.internal_links || []).map(u => ({ url: u, label: '[Interner Link]' }));

            for (const detail of linkDetails) {
              const linkUrl = detail.url;
              const linkLbl = detail.label || '[Interner Link]';
              if (!linkSourceMap.has(linkUrl)) {
                linkSourceMap.set(linkUrl, { source: currentPage, label: linkLbl });
              }

              if (!discoveredInternalMap.has(linkUrl)) {
                discoveredInternalMap.set(linkUrl, { url: linkUrl, label: linkLbl, sources: new Set([currentPage]) });
              } else {
                discoveredInternalMap.get(linkUrl).sources.add(currentPage);
              }

              const isPagination = linkUrl.toLowerCase().includes('/page/');
              if (!isPagination && !visited.has(linkUrl) && !queuedSet.has(linkUrl) && queuedSet.size < maxPages * 3) {
                queuedSet.add(linkUrl);
                queue.push(linkUrl);
              }
            }

            // Collect external links, images, and documents into deduplicated map
            if (Array.isArray(pageData.assets)) {
              for (const asset of pageData.assets) {
                if (!uniqueAssetsMap.has(asset.url)) {
                  uniqueAssetsMap.set(asset.url, {
                    url: asset.url,
                    category: asset.category,
                    label: asset.label || '',
                    sources: new Set([currentPage])
                  });
                } else {
                  uniqueAssetsMap.get(asset.url).sources.add(currentPage);
                }
              }
            }

            // Backward compatibility if backend already verified assets inline
            if (!Array.isArray(pageData.assets) && pageData.assets_checked_count) {
              // Handled via broken_results above
            }

            if (Array.isArray(pageData.security_warnings)) {
              for (const w of pageData.security_warnings) {
                const wKey = `${w.source}||${w.url}`;
                if (!securityWarningsMap.has(wKey)) {
                  securityWarningsMap.set(wKey, w);
                }
              }
            }

            if (Array.isArray(pageData.documents)) {
              for (const d of pageData.documents) {
                if (!documentsMap.has(d.url)) {
                  documentsMap.set(d.url, d);
                }
              }
            }
          }
        } catch (pageErr) {
          appendLog(`[WARNUNG] Netzwerkproblem bei ${currentPage}: ${pageErr.message}`);
        }
      }

      // Remove already-crawled internal pages from asset map, and include up to 250 unvisited internal links for 404 validation
      for (const vUrl of visited) {
        uniqueAssetsMap.delete(vUrl);
      }

      let addedUnvisitedInternal = 0;
      for (const [intUrl, intInfo] of discoveredInternalMap.entries()) {
        if (!visited.has(intUrl) && !uniqueAssetsMap.has(intUrl) && addedUnvisitedInternal < 250) {
          uniqueAssetsMap.set(intUrl, {
            url: intUrl,
            category: 'INTERN',
            label: intInfo.label,
            sources: intInfo.sources
          });
          addedUnvisitedInternal++;
        }
      }

      // Phase 2: Deduplicated Batch Asset & Link Verification
      const itemsToVerify = Array.from(uniqueAssetsMap.values());
      const totalUnique = itemsToVerify.length;

      if (totalUnique > 0) {
        appendLog(`[PRÜFUNG] Validiere ${totalUnique} eindeutige Links, Bilder & Dokumente (ohne Login-Wall-Fehlalarme)...`);
      }

      const BATCH_SIZE = 10;
      const batches = [];
      for (let i = 0; i < totalUnique; i += BATCH_SIZE) {
        batches.push(itemsToVerify.slice(i, i + BATCH_SIZE));
      }

      let verifiedCount = 0;
      const CONCURRENCY = 2;

      for (let i = 0; i < batches.length; i += CONCURRENCY) {
        const currentSlice = batches.slice(i, i + CONCURRENCY);
        await Promise.all(currentSlice.map(async (batch) => {
          try {
            const verifyRes = await fetch('/api/verify-batch', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                root_url: url,
                email: authorizedEmail,
                items: batch.map(it => ({
                  url: it.url,
                  category: it.category,
                  source: Array.from(it.sources)[0] || url
                }))
              })
            });

            if (verifyRes.ok) {
              const verifyData = await verifyRes.json();
              for (const r of (verifyData.results || [])) {
                if (r.broken) {
                  const meta = uniqueAssetsMap.get(r.url);
                  if (!meta) continue;
                  const sourcesList = Array.from(meta.sources);
                  appendLog(`[FEHLER] ❌ Defekt (${r.status}): ${r.url}`);

                  if (sourcesList.length <= 3) {
                    for (const srcPage of sourcesList) {
                      recordBroken({
                        source: srcPage,
                        broken_url: r.url,
                        status: r.status,
                        category: meta.category,
                        text: meta.label
                      });
                    }
                  } else {
                    recordBroken({
                      source: sourcesList[0],
                      broken_url: r.url,
                      status: r.status,
                      category: meta.category,
                      text: `${meta.label} (auf ${sourcesList.length} Seiten gefunden)`
                    });
                  }
                }
              }
            }
          } catch (batchErr) {
            appendLog(`[WARNUNG] Teilprüfung übersprungen: ${batchErr.message}`);
          } finally {
            verifiedCount += batch.length;
            const pct = Math.min(98, Math.round(60 + (verifiedCount / Math.max(1, totalUnique)) * 38));
            document.getElementById('progressBar').style.width = `${pct}%`;
            document.getElementById('percentBadge').textContent = `${pct}%`;
            document.getElementById('stageTitle').textContent = `Links, Bilder & Dokumente prüfen (${verifiedCount}/${totalUnique})`;
          }
        }));
      }

      // Step 3: Complete & Render Results
      const allSecurityWarnings = Array.from(securityWarningsMap.values());
      const allDocuments = Array.from(documentsMap.values());
      const totalExternCount = itemsToVerify.filter(a => a.category === 'EXTERN').length;
      const totalImagesCount = itemsToVerify.filter(a => a.category === 'BILD').length;
      const totalDocsCount = itemsToVerify.filter(a => a.category === 'DOKUMENT').length;

      const elapsed = Math.round((Date.now() - startTime) / 100) / 10;
      document.getElementById('progressBar').style.width = '100%';
      document.getElementById('percentBadge').textContent = '100%';
      document.getElementById('stageTitle').textContent = 'Abgeschlossen';
      appendLog(`[SUCCESS] ✅ Prüfung erfolgreich abgeschlossen in ${elapsed}s!`);
      appendLog(`[SUMMARY] ${visited.size} Seiten analysiert, ${totalUnique} eindeutige Elemente geprüft, ${allBrokenResults.length} echte Defekte gefunden`);
      resetSubmitButton();

      const finalResult = {
        target_url: url,
        duration_seconds: elapsed,
        summary: {
          pages_scanned: visited.size,
          total_assets_checked: totalUnique,
          external_links_count: totalExternCount,
          images_count: totalImagesCount,
          documents_count: totalDocsCount,
          total_broken: allBrokenResults.length,
          broken_links: allBrokenResults.filter(b => b.category === 'EXTERN' || b.category === 'INTERN').length,
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
      }, 450);

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

  // Polling Status (Python Local/NAS Mode)
  function startPolling(jobId) {
    if (pollTimer) clearInterval(pollTimer);

    pollTimer = setInterval(async () => {
      try {
        const res = await fetch(`/api/status?job_id=${jobId}`);
        if (!res.ok) throw new Error('Statusdaten konnten nicht abgerufen werden');
        const job = await res.json();

        const pct = job.progress || 0;
        document.getElementById('progressBar').style.width = `${pct}%`;
        document.getElementById('percentBadge').textContent = `${pct}%`;
        document.getElementById('stageTitle').textContent = job.stage || 'Wird ausgeführt...';

        if (job.logs && job.logs.length > renderedLogsCount) {
          const newLogs = job.logs.slice(renderedLogsCount);
          newLogs.forEach(msg => appendLog(msg));
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

    const categoryLabels = {
      INTERN: 'Defekter Interner Link',
      EXTERN: 'Defekter Externer Link',
      BILD: 'Defektes Bild',
      DOKUMENT: 'Defektes Dokument'
    };

    let csvContent = '\ufeffFehlertyp / Kategorie,HTTP-Status,Details / Kontext,Defekte oder unsichere Ziel-URL,Gefunden auf Seite (Quell-URL)\r\n';

    (currentResults.broken_results || []).forEach(b => {
      const catText = categoryLabels[b.category] || `Defekter ${b.category || 'Asset'}`;
      const line = [
        `"${catText}"`,
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

  if (text.includes('FEHLER') || text.includes('Fehler') || text.includes('Error') || text.includes('❌')) {
    line.style.color = '#f87171';
  } else if (text.includes('erfolgreich') || text.includes('abgeschlossen') || text.includes('Autorisiert') || text.includes('SUCCESS')) {
    line.style.color = '#4ade80';
  } else if (text.includes('Sitemap') || text.includes('Analysiere') || text.includes('PRÜFUNG')) {
    line.style.color = '#38bdf8';
  }

  line.textContent = `> ${text}`;
  terminal.appendChild(line);
  terminal.scrollTop = terminal.scrollHeight;

  renderedLogsCount++;
  const logCountEl = document.getElementById('logCount');
  if (logCountEl) {
    logCountEl.textContent = `${renderedLogsCount} Einträge`;
  }
}

// Render Results Dashboard
function renderResults(result) {
  if (!result) return;
  const summary = result.summary || {};

  document.getElementById('scanDurationText').textContent =
    `Prüfung vor wenigen Sekunden abgeschlossen • Dauer: ${result.duration_seconds || 0} Sekunden (${result.target_url})`;

  document.getElementById('metricPages').textContent = summary.pages_scanned || 0;
  document.getElementById('metricAssets').textContent = `Insgesamt ${summary.total_assets_checked || 0} eindeutige Links & Assets geprüft`;

  document.getElementById('metricBrokenLinks').textContent = summary.broken_links || 0;
  document.getElementById('metricBrokenImages').textContent = summary.broken_images || 0;
  document.getElementById('metricBrokenDocs').textContent = summary.broken_docs || 0;
  document.getElementById('metricSecurity').textContent = summary.security_warnings_count || 0;

  const brokenResults = result.broken_results || [];
  const securityWarnings = result.security_warnings || [];

  const linkCount = brokenResults.filter(b => b.category === 'EXTERN' || b.category === 'INTERN').length;
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
    if (activeFilter === 'EXTERN') {
      items = items.filter(item => item.type === 'EXTERN' || item.type === 'INTERN');
    } else {
      items = items.filter(item => item.type === activeFilter);
    }
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
    if (item.type === 'INTERN') {
      badgeHtml = `<span class="badge badge-link">🔗 Interner Link</span>`;
    } else if (item.type === 'EXTERN') {
      badgeHtml = `<span class="badge badge-link">🔗 Externer Link</span>`;
    } else if (item.type === 'BILD') {
      badgeHtml = `<span class="badge badge-image">🖼️ Defektes Bild</span>`;
    } else if (item.type === 'DOKUMENT') {
      badgeHtml = `<span class="badge badge-doc">📄 Defektes Dokument</span>`;
    } else if (item.type === 'SECURITY') {
      badgeHtml = `<span class="badge badge-sec">🛡️ Sicherheitswarnung</span>`;
    }

    const statusStr = String(item.status);
    let statusClass = 'status-warn';
    if (item.status === 404 || item.status === 410 || statusStr.includes('404') || statusStr.includes('existiert nicht')) {
      statusClass = 'status-404';
    } else if (Number(item.status) >= 500) {
      statusClass = 'status-500';
    }

    const statusHtml = `<span class="status-tag ${statusClass}">${escapeHtml(statusStr)}</span>`;

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
