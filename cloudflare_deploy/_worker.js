// Cloudflare Pages Worker: _worker.js
// Advanced multi-page crawler & QA auditor for Cloudflare Edge

const DEFAULT_ALLOWED_DOMAIN = '@yourcompany.com';
const DOC_EXTENSIONS = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.zip', '.csv'];
const IGNORE_KEYWORDS = ['/wp-json/', '/feed/', 'replytocom=', '/page/', '#', 'javascript:', 'mailto:', 'tel:'];
const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36';

function getAllowedDomain(env) {
  return env?.ALLOWED_DOMAIN || DEFAULT_ALLOWED_DOMAIN;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 0. Configuration Endpoint
    if (url.pathname === '/api/config') {
      return new Response(JSON.stringify({
        allowed_domain: getAllowedDomain(env)
      }), {
        headers: { 'Content-Type': 'application/json; charset=utf-8' }
      });
    }

    // 1. Discover Sitemap Endpoint
    if (url.pathname === '/api/discover') {
      if (request.method !== 'POST') {
        return new Response(JSON.stringify({ error: 'Methode nicht erlaubt' }), { status: 405 });
      }
      return handleDiscover(request, env);
    }

    // 2. Scan Single Page Endpoint
    if (url.pathname === '/api/scan-page') {
      if (request.method !== 'POST') {
        return new Response(JSON.stringify({ error: 'Methode nicht erlaubt' }), { status: 405 });
      }
      return handleScanPage(request, env);
    }

    // 3. Fallback Batch Scan Endpoint
    if (url.pathname === '/api/scan') {
      if (request.method !== 'POST') {
        return new Response(JSON.stringify({ error: 'Methode nicht erlaubt' }), { status: 405 });
      }
      return handleScanBatch(request, env);
    }

    // 4. Status Check Endpoint
    if (url.pathname === '/api/status') {
      return new Response(JSON.stringify({
        status: 'completed',
        progress: 100,
        stage: 'Fertiggestellt',
        logs: ['[INFO] Scan abgeschlossen']
      }), {
        headers: { 'Content-Type': 'application/json; charset=utf-8' }
      });
    }

    // Default: Serve static assets (index.html, style.css, app.js, etc.)
    return env.ASSETS.fetch(request);
  }
};

/**
 * Discovers sitemap XML files and extracts page URLs
 */
async function handleDiscover(request, env) {
  let body = {};
  try { body = await request.json(); } catch {}
  const email = (body.email || '').trim().toLowerCase();
  const allowedDomain = getAllowedDomain(env);

  if (!email || !email.endsWith(allowedDomain)) {
    return new Response(JSON.stringify({
      error: `Zugriff verweigert: Nur autorisierte Mitarbeiter mit einer ${allowedDomain} E-Mail-Adresse sind zugelassen.`
    }), {
      status: 403,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  let url = (body.url || '').trim();
  if (!url) {
    return new Response(JSON.stringify({ error: 'Bitte eine Website-URL eingeben' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }

  const maxPages = Math.min(parseInt(body.max_pages) || 50, 300);

  try {
    const parsed = new URL(url);
    const baseUrl = `${parsed.protocol}//${parsed.host}`;
    const sitemapPaths = ['/wp-sitemap.xml', '/sitemap_index.xml', '/sitemap.xml'];
    const foundUrls = new Set();
    const visitedSitemaps = new Set();

    async function parseXml(xmlUrl) {
      if (visitedSitemaps.has(xmlUrl) || foundUrls.size >= maxPages) return;
      visitedSitemaps.add(xmlUrl);
      try {
        const res = await fetch(xmlUrl, {
          headers: { 'User-Agent': USER_AGENT },
          redirect: 'follow'
        });
        if (!res.ok) return;
        const text = await res.text();
        const locRegex = /<loc>\s*(https?:\/\/[^<\s]+)\s*<\/loc>/gi;
        let m;
        const childSitemaps = [];
        while ((m = locRegex.exec(text)) !== null) {
          const u = m[1].trim();
          if (u.endsWith('.xml')) {
            childSitemaps.push(u);
          } else {
            if (foundUrls.size < maxPages) {
              foundUrls.add(u);
            }
          }
        }
        for (const child of childSitemaps) {
          if (foundUrls.size >= maxPages) break;
          await parseXml(child);
        }
      } catch {}
    }

    for (const p of sitemapPaths) {
      const smUrl = new URL(p, baseUrl).href;
      await parseXml(smUrl);
      if (foundUrls.size > 0) break;
    }

    const pages = Array.from(foundUrls).slice(0, maxPages);
    return new Response(JSON.stringify({
      sitemap_found: pages.length > 0,
      pages: pages.length > 0 ? pages : [url],
      count: pages.length
    }), {
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  } catch (err) {
    return new Response(JSON.stringify({
      sitemap_found: false,
      pages: [url],
      error: err.message
    }), {
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }
}

/**
 * Scans a single page, parses links/images, and checks assets
 */
async function handleScanPage(request, env) {
  let body = {};
  try { body = await request.json(); } catch {}
  const email = (body.email || '').trim().toLowerCase();
  const allowedDomain = getAllowedDomain(env);

  if (!email || !email.endsWith(allowedDomain)) {
    return new Response(JSON.stringify({
      error: `Zugriff verweigert: Nur autorisierte Mitarbeiter mit einer ${allowedDomain} E-Mail-Adresse sind zugelassen.`
    }), {
      status: 403,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  let pageUrl = (body.page_url || '').trim();
  let rootUrl = (body.root_url || pageUrl).trim();
  if (!pageUrl) {
    return new Response(JSON.stringify({ error: 'URL erforderlich' }), { status: 400 });
  }

  try {
    const parsedStart = new URL(rootUrl);
    const baseDomain = parsedStart.hostname.replace(/^www\./, '');
    const isHttps = rootUrl.startsWith('https:');

    let pageResp;
    try {
      pageResp = await fetch(pageUrl, {
        headers: { 'User-Agent': USER_AGENT },
        redirect: 'follow'
      });
    } catch (err) {
      return new Response(JSON.stringify({
        page_url: pageUrl,
        fetch_error: err.message,
        internal_links: [],
        broken_results: [{
          source: pageUrl,
          broken_url: pageUrl,
          status: 'Verbindungsfehler',
          category: 'SEITE',
          text: '[Seite nicht erreichbar]'
        }],
        security_warnings: [],
        documents: [],
        assets_checked_count: 0,
        extern_count: 0,
        images_count: 0,
        docs_count: 0
      }), {
        headers: { 'Content-Type': 'application/json; charset=utf-8' }
      });
    }

    if (!pageResp.ok) {
      return new Response(JSON.stringify({
        page_url: pageUrl,
        fetch_error: `HTTP ${pageResp.status}`,
        internal_links: [],
        broken_results: [{
          source: pageUrl,
          broken_url: pageUrl,
          status: pageResp.status,
          category: 'SEITE',
          text: `[HTTP ${pageResp.status}]`
        }],
        security_warnings: [],
        documents: [],
        assets_checked_count: 0,
        extern_count: 0,
        images_count: 0,
        docs_count: 0
      }), {
        headers: { 'Content-Type': 'application/json; charset=utf-8' }
      });
    }

    const contentType = pageResp.headers.get('content-type') || '';
    if (!contentType.includes('text/html')) {
      return new Response(JSON.stringify({
        page_url: pageUrl,
        internal_links: [],
        broken_results: [],
        security_warnings: [],
        documents: [],
        assets_checked_count: 0,
        extern_count: 0,
        images_count: 0,
        docs_count: 0
      }), {
        headers: { 'Content-Type': 'application/json; charset=utf-8' }
      });
    }

    const html = await pageResp.text();
    const assetsToCheck = new Map();
    const securityWarnings = [];
    const brokenResults = [];
    const internalLinks = new Set();
    const documentsFound = [];

    // 1. Links <a href="...">
    const linkRegex = /<a\s+[^>]*?href=["']([^"']+)["'][^>]*?>([\s\S]*?)<\/a>/gi;
    let match;
    while ((match = linkRegex.exec(html)) !== null) {
      let href = match[1].trim();
      let text = match[2].replace(/<[^>]+>/g, '').trim() || '[Link]';

      if (!href || href.startsWith('#') || href.startsWith('javascript:') || href.startsWith('mailto:') || href.startsWith('tel:')) {
        continue;
      }

      try {
        const fullUrl = new URL(href, pageUrl).href.split('#')[0];
        if (IGNORE_KEYWORDS.some(k => fullUrl.includes(k))) continue;

        const targetHost = new URL(fullUrl).hostname.replace(/^www\./, '');
        const isInternal = targetHost.includes(baseDomain);

        if (isHttps && fullUrl.startsWith('http:') && isInternal) {
          securityWarnings.push({
            source: pageUrl,
            url: fullUrl,
            issue: 'Mixed Content: Interner HTTP-Link auf HTTPS-Website'
          });
        }

        const isDoc = DOC_EXTENSIONS.some(ext => fullUrl.toLowerCase().split('?')[0].endsWith(ext));
        if (isDoc) {
          if (!assetsToCheck.has(fullUrl)) assetsToCheck.set(fullUrl, { source: pageUrl, cat: 'DOKUMENT', label: text.slice(0, 40) });
          documentsFound.push({ source: pageUrl, url: fullUrl, label: text.slice(0, 40) });
        } else if (!isInternal) {
          if (!assetsToCheck.has(fullUrl)) assetsToCheck.set(fullUrl, { source: pageUrl, cat: 'EXTERN', label: text.slice(0, 40) });
        } else {
          internalLinks.add(fullUrl);
        }
      } catch {}
    }

    // 2. Images <img src="...">
    const imgRegex = /<img\s+[^>]*?src=["']([^"']+)["']/gi;
    while ((match = imgRegex.exec(html)) !== null) {
      let src = match[1].trim();
      if (!src || src.startsWith('data:')) continue;

      try {
        const fullImg = new URL(src, pageUrl).href;
        const imgHost = new URL(fullImg).hostname.replace(/^www\./, '');

        if (isHttps && fullImg.startsWith('http:') && imgHost.includes(baseDomain)) {
          securityWarnings.push({
            source: pageUrl,
            url: fullImg,
            issue: 'Unsicheres Bild: Bild wird über HTTP geladen'
          });
        }

        if (!assetsToCheck.has(fullImg)) {
          assetsToCheck.set(fullImg, { source: pageUrl, cat: 'BILD', label: '[BILD]' });
        }
      } catch {}
    }

    // Limit assets to check per page (max 20 to maintain high speed and prevent subrequest quota exhaustion)
    const items = Array.from(assetsToCheck.entries()).slice(0, 20);

    // 3. Concurrently check assets
    await Promise.all(items.map(async ([assetUrl, info]) => {
      try {
        let res = await fetch(assetUrl, {
          method: 'HEAD',
          headers: { 'User-Agent': USER_AGENT },
          redirect: 'follow'
        });

        if (res.status === 403 || res.status === 405) {
          res = await fetch(assetUrl, {
            method: 'GET',
            headers: { 'User-Agent': USER_AGENT },
            redirect: 'follow'
          });
        }

        if (res.status >= 400) {
          brokenResults.push({
            source: info.source,
            broken_url: assetUrl,
            status: res.status,
            category: info.cat,
            text: info.label
          });
        }
      } catch (err) {
        brokenResults.push({
          source: info.source,
          broken_url: assetUrl,
          status: 'Timeout/Fehler',
          category: info.cat,
          text: info.label
        });
      }
    }));

    return new Response(JSON.stringify({
      page_url: pageUrl,
      internal_links: Array.from(internalLinks),
      broken_results: brokenResults,
      security_warnings: securityWarnings,
      documents: documentsFound,
      assets_checked_count: items.length,
      extern_count: items.filter(([, v]) => v.cat === 'EXTERN').length,
      images_count: items.filter(([, v]) => v.cat === 'BILD').length,
      docs_count: items.filter(([, v]) => v.cat === 'DOKUMENT').length
    }), {
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });

  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }
}

/**
 * Fallback batch scan for direct API consumers (scans sitemap or first 5 pages)
 */
async function handleScanBatch(request, env) {
  const startTime = Date.now();
  let body = {};
  try { body = await request.json(); } catch {}
  const email = (body.email || '').trim().toLowerCase();
  const allowedDomain = getAllowedDomain(env);

  if (!email || !email.endsWith(allowedDomain)) {
    return new Response(JSON.stringify({
      error: `Zugriff verweigert: Nur autorisierte Mitarbeiter mit einer ${allowedDomain} E-Mail-Adresse sind zugelassen.`
    }), {
      status: 403,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  let url = (body.url || '').trim();
  if (!url) {
    return new Response(JSON.stringify({ error: 'Bitte eine gültige Website-URL eingeben' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }

  // Discover sitemap or start with url
  const parsed = new URL(url);
  const baseUrl = `${parsed.protocol}//${parsed.host}`;
  const sitemapPaths = ['/wp-sitemap.xml', '/sitemap.xml'];
  const pagesToScan = [url];

  for (const sp of sitemapPaths) {
    try {
      const res = await fetch(new URL(sp, baseUrl).href, { headers: { 'User-Agent': USER_AGENT } });
      if (res.ok) {
        const txt = await res.text();
        const locs = txt.match(/<loc>\s*(https?:\/\/[^<\s]+)\s*<\/loc>/gi);
        if (locs) {
          for (const loc of locs) {
            const cleanUrl = loc.replace(/<\/?loc>/gi, '').trim();
            if (!cleanUrl.endsWith('.xml') && !pagesToScan.includes(cleanUrl)) {
              pagesToScan.push(cleanUrl);
            }
            if (pagesToScan.length >= 5) break;
          }
        }
      }
    } catch {}
    if (pagesToScan.length > 1) break;
  }

  // Scan up to 5 pages
  const targetPages = pagesToScan.slice(0, 5);
  const allBroken = [];
  const allSec = [];
  const allDocs = [];
  let totalChecked = 0;

  for (const p of targetPages) {
    try {
      const pResp = await fetch(p, { headers: { 'User-Agent': USER_AGENT } });
      if (!pResp.ok) continue;
      const html = await pResp.text();

      // extract broken links
      const lRegex = /<a\s+[^>]*?href=["']([^"']+)["'][^>]*?>([\s\S]*?)<\/a>/gi;
      let m;
      const toCheck = [];
      while ((m = lRegex.exec(html)) !== null && toCheck.length < 8) {
        const h = m[1].trim();
        if (h.startsWith('http')) toCheck.push(h);
      }

      await Promise.all(toCheck.map(async (linkUrl) => {
        try {
          totalChecked++;
          const checkRes = await fetch(linkUrl, { method: 'HEAD', headers: { 'User-Agent': USER_AGENT } });
          if (checkRes.status >= 400) {
            allBroken.push({ source: p, broken_url: linkUrl, status: checkRes.status, category: 'EXTERN', text: '[Link]' });
          }
        } catch {
          allBroken.push({ source: p, broken_url: linkUrl, status: 'Fehler', category: 'EXTERN', text: '[Link]' });
        }
      }));
    } catch {}
  }

  const elapsed = Math.round((Date.now() - startTime) / 100) / 10;
  return new Response(JSON.stringify({
    job_id: 'cf_' + Math.random().toString(36).slice(2, 8),
    status: 'completed',
    result: {
      target_url: url,
      duration_seconds: elapsed,
      summary: {
        pages_scanned: targetPages.length,
        total_assets_checked: totalChecked,
        external_links_count: totalChecked,
        images_count: 0,
        documents_count: 0,
        total_broken: allBroken.length,
        broken_links: allBroken.length,
        broken_images: 0,
        broken_docs: 0,
        security_warnings_count: allSec.length
      },
      pages: targetPages,
      broken_results: allBroken,
      security_warnings: allSec,
      documents: allDocs
    },
    message: 'Prüfung abgeschlossen'
  }), {
    headers: { 'Content-Type': 'application/json; charset=utf-8' }
  });
}
