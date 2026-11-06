// Cloudflare Pages Worker: _worker.js
// High-precision multi-page QA crawler & broken-asset verifier for Cloudflare Edge

const DEFAULT_ALLOWED_DOMAIN = '@yourcompany.com';

const DOC_EXTENSIONS = [
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.zip', '.rar', '.7z', '.csv', '.mp4', '.webm', '.mov', '.mp3', '.wav'
];

const IMG_EXTENSIONS = [
  '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.avif', '.bmp', '.ico'
];

const SKIP_URL_PATTERNS = [
  '/wp-json/', '/xmlrpc.php', '/wp-login.php', '/wp-admin/',
  '/feed/', 'replytocom=', '/cdn-cgi/l/email-protection'
];

const TRACKING_PIXEL_DOMAINS = [
  'facebook.com/tr', 'connect.facebook.net', 'google-analytics.com',
  'googletagmanager.com', 'doubleclick.net', 'bat.bing.com',
  'px.ads.linkedin.com', 'analytics.tiktok.com'
];

// Platforms that require login or return anti-bot HTTP 400/401/403/429/999 to server IPs
const SOCIAL_AND_AUTH_DOMAINS = [
  'linkedin.com', 'lnkd.in',
  'facebook.com', 'fb.com', 'fb.me', 'messenger.com',
  'instagram.com', 'threads.net',
  'twitter.com', 'x.com', 't.co',
  'xing.com',
  'tiktok.com',
  'pinterest.com', 'pinterest.de',
  'reddit.com',
  'whatsapp.com', 'wa.me', 't.me',
  'kununu.com', 'glassdoor.com', 'glassdoor.de', 'stepstone.de', 'indeed.com',
  'youtube.com', 'youtu.be',
  'login.microsoftonline.com', 'forms.office.com', 'forms.cloud.microsoft',
  'accounts.google.com', 'appleid.apple.com'
];

// HTTP status codes that mean "Alive, but Login-Required / Bot-Protected / Rate-Limited" (NOT broken)
const PROTECTED_ALIVE_STATUSES = new Set([401, 403, 405, 406, 407, 429, 999]);

// HTTP status codes that confirm a genuinely dead/missing/crashed target (530 = Cloudflare Origin DNS / NXDOMAIN error)
const TRULY_BROKEN_STATUSES = new Set([404, 410, 500, 502, 504, 520, 521, 522, 523, 530]);

const BROWSER_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
  'Accept-Language': 'de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7',
  'Cache-Control': 'no-cache'
};

function getAllowedDomain(env) {
  return (env?.ALLOWED_DOMAIN || DEFAULT_ALLOWED_DOMAIN).trim().toLowerCase();
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' }
  });
}

function decodeHtmlEntities(str) {
  if (!str) return '';
  return str
    .replace(/&amp;/gi, '&')
    .replace(/&#0*38;/g, '&')
    .replace(/&#x0*26;/gi, '&')
    .replace(/&quot;/gi, '"')
    .replace(/&#0*39;/g, "'")
    .trim();
}

function stripNonVisibleHtml(html) {
  return html
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<template\b[^>]*>[\s\S]*?<\/template>/gi, ' ')
    .replace(/<noscript\b[^>]*>[\s\S]*?<\/noscript>/gi, ' ');
}

function extractAttr(tagAttrs, attrName) {
  const re = new RegExp(`(?:^|\\s)${attrName}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i');
  const m = re.exec(tagAttrs);
  if (!m) return '';
  return decodeHtmlEntities(m[1] ?? m[2] ?? m[3] ?? '');
}

function isNonHttpScheme(raw) {
  const lower = raw.trim().toLowerCase();
  return (
    !lower ||
    lower.startsWith('#') ||
    lower.startsWith('javascript:') ||
    lower.startsWith('mailto:') ||
    lower.startsWith('tel:') ||
    lower.startsWith('sms:') ||
    lower.startsWith('fax:') ||
    lower.startsWith('callto:') ||
    lower.startsWith('whatsapp:') ||
    lower.startsWith('skype:') ||
    lower.startsWith('geo:') ||
    lower.startsWith('maps:') ||
    lower.startsWith('webcal:') ||
    lower.startsWith('data:') ||
    lower.startsWith('blob:') ||
    lower.startsWith('about:') ||
    lower === '//:0'
  );
}

function isSameSiteHost(hostname, baseDomain) {
  const clean = hostname.toLowerCase().replace(/^www\./, '');
  return clean === baseDomain || clean.endsWith('.' + baseDomain);
}

function isSocialOrAuthHost(hostname) {
  const clean = hostname.toLowerCase().replace(/^www\./, '');
  return SOCIAL_AND_AUTH_DOMAINS.some(d => clean === d || clean.endsWith('.' + d));
}

function isWafChallengeResponse(res) {
  if (res.headers.get('cf-mitigated')) return true;
  if (res.status === 503) {
    const server = (res.headers.get('server') || '').toLowerCase();
    if (server.includes('cloudflare') || server.includes('ddos-guard') || server.includes('akamai')) {
      return true;
    }
  }
  return false;
}

async function fetchWithTimeout(targetUrl, options = {}, timeoutMs = 7000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(targetUrl, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Checks via Cloudflare DoH whether a hostname actually exists in DNS.
 * Returns true if the domain has valid A, AAAA, or CNAME records; false if NXDOMAIN / dead.
 */
async function checkDomainExistsInDns(hostname) {
  try {
    for (const qtype of ['A', 'AAAA']) {
      const dohUrl = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=${qtype}`;
      const res = await fetchWithTimeout(dohUrl, {
        headers: { 'Accept': 'application/dns-json' }
      }, 3000);
      if (!res.ok) return true; // Assume alive if DoH itself errors
      const data = await res.json();
      if (data.Status === 3) {
        return false; // NXDOMAIN: Domain definitely does not exist
      }
      if (Array.isArray(data.Answer) && data.Answer.length > 0) {
        return true;
      }
    }
    return false;
  } catch {
    return true; // Conservative fallback: do not false-positive on DoH hiccup
  }
}

/**
 * High-precision verification of a single URL (link, image, or document).
 * Eliminates false positives from login walls (LinkedIn, etc.), WAFs (403), and HEAD rejections.
 */
async function verifySingleUrl(targetUrl, category, sourceUrl, baseDomain) {
  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return { broken: true, status: 'Ungültige URL' };
  }

  const isInternal = isSameSiteHost(parsed.hostname, baseDomain);
  const reqHeaders = { ...BROWSER_HEADERS };
  if (sourceUrl) {
    reqHeaders['Referer'] = sourceUrl;
  }

  let res = null;
  let networkError = null;

  // Step 1: Fast HEAD check
  try {
    res = await fetchWithTimeout(targetUrl, {
      method: 'HEAD',
      headers: reqHeaders,
      redirect: 'follow'
    }, 6000);
    await res.body?.cancel();
  } catch (err) {
    networkError = err;
  }

  // Step 2: If HEAD failed or returned >= 400 (except rate-limit 429 / LinkedIn 999), confirm with GET
  if (!res || (res.status >= 400 && res.status !== 429 && res.status !== 999)) {
    try {
      const getHeaders = { ...reqHeaders };
      if (category === 'BILD' || category === 'DOKUMENT') {
        getHeaders['Range'] = 'bytes=0-2047';
      }
      res = await fetchWithTimeout(targetUrl, {
        method: 'GET',
        headers: getHeaders,
        redirect: 'follow'
      }, 7500);
      await res.body?.cancel();
      networkError = null;
    } catch (err) {
      networkError = err;
    }
  }

  // Step 3: Evaluate response if received
  if (res) {
    const status = res.status;

    // 2xx / 3xx (including 206 Partial Content from Range header)
    if (status >= 200 && status < 400) {
      // Soft-404 check strictly for internal image files returning HTML instead of an image
      if (category === 'BILD' && isInternal && status === 200) {
        const ct = (res.headers.get('content-type') || '').toLowerCase();
        const pathLower = parsed.pathname.toLowerCase();
        if (ct.startsWith('text/html') && /\.(jpe?g|png|gif|webp|avif|bmp)$/i.test(pathLower) && !isWafChallengeResponse(res)) {
          return { broken: true, status: '404 (Kein Bild)' };
        }
      }
      return { broken: false, status };
    }

    // Protected / Login-Wall / WAF / Rate-Limit -> Alive, NOT broken!
    if (PROTECTED_ALIVE_STATUSES.has(status)) {
      return { broken: false, status };
    }

    // Social & Login platforms returning 400 Bad Request to non-JS clients (e.g. Facebook/Meta, X)
    let finalHost = parsed.hostname;
    try {
      if (res.url) finalHost = new URL(res.url).hostname;
    } catch {}
    if (status === 400 && (isSocialOrAuthHost(parsed.hostname) || isSocialOrAuthHost(finalHost))) {
      return { broken: false, status };
    }

    // WAF / Cloudflare 503 Challenge -> Alive, NOT broken!
    if (isWafChallengeResponse(res)) {
      return { broken: false, status };
    }

    // Genuine Dead / Missing / Server Error Statuses (404, 410, 500, 502, 504, 520-523, 530 DNS, or 503 non-WAF)
    if (TRULY_BROKEN_STATUSES.has(status) || status === 503) {
      return { broken: true, status: status === 530 ? 'Domain existiert nicht' : status };
    }

    // Other 4xx (e.g., 400 on malformed internal/document link)
    if (status === 400 && (isInternal || category === 'BILD' || category === 'DOKUMENT')) {
      return { broken: true, status };
    }

    return { broken: false, status };
  }

  // Step 4: Both HEAD and GET threw network errors — distinguish dead DNS from bot-blocking firewall
  if (networkError) {
    const errMsg = String(networkError?.message || '');
    if (errMsg.toLowerCase().includes('subrequest')) {
      // Never flag Cloudflare quota limits as broken website links
      return { broken: false, status: 'Skipped' };
    }

    const dnsExists = await checkDomainExistsInDns(parsed.hostname);
    if (!dnsExists) {
      return { broken: true, status: 'Domain existiert nicht' };
    }

    // If the asset is on the website's own domain and failed twice while the site itself is up
    if (isInternal) {
      return { broken: true, status: 'Nicht erreichbar' };
    }

    // External domain has valid DNS records, meaning a firewall/TLS rule likely dropped datacenter bot packets
    return { broken: false, status: 'Firewall-Protected' };
  }

  return { broken: false, status: 200 };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 0. Configuration Endpoint
    if (url.pathname === '/api/config') {
      return jsonResponse({
        allowed_domain: getAllowedDomain(env)
      });
    }

    // 1. Discover Sitemap Endpoint
    if (url.pathname === '/api/discover') {
      if (request.method !== 'POST') return jsonResponse({ error: 'Methode nicht erlaubt' }, 405);
      return handleDiscover(request, env);
    }

    // 2. Scan Single Page HTML Endpoint
    if (url.pathname === '/api/scan-page') {
      if (request.method !== 'POST') return jsonResponse({ error: 'Methode nicht erlaubt' }, 405);
      return handleScanPage(request, env);
    }

    // 3. Verify Batch of Unique Assets/Links Endpoint
    if (url.pathname === '/api/verify-batch') {
      if (request.method !== 'POST') return jsonResponse({ error: 'Methode nicht erlaubt' }, 405);
      return handleVerifyBatch(request, env);
    }

    // 4. Fallback Direct Batch Scan Endpoint
    if (url.pathname === '/api/scan') {
      if (request.method !== 'POST') return jsonResponse({ error: 'Methode nicht erlaubt' }, 405);
      return handleScanBatch(request, env);
    }

    // 5. Status Check Endpoint
    if (url.pathname === '/api/status') {
      return jsonResponse({
        status: 'completed',
        progress: 100,
        stage: 'Fertiggestellt',
        logs: ['[INFO] Scan abgeschlossen']
      });
    }

    // Default: Serve static assets (index.html, style.css, app.js, etc.)
    return env.ASSETS.fetch(request);
  }
};

/**
 * Discovers sitemap XML files and extracts page URLs (always including start URL first)
 */
async function handleDiscover(request, env) {
  let body = {};
  try { body = await request.json(); } catch {}
  const email = (body.email || '').trim().toLowerCase();
  const allowedDomain = getAllowedDomain(env);

  if (!email || !email.endsWith(allowedDomain)) {
    return jsonResponse({
      error: `Zugriff verweigert: Nur autorisierte Mitarbeiter mit einer ${allowedDomain} E-Mail-Adresse sind zugelassen.`
    }, 403);
  }

  let url = (body.url || '').trim();
  if (!url) {
    return jsonResponse({ error: 'Bitte eine Website-URL eingeben' }, 400);
  }

  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }

  const maxPages = Math.min(parseInt(body.max_pages) || 50, 300);

  try {
    const parsed = new URL(url);
    const baseUrl = `${parsed.protocol}//${parsed.host}`;
    const sitemapPaths = ['/wp-sitemap.xml', '/sitemap_index.xml', '/sitemap.xml'];
    const foundUrls = new Set([url]); // Always ensure target URL itself is first!
    let sitemapFound = false;
    const visitedSitemaps = new Set();

    async function parseXml(xmlUrl) {
      if (visitedSitemaps.has(xmlUrl) || foundUrls.size >= maxPages) return;
      visitedSitemaps.add(xmlUrl);
      try {
        const res = await fetchWithTimeout(xmlUrl, {
          headers: BROWSER_HEADERS,
          redirect: 'follow'
        }, 5000);
        if (!res.ok) return;
        const text = await res.text();
        if (!text.includes('<loc>')) return;

        const locRegex = /<loc>\s*(https?:\/\/[^<\s]+)\s*<\/loc>/gi;
        let m;
        const childSitemaps = [];
        while ((m = locRegex.exec(text)) !== null) {
          const u = decodeHtmlEntities(m[1]);
          if (u.toLowerCase().split('?')[0].endsWith('.xml')) {
            childSitemaps.push(u);
          } else {
            sitemapFound = true;
            if (foundUrls.size < maxPages) {
              foundUrls.add(u);
            }
          }
        }

        // Prioritize page sitemaps before post/archive sitemaps so core pages are audited first
        childSitemaps.sort((a, b) => {
          const aIsPage = a.toLowerCase().includes('page') ? 0 : 1;
          const bIsPage = b.toLowerCase().includes('page') ? 0 : 1;
          return aIsPage - bIsPage;
        });

        for (const child of childSitemaps.slice(0, 12)) {
          if (foundUrls.size >= maxPages) break;
          await parseXml(child);
        }
      } catch {}
    }

    for (const p of sitemapPaths) {
      const smUrl = new URL(p, baseUrl).href;
      await parseXml(smUrl);
      if (sitemapFound) break;
    }

    const pages = Array.from(foundUrls).slice(0, maxPages);
    return jsonResponse({
      sitemap_found: sitemapFound,
      pages,
      count: sitemapFound ? pages.length : 0
    });
  } catch (err) {
    return jsonResponse({
      sitemap_found: false,
      pages: [url],
      error: err.message
    });
  }
}

/**
 * Fetches and parses a single page's HTML, extracting ALL links, images, documents, and mixed content.
 */
async function handleScanPage(request, env) {
  let body = {};
  try { body = await request.json(); } catch {}
  const email = (body.email || '').trim().toLowerCase();
  const allowedDomain = getAllowedDomain(env);

  if (!email || !email.endsWith(allowedDomain)) {
    return jsonResponse({
      error: `Zugriff verweigert: Nur autorisierte Mitarbeiter mit einer ${allowedDomain} E-Mail-Adresse sind zugelassen.`
    }, 403);
  }

  const pageUrl = (body.page_url || '').trim();
  const rootUrl = (body.root_url || pageUrl).trim();
  const sourceUrl = (body.source_url || pageUrl).trim();
  const linkLabel = (body.link_label || '[Seitenlink]').trim();

  if (!pageUrl) {
    return jsonResponse({ error: 'URL erforderlich' }, 400);
  }

  try {
    const parsedStart = new URL(rootUrl);
    const baseDomain = parsedStart.hostname.toLowerCase().replace(/^www\./, '');
    const isHttps = rootUrl.startsWith('https:');

    let pageResp;
    try {
      pageResp = await fetchWithTimeout(pageUrl, {
        headers: BROWSER_HEADERS,
        redirect: 'follow'
      }, 9000);
    } catch (err) {
      const dnsOk = await checkDomainExistsInDns(new URL(pageUrl).hostname);
      return jsonResponse({
        page_url: pageUrl,
        fetch_error: err.message,
        internal_links: [],
        internal_link_details: [],
        assets: [],
        broken_results: [{
          source: sourceUrl,
          broken_url: pageUrl,
          status: dnsOk ? 'Nicht erreichbar' : 'Domain existiert nicht',
          category: 'INTERN',
          text: linkLabel
        }],
        security_warnings: [],
        documents: []
      });
    }

    if (!pageResp.ok) {
      const status = pageResp.status;
      await pageResp.body?.cancel();
      const isTrulyBroken = TRULY_BROKEN_STATUSES.has(status) || (status === 503 && !isWafChallengeResponse(pageResp));
      return jsonResponse({
        page_url: pageUrl,
        fetch_error: `HTTP ${status}`,
        internal_links: [],
        internal_link_details: [],
        assets: [],
        broken_results: isTrulyBroken ? [{
          source: sourceUrl,
          broken_url: pageUrl,
          status: status === 530 ? 'Domain existiert nicht' : status,
          category: 'INTERN',
          text: linkLabel
        }] : [],
        security_warnings: [],
        documents: []
      });
    }

    const contentType = (pageResp.headers.get('content-type') || '').toLowerCase();
    if (!contentType.includes('text/html')) {
      await pageResp.body?.cancel();
      return jsonResponse({
        page_url: pageUrl,
        internal_links: [],
        internal_link_details: [],
        assets: [],
        broken_results: [],
        security_warnings: [],
        documents: []
      });
    }

    const rawHtml = await pageResp.text();
    const cleanHtml = stripNonVisibleHtml(rawHtml);

    const effectivePageUrl = pageResp.url || pageUrl;
    const assetsMap = new Map(); // url -> { url, category, label }
    const internalLinksMap = new Map(); // url -> label
    const securityWarnings = [];
    const documentsFound = [];

    // 1. Parse <a ...>...</a>
    const aTagRegex = /<a\b([^>]*)>([\s\S]*?)<\/a>/gi;
    let match;
    while ((match = aTagRegex.exec(cleanHtml)) !== null) {
      const attrs = match[1];
      const rawHref = extractAttr(attrs, 'href');
      if (isNonHttpScheme(rawHref)) continue;

      let text = decodeHtmlEntities(match[2].replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' '));
      if (!text) {
        text = extractAttr(attrs, 'aria-label') || extractAttr(attrs, 'title') || '[Link]';
      }

      try {
        const resolved = new URL(rawHref, effectivePageUrl);
        if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') continue;
        resolved.hash = '';
        const fullUrl = resolved.href;

        if (SKIP_URL_PATTERNS.some(p => fullUrl.toLowerCase().includes(p))) continue;

        const isInternal = isSameSiteHost(resolved.hostname, baseDomain);
        const pathLower = resolved.pathname.toLowerCase();

        // Mixed content check for internal HTTP links on HTTPS site
        if (isHttps && resolved.protocol === 'http:' && isInternal) {
          securityWarnings.push({
            source: pageUrl,
            url: fullUrl,
            issue: 'Mixed Content: Interner HTTP-Link auf HTTPS-Website'
          });
        }

        const isDoc = DOC_EXTENSIONS.some(ext => pathLower.endsWith(ext));
        const isImgLink = IMG_EXTENSIONS.some(ext => pathLower.endsWith(ext));

        if (isDoc) {
          if (!assetsMap.has(fullUrl)) {
            assetsMap.set(fullUrl, { url: fullUrl, category: 'DOKUMENT', label: text.slice(0, 50) });
          }
          documentsFound.push({ source: pageUrl, url: fullUrl, label: text.slice(0, 50) });
        } else if (isImgLink) {
          if (!assetsMap.has(fullUrl)) {
            assetsMap.set(fullUrl, { url: fullUrl, category: 'BILD', label: text.slice(0, 50) || '[Bild-Link]' });
          }
        } else if (!isInternal) {
          if (!assetsMap.has(fullUrl)) {
            assetsMap.set(fullUrl, { url: fullUrl, category: 'EXTERN', label: text.slice(0, 50) });
          }
        } else {
          // Skip WordPress pagination archives from deep crawl bloat, but still allow checking if linked
          if (!internalLinksMap.has(fullUrl)) {
            internalLinksMap.set(fullUrl, text.slice(0, 50));
          }
        }
      } catch {}
    }

    // 2. Parse <img ...>
    const imgTagRegex = /<img\b([^>]*)>/gi;
    while ((match = imgTagRegex.exec(cleanHtml)) !== null) {
      const attrs = match[1];
      let rawSrc = extractAttr(attrs, 'src');
      if (!rawSrc || rawSrc.toLowerCase().startsWith('data:')) {
        rawSrc = extractAttr(attrs, 'data-src') || extractAttr(attrs, 'data-lazy-src');
      }
      if (isNonHttpScheme(rawSrc)) continue;

      const altText = extractAttr(attrs, 'alt');
      const imgLabel = altText ? `[BILD] ${altText.slice(0, 40)}` : '[BILD]';

      try {
        const resolved = new URL(rawSrc, effectivePageUrl);
        if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') continue;
        resolved.hash = '';
        const fullImg = resolved.href;

        // Skip 1x1 analytics tracking pixels
        if (TRACKING_PIXEL_DOMAINS.some(d => fullImg.toLowerCase().includes(d))) continue;

        const isInternalImg = isSameSiteHost(resolved.hostname, baseDomain);
        if (isHttps && resolved.protocol === 'http:' && isInternalImg) {
          securityWarnings.push({
            source: pageUrl,
            url: fullImg,
            issue: 'Unsicheres Bild: Bild wird über HTTP geladen'
          });
        }

        if (!assetsMap.has(fullImg)) {
          assetsMap.set(fullImg, { url: fullImg, category: 'BILD', label: imgLabel });
        }
      } catch {}
    }

    const internalLinkDetails = Array.from(internalLinksMap.entries()).map(([u, lbl]) => ({ url: u, label: lbl }));

    return jsonResponse({
      page_url: pageUrl,
      internal_links: internalLinkDetails.map(d => d.url),
      internal_link_details: internalLinkDetails,
      assets: Array.from(assetsMap.values()),
      broken_results: [],
      security_warnings: securityWarnings,
      documents: documentsFound
    });
  } catch (err) {
    return jsonResponse({ error: err.message }, 500);
  }
}

/**
 * Verifies a batch of up to 10 unique URLs safely within Cloudflare Worker subrequest quotas.
 */
async function handleVerifyBatch(request, env) {
  let body = {};
  try { body = await request.json(); } catch {}
  const email = (body.email || '').trim().toLowerCase();
  const allowedDomain = getAllowedDomain(env);

  if (!email || !email.endsWith(allowedDomain)) {
    return jsonResponse({
      error: `Zugriff verweigert: Nur autorisierte Mitarbeiter mit einer ${allowedDomain} E-Mail-Adresse sind zugelassen.`
    }, 403);
  }

  const rootUrl = (body.root_url || '').trim();
  let baseDomain = '';
  try {
    baseDomain = new URL(rootUrl).hostname.toLowerCase().replace(/^www\./, '');
  } catch {}

  const rawItems = Array.isArray(body.items) ? body.items.slice(0, 10) : [];

  const results = await Promise.all(rawItems.map(async (item) => {
    const check = await verifySingleUrl(item.url, item.category || 'EXTERN', item.source || rootUrl, baseDomain);
    return {
      url: item.url,
      broken: check.broken,
      status: check.status
    };
  }));

  return jsonResponse({ results });
}

/**
 * Fallback single-call batch scan for direct API consumers
 */
async function handleScanBatch(request, env) {
  const startTime = Date.now();
  let body = {};
  try { body = await request.json(); } catch {}
  const email = (body.email || '').trim().toLowerCase();
  const allowedDomain = getAllowedDomain(env);

  if (!email || !email.endsWith(allowedDomain)) {
    return jsonResponse({
      error: `Zugriff verweigert: Nur autorisierte Mitarbeiter mit einer ${allowedDomain} E-Mail-Adresse sind zugelassen.`
    }, 403);
  }

  let url = (body.url || '').trim();
  if (!url) {
    return jsonResponse({ error: 'Bitte eine gültige Website-URL eingeben' }, 400);
  }
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }

  const parsedStart = new URL(url);
  const baseDomain = parsedStart.hostname.toLowerCase().replace(/^www\./, '');

  // Scan the target page via handleScanPage logic
  const pageReq = new Request(request.url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ page_url: url, root_url: url, email })
  });
  const pageRes = await handleScanPage(pageReq, env);
  const pageData = await pageRes.json();

  const assets = (pageData.assets || []).slice(0, 15);
  const brokenResults = [...(pageData.broken_results || [])];

  await Promise.all(assets.map(async (asset) => {
    const check = await verifySingleUrl(asset.url, asset.category, url, baseDomain);
    if (check.broken) {
      brokenResults.push({
        source: url,
        broken_url: asset.url,
        status: check.status,
        category: asset.category,
        text: asset.label
      });
    }
  }));

  const elapsed = Math.round((Date.now() - startTime) / 100) / 10;
  return jsonResponse({
    job_id: 'cf_' + Math.random().toString(36).slice(2, 8),
    status: 'completed',
    result: {
      target_url: url,
      duration_seconds: elapsed,
      summary: {
        pages_scanned: 1,
        total_assets_checked: assets.length,
        external_links_count: assets.filter(a => a.category === 'EXTERN').length,
        images_count: assets.filter(a => a.category === 'BILD').length,
        documents_count: assets.filter(a => a.category === 'DOKUMENT').length,
        total_broken: brokenResults.length,
        broken_links: brokenResults.filter(b => b.category === 'EXTERN' || b.category === 'INTERN').length,
        broken_images: brokenResults.filter(b => b.category === 'BILD').length,
        broken_docs: brokenResults.filter(b => b.category === 'DOKUMENT').length,
        security_warnings_count: (pageData.security_warnings || []).length
      },
      pages: [url],
      broken_results: brokenResults,
      security_warnings: pageData.security_warnings || [],
      documents: pageData.documents || []
    },
    message: 'Prüfung abgeschlossen'
  });
}
