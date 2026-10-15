const DEFAULT_ALLOWED_DOMAIN = '@yourcompany.com';
const DOC_EXTENSIONS = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.zip', '.csv'];
const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36';

export async function onRequestPost(context) {
  const allowedDomain = context.env?.ALLOWED_DOMAIN || DEFAULT_ALLOWED_DOMAIN;
  const startTime = Date.now();
  let body;
  try {
    body = await context.request.json();
  } catch {
    body = {};
  }

  let url = (body.url || '').trim();
  const email = (body.email || '').trim().toLowerCase();

  // Corporate Domain Security Enforcement
  if (!email || !email.endsWith(allowedDomain)) {
    return new Response(JSON.stringify({
      error: `Zugriff verweigert: Nur autorisierte Mitarbeiter mit einer ${allowedDomain} E-Mail-Adresse sind zugelassen.`
    }), {
      status: 403,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  if (!url) {
    return new Response(JSON.stringify({ error: 'Bitte eine gültige Website-URL eingeben' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }

  try {
    const parsedStart = new URL(url);
    const baseDomain = parsedStart.hostname.replace(/^www\./, '');
    const isHttps = url.startsWith('https:');

    // Fetch Target Page HTML
    const pageResp = await fetch(url, {
      headers: { 'User-Agent': USER_AGENT },
      redirect: 'follow'
    });

    const contentType = pageResp.headers.get('content-type') || '';
    if (!contentType.includes('text/html')) {
      return new Response(JSON.stringify({
        error: `Die Ziel-URL liefert kein HTML (Content-Type: ${contentType})`
      }), { status: 400, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
    }

    const html = await pageResp.text();

    const assetsToCheck = new Map(); // url -> { source, cat, label }
    const securityWarnings = [];
    const brokenResults = [];

    // Extract Links <a href="...">
    const linkRegex = /<a\s+[^>]*?href=["']([^"']+)["'][^>]*?>([\s\S]*?)<\/a>/gi;
    let match;
    while ((match = linkRegex.exec(html)) !== null) {
      let href = match[1].trim();
      let text = match[2].replace(/<[^>]+>/g, '').trim() || '[Link]';

      if (!href || href.startsWith('#') || href.startsWith('javascript:') || href.startsWith('mailto:') || href.startsWith('tel:')) {
        continue;
      }

      try {
        const fullUrl = new URL(href, url).href.split('#')[0];
        const targetHost = new URL(fullUrl).hostname.replace(/^www\./, '');
        const isInternal = targetHost.includes(baseDomain);

        // Mixed Content Check
        if (isHttps && fullUrl.startsWith('http:') && isInternal) {
          securityWarnings.push({
            source: url,
            url: fullUrl,
            issue: 'Mixed Content: Interner HTTP-Link auf HTTPS-Website'
          });
        }

        const isDoc = DOC_EXTENSIONS.some(ext => fullUrl.toLowerCase().split('?')[0].endsWith(ext));
        if (isDoc) {
          if (!assetsToCheck.has(fullUrl)) assetsToCheck.set(fullUrl, { source: url, cat: 'DOKUMENT', label: text.slice(0, 40) });
        } else if (!isInternal) {
          if (!assetsToCheck.has(fullUrl)) assetsToCheck.set(fullUrl, { source: url, cat: 'EXTERN', label: text.slice(0, 40) });
        }
      } catch {}
    }

    // Extract Images <img src="...">
    const imgRegex = /<img\s+[^>]*?src=["']([^"']+)["']/gi;
    while ((match = imgRegex.exec(html)) !== null) {
      let src = match[1].trim();
      if (!src || src.startsWith('data:')) continue;

      try {
        const fullImg = new URL(src, url).href;
        const imgHost = new URL(fullImg).hostname.replace(/^www\./, '');

        if (isHttps && fullImg.startsWith('http:') && imgHost.includes(baseDomain)) {
          securityWarnings.push({
            source: url,
            url: fullImg,
            issue: 'Unsicheres Bild: Bild wird über HTTP geladen'
          });
        }

        if (!assetsToCheck.has(fullImg)) {
          assetsToCheck.set(fullImg, { source: url, cat: 'BILD', label: '[BILD]' });
        }
      } catch {}
    }

    // Limit assets to check to fit Cloudflare subrequest limit (max 35)
    const items = Array.from(assetsToCheck.entries()).slice(0, 35);

    // Verify assets concurrently
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

    const elapsed = Math.round((Date.now() - startTime) / 100) / 10;
    const externCount = items.filter(([, v]) => v.cat === 'EXTERN').length;
    const imagesCount = items.filter(([, v]) => v.cat === 'BILD').length;
    const docsCount = items.filter(([, v]) => v.cat === 'DOKUMENT').length;

    const result = {
      target_url: url,
      duration_seconds: elapsed,
      summary: {
        pages_scanned: 1,
        total_assets_checked: items.length,
        external_links_count: externCount,
        images_count: imagesCount,
        documents_count: docsCount,
        total_broken: brokenResults.length,
        broken_links: brokenResults.filter(b => b.category === 'EXTERN').length,
        broken_images: brokenResults.filter(b => b.category === 'BILD').length,
        broken_docs: brokenResults.filter(b => b.category === 'DOKUMENT').length,
        security_warnings_count: securityWarnings.length
      },
      pages: [url],
      broken_results: brokenResults,
      security_warnings: securityWarnings,
      documents: items.filter(([, v]) => v.cat === 'DOKUMENT').map(([u, v]) => ({ source: v.source, url: u, label: v.label }))
    };

    return new Response(JSON.stringify({
      job_id: 'cf_' + Math.random().toString(36).slice(2, 8),
      status: 'completed',
      result: result,
      message: 'Prüfung auf Cloudflare Edge abgeschlossen'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  } catch (e) {
    return new Response(JSON.stringify({
      error: `Verbindungsfehler: ${e.message}`
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }
}
