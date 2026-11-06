import socket
import ssl
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from urllib.parse import quote, urljoin, urlparse, urlsplit, urlunsplit

HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
    ),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7',
    'Cache-Control': 'no-cache',
}

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

DOC_EXTENSIONS = (
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.rar', '.7z', '.csv', '.mp4', '.webm', '.mov', '.mp3', '.wav'
)
IMG_EXTENSIONS = (
    '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.avif', '.bmp', '.ico'
)
IGNORE_KEYWORDS = (
    '/wp-json/', '/xmlrpc.php', '/wp-login.php', '/wp-admin/',
    '/feed/', 'replytocom=', '/cdn-cgi/l/email-protection'
)
NON_HTTP_PREFIXES = (
    '#', 'javascript:', 'mailto:', 'tel:', 'sms:', 'fax:', 'callto:',
    'whatsapp:', 'skype:', 'geo:', 'maps:', 'webcal:', 'data:', 'blob:', 'about:'
)
TRACKING_PIXEL_DOMAINS = (
    'facebook.com/tr', 'connect.facebook.net', 'google-analytics.com',
    'googletagmanager.com', 'doubleclick.net', 'bat.bing.com',
    'px.ads.linkedin.com', 'analytics.tiktok.com'
)
SOCIAL_AND_AUTH_DOMAINS = (
    'linkedin.com', 'lnkd.in',
    'facebook.com', 'fb.com', 'fb.me', 'messenger.com',
    'instagram.com', 'threads.net',
    'twitter.com', 'x.com', 't.co',
    'xing.com', 'tiktok.com', 'pinterest.com', 'pinterest.de',
    'reddit.com', 'whatsapp.com', 'wa.me', 't.me',
    'kununu.com', 'glassdoor.com', 'glassdoor.de', 'stepstone.de', 'indeed.com',
    'youtube.com', 'youtu.be',
    'login.microsoftonline.com', 'forms.office.com', 'forms.cloud.microsoft',
    'accounts.google.com', 'appleid.apple.com'
)

PROTECTED_ALIVE_STATUSES = {401, 403, 405, 406, 407, 429, 999}
TRULY_BROKEN_STATUSES = {404, 410, 500, 502, 504, 520, 521, 522, 523, 530}
IGNORED_TAGS = {'script', 'style', 'template', 'noscript'}


def normalize_url(raw_url):
    """Safely percent-encodes non-ASCII paths/queries (e.g. German umlauts) and strips fragments."""
    try:
        parts = urlsplit(raw_url.strip())
        if parts.scheme.lower() not in ('http', 'https') or not parts.netloc:
            return ''
        host = parts.hostname.encode('idna').decode('ascii') if parts.hostname else ''
        netloc = f"{host}:{parts.port}" if parts.port else host
        path = quote(parts.path or '/', safe="/:@!$&'()*+,;=-._~%")
        query = quote(parts.query, safe="=/:@!$&'()*+,;-._~%?")
        return urlunsplit((parts.scheme.lower(), netloc, path, query, ''))
    except Exception:
        return ''


def is_same_site(hostname, base_domain):
    if not hostname:
        return False
    clean = hostname.lower().removeprefix('www.')
    return clean == base_domain or clean.endswith('.' + base_domain)


def is_social_or_auth_host(hostname):
    if not hostname:
        return False
    clean = hostname.lower().removeprefix('www.')
    return any(clean == d or clean.endswith('.' + d) for d in SOCIAL_AND_AUTH_DOMAINS)


def is_waf_challenge(headers, status_code):
    if not headers:
        return False
    if headers.get('cf-mitigated'):
        return True
    if status_code == 503:
        server = (headers.get('Server') or '').lower()
        if any(w in server for w in ('cloudflare', 'ddos-guard', 'akamai')):
            return True
    return False


def domain_resolves_in_dns(hostname):
    if not hostname:
        return False
    try:
        socket.getaddrinfo(hostname, None)
        return True
    except socket.gaierror:
        return False
    except Exception:
        return True


class QAHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.images = []
        self.current_link = None
        self.current_link_fallback = ''
        self.current_text = ''
        self._ignored_depth = 0

    def handle_starttag(self, tag, attrs):
        tag_lower = tag.lower()
        if tag_lower in IGNORED_TAGS:
            self._ignored_depth += 1
            return
        if self._ignored_depth > 0:
            return

        attrs_dict = {k.lower(): (v or '') for k, v in attrs if k}
        if tag_lower == 'a' and 'href' in attrs_dict:
            self.current_link = attrs_dict['href'].strip()
            self.current_link_fallback = (
                attrs_dict.get('aria-label', '').strip()
                or attrs_dict.get('title', '').strip()
            )
            self.current_text = ''
        elif tag_lower == 'img':
            src = attrs_dict.get('src', '').strip()
            if not src or src.lower().startswith('data:'):
                src = (
                    attrs_dict.get('data-src', '').strip()
                    or attrs_dict.get('data-lazy-src', '').strip()
                )
            alt = attrs_dict.get('alt', '').strip()
            if src:
                self.images.append((src, alt))

    def handle_data(self, data):
        if self._ignored_depth == 0 and self.current_link is not None:
            cleaned = ' '.join(data.split())
            if cleaned:
                self.current_text += cleaned + ' '

    def handle_endtag(self, tag):
        tag_lower = tag.lower()
        if tag_lower in IGNORED_TAGS and self._ignored_depth > 0:
            self._ignored_depth -= 1
            return
        if tag_lower == 'a' and self.current_link is not None:
            text = self.current_text.strip() or self.current_link_fallback or '[Link]'
            self.links.append((self.current_link, text))
            self.current_link = None
            self.current_link_fallback = ''
            self.current_text = ''


def get_sitemap_urls(base_url, max_pages=300, log_cb=None):
    """Parses sitemaps (/wp-sitemap.xml, /sitemap_index.xml, /sitemap.xml) with base_url always first."""
    sitemap_paths = ['/wp-sitemap.xml', '/sitemap_index.xml', '/sitemap.xml']
    found_urls = [base_url]
    found_set = {base_url}
    visited_sitemaps = set()
    sitemap_hit = False

    def parse_xml(url):
        nonlocal sitemap_hit
        if url in visited_sitemaps or len(found_urls) >= max_pages:
            return
        visited_sitemaps.add(url)
        try:
            norm = normalize_url(url)
            if not norm:
                return
            req = urllib.request.Request(norm, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                content = resp.read()
            tree = ET.fromstring(content)
            child_sitemaps = []
            for elem in tree.iter():
                if 'loc' in elem.tag and elem.text:
                    loc = normalize_url(elem.text.strip())
                    if not loc:
                        continue
                    if loc.lower().split('?')[0].endswith('.xml'):
                        child_sitemaps.append(loc)
                    else:
                        sitemap_hit = True
                        if loc not in found_set and len(found_urls) < max_pages:
                            found_set.add(loc)
                            found_urls.append(loc)

            child_sitemaps.sort(key=lambda u: 0 if 'page' in u.lower() else 1)
            for child in child_sitemaps[:12]:
                if len(found_urls) >= max_pages:
                    break
                parse_xml(child)
        except Exception:
            pass

    for path in sitemap_paths:
        sm_url = urljoin(base_url, path)
        if log_cb:
            log_cb(f"Suche nach Sitemap: {sm_url}")
        parse_xml(sm_url)
        if sitemap_hit:
            if log_cb:
                log_cb(f"Sitemap erfolgreich gefunden ({len(found_urls)} Seiten)")
            break

    if not sitemap_hit and log_cb:
        log_cb(f"Keine XML-Sitemap gefunden — Scan startet direkt auf: {base_url}")

    return found_urls[:max_pages]


def run_scanner(start_url, max_pages=100, progress_cb=None):
    """
    High-precision multi-threaded Web QA scanner in German.
    Avoids false positives on login-protected platforms (LinkedIn, etc.) and WAFs.
    """
    start_time = time.time()

    def notify(pct, stage, msg=''):
        if progress_cb:
            progress_cb(pct, stage, msg)

    start_url = start_url.strip()
    if not start_url.startswith(('http://', 'https://')):
        start_url = 'https://' + start_url
    start_url = normalize_url(start_url) or start_url

    parsed_start = urlparse(start_url)
    base_domain = (parsed_start.hostname or '').lower().removeprefix('www.')
    is_https = start_url.startswith('https:')

    notify(5, 'Sitemap-Erkennung', f"Verbindung wird hergestellt mit {start_url} ...")

    pages_to_scan = get_sitemap_urls(
        start_url,
        max_pages=max_pages,
        log_cb=lambda m: notify(10, 'Sitemap-Erkennung', m),
    )
    notify(20, 'Seitenstruktur analysieren', f"{len(pages_to_scan)} Seiten zur Überprüfung erfasst")

    assets_to_check = {}  # url -> (source_page, category, text_label)
    security_warnings_map = {}
    broken_results = []
    broken_dedupe = set()
    internal_links_found = {}  # url -> (source_page, label)

    def add_broken(source, broken_url, status, category, text):
        key = (source, broken_url)
        if key not in broken_dedupe:
            broken_dedupe.add(key)
            broken_results.append({
                'source': source,
                'broken_url': broken_url,
                'status': status,
                'category': category,
                'text': text,
            })

    # Step 2: Parallel Page HTML Processing
    def process_page(page_url):
        local_assets = []
        local_internal = []
        local_warnings = []
        page_broken = None

        try:
            req = urllib.request.Request(page_url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=7, context=ctx) as resp:
                content_type = (resp.headers.get('Content-Type') or '').lower()
                effective_url = resp.geturl() or page_url
                if 'text/html' not in content_type:
                    return page_url, local_assets, local_internal, local_warnings, None
                html = resp.read().decode('utf-8', errors='ignore')

            parser = QAHTMLParser()
            parser.feed(html)

            for href, text in parser.links:
                href_clean = href.strip()
                if not href_clean or href_clean.lower().startswith(NON_HTTP_PREFIXES) or href_clean == '//:0':
                    continue

                full = normalize_url(urljoin(effective_url, href_clean))
                if not full:
                    continue
                if any(k in full.lower() for k in IGNORE_KEYWORDS):
                    continue

                parsed_target = urlparse(full)
                is_internal = is_same_site(parsed_target.hostname, base_domain)
                path_lower = parsed_target.path.lower()

                if is_https and parsed_target.scheme == 'http' and is_internal:
                    local_warnings.append({
                        'source': page_url,
                        'url': full,
                        'issue': 'Mixed Content: Interner HTTP-Link auf HTTPS-Website',
                    })

                if path_lower.endswith(DOC_EXTENSIONS):
                    local_assets.append((full, 'DOKUMENT', text[:50]))
                elif path_lower.endswith(IMG_EXTENSIONS):
                    local_assets.append((full, 'BILD', text[:50] or '[Bild-Link]'))
                elif not is_internal:
                    local_assets.append((full, 'EXTERN', text[:50]))
                else:
                    local_internal.append((full, text[:50]))

            for src, alt in parser.images:
                src_clean = src.strip()
                if not src_clean or src_clean.lower().startswith(NON_HTTP_PREFIXES) or src_clean == '//:0':
                    continue

                full_img = normalize_url(urljoin(effective_url, src_clean))
                if not full_img:
                    continue
                if any(tp in full_img.lower() for tp in TRACKING_PIXEL_DOMAINS):
                    continue

                parsed_img = urlparse(full_img)
                if is_https and parsed_img.scheme == 'http' and is_same_site(parsed_img.hostname, base_domain):
                    local_warnings.append({
                        'source': page_url,
                        'url': full_img,
                        'issue': 'Unsicheres Bild: Bild wird über unverschlüsseltes HTTP geladen',
                    })

                label = f"[BILD] {alt[:40]}" if alt else '[BILD]'
                local_assets.append((full_img, 'BILD', label))

        except urllib.error.HTTPError as he:
            if he.code in TRULY_BROKEN_STATUSES or (he.code == 503 and not is_waf_challenge(he.headers, he.code)):
                page_broken = (start_url, page_url, he.code, 'INTERN', '[Seitenlink]')
        except Exception as e:
            hostname = urlparse(page_url).hostname
            if not domain_resolves_in_dns(hostname):
                page_broken = (start_url, page_url, 'Domain existiert nicht', 'INTERN', '[Seitenlink]')
            else:
                notify(25, 'Seitenstruktur analysieren', f"Zugriffswarnung bei {page_url}: {str(e)[:50]}")

        return page_url, local_assets, local_internal, local_warnings, page_broken

    notify(25, 'Seitenstruktur analysieren', 'Seiteninhalte werden mit 12 Threads parallel analysiert...')
    completed_pages = 0
    visited_set = set(pages_to_scan)

    def ingest_page_results(results_iter, total_count):
        nonlocal completed_pages
        for page, page_assets, page_int, page_warns, page_broken in results_iter:
            completed_pages += 1
            if page_broken:
                add_broken(*page_broken)
            for asset_url, cat, label in page_assets:
                if asset_url not in assets_to_check:
                    assets_to_check[asset_url] = (page, cat, label)
            for int_url, int_lbl in page_int:
                if int_url not in internal_links_found:
                    internal_links_found[int_url] = (page, int_lbl)
            for w in page_warns:
                security_warnings_map[(w['source'], w['url'])] = w
            pct = min(55, int(25 + (completed_pages / max(1, total_count)) * 30))
            notify(pct, 'Seitenstruktur analysieren', f"Analysiert ({completed_pages}/{total_count}): {page[:65]}")

    with ThreadPoolExecutor(max_workers=12) as executor:
        ingest_page_results(executor.map(process_page, pages_to_scan), len(pages_to_scan))

    # Deep crawl discovered internal pages if sitemap had fewer pages than max_pages
    while len(pages_to_scan) < max_pages:
        candidates = [
            u for u in internal_links_found.keys()
            if u not in visited_set and '/page/' not in u.lower()
        ][:max_pages - len(pages_to_scan)]
        if not candidates:
            break
        for c in candidates:
            visited_set.add(c)
            pages_to_scan.append(c)
        notify(56, 'Crawling erweitern', f"{len(candidates)} weitere Unterseiten entdeckt. Werden analysiert...")
        with ThreadPoolExecutor(max_workers=12) as executor:
            ingest_page_results(executor.map(process_page, candidates), len(pages_to_scan))

    # Also verify unvisited internal links (up to 250) so broken internal hrefs are caught
    added_int = 0
    for int_url, (src_page, int_lbl) in internal_links_found.items():
        if int_url not in visited_set and int_url not in assets_to_check and added_int < 250:
            assets_to_check[int_url] = (src_page, 'INTERN', int_lbl)
            added_int += 1

    # Remove already-fetched pages
    for v_url in visited_set:
        assets_to_check.pop(v_url, None)

    total_assets = len(assets_to_check)
    notify(58, 'Assets & Links prüfen', f"{total_assets} eindeutige Assets und Links zur Validierung bereit")

    # Step 3: High-Precision Parallel Asset Verification (16 Threads)
    def verify_asset(item):
        url, (source, cat, label) = item
        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        is_internal = is_same_site(hostname, base_domain)

        req_headers = dict(HEADERS)
        req_headers['Referer'] = source

        def evaluate_http_result(status_code, resp_headers, final_url=''):
            if 200 <= status_code < 400:
                if cat == 'BILD' and is_internal and status_code == 200:
                    ct = (resp_headers.get('Content-Type') or '').lower()
                    if ct.startswith('text/html') and parsed.path.lower().endswith(
                        ('.jpg', '.jpeg', '.png', '.gif', '.webp', '.avif', '.bmp')
                    ) and not is_waf_challenge(resp_headers, status_code):
                        return {'source': source, 'broken_url': url, 'status': '404 (Kein Bild)', 'category': cat, 'text': label}
                return None

            if status_code in PROTECTED_ALIVE_STATUSES:
                return None

            final_host = urlparse(final_url).hostname if final_url else hostname
            if status_code == 400 and (is_social_or_auth_host(hostname) or is_social_or_auth_host(final_host)):
                return None

            if is_waf_challenge(resp_headers, status_code):
                return None

            if status_code in TRULY_BROKEN_STATUSES or status_code == 503:
                return {'source': source, 'broken_url': url, 'status': status_code, 'category': cat, 'text': label}

            if status_code == 400 and (is_internal or cat in ('BILD', 'DOKUMENT')):
                return {'source': source, 'broken_url': url, 'status': status_code, 'category': cat, 'text': label}

            return None

        # 1. Try HEAD first
        head_status = None
        head_headers = None
        try:
            req_head = urllib.request.Request(url, headers=req_headers, method='HEAD')
            with urllib.request.urlopen(req_head, timeout=5.5, context=ctx) as resp:
                return evaluate_http_result(resp.status, resp.headers, resp.geturl())
        except urllib.error.HTTPError as e:
            head_status = e.code
            head_headers = e.headers
            if head_status in (429, 999):
                return None

        # 2. Always confirm with GET if HEAD failed or returned >= 400
        get_headers = dict(req_headers)
        if cat in ('BILD', 'DOKUMENT'):
            get_headers['Range'] = 'bytes=0-2047'
        try:
            req_get = urllib.request.Request(url, headers=get_headers, method='GET')
            with urllib.request.urlopen(req_get, timeout=7.0, context=ctx) as resp:
                return evaluate_http_result(resp.status, resp.headers, resp.geturl())
        except urllib.error.HTTPError as e2:
            return evaluate_http_result(e2.code, e2.headers, e2.geturl() if hasattr(e2, 'geturl') else '')
        except Exception:
            if head_status is not None:
                return evaluate_http_result(head_status, head_headers)
            if not domain_resolves_in_dns(hostname):
                return {'source': source, 'broken_url': url, 'status': 'Domain existiert nicht', 'category': cat, 'text': label}
            if is_internal:
                return {'source': source, 'broken_url': url, 'status': 'Nicht erreichbar', 'category': cat, 'text': label}
            # External domain resolves in DNS (e.g. TLS cipher mismatch or bot packet drop) -> not a dead link
            return None

    completed_assets = 0
    with ThreadPoolExecutor(max_workers=16) as executor:
        for res in executor.map(verify_asset, assets_to_check.items()):
            completed_assets += 1
            if res:
                add_broken(res['source'], res['broken_url'], res['status'], res['category'], res['text'])
            if total_assets > 0:
                pct = int(60 + (completed_assets / total_assets) * 36)
                if completed_assets % 10 == 0 or completed_assets == total_assets:
                    notify(pct, 'Assets & Links prüfen', f"Geprüft ({completed_assets}/{total_assets}) Elemente...")

    extern_count = sum(1 for _, (_, c, _) in assets_to_check.items() if c == 'EXTERN')
    images_count = sum(1 for _, (_, c, _) in assets_to_check.items() if c == 'BILD')
    docs_count = sum(1 for _, (_, c, _) in assets_to_check.items() if c == 'DOKUMENT')

    broken_links_count = sum(1 for b in broken_results if b['category'] in ('EXTERN', 'INTERN'))
    broken_images_count = sum(1 for b in broken_results if b['category'] == 'BILD')
    broken_docs_count = sum(1 for b in broken_results if b['category'] == 'DOKUMENT')

    security_warnings = list(security_warnings_map.values())
    documents_list = [
        {'source': src, 'url': u, 'label': lbl}
        for u, (src, c, lbl) in assets_to_check.items() if c == 'DOKUMENT'
    ]

    elapsed = round(time.time() - start_time, 2)
    notify(100, 'Prüfung abgeschlossen', f"Scan in {elapsed}s beendet. Insgesamt {len(broken_results)} echte Defekte gefunden.")

    return {
        'target_url': start_url,
        'duration_seconds': elapsed,
        'summary': {
            'pages_scanned': len(pages_to_scan),
            'total_assets_checked': len(assets_to_check),
            'external_links_count': extern_count,
            'images_count': images_count,
            'documents_count': docs_count,
            'total_broken': len(broken_results),
            'broken_links': broken_links_count,
            'broken_images': broken_images_count,
            'broken_docs': broken_docs_count,
            'security_warnings_count': len(security_warnings),
        },
        'pages': pages_to_scan,
        'broken_results': broken_results,
        'security_warnings': security_warnings,
        'documents': documents_list[:50],
    }
