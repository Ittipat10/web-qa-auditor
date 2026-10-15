import urllib.request
import urllib.error
import ssl
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor
import time

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
}

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

DOC_EXTENSIONS = ('.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.zip', '.csv')
IGNORE_KEYWORDS = ('/wp-json/', '/feed/', 'replytocom=', '/page/', '#')


class QAHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.images = []
        self.current_link = None
        self.current_text = ""

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == 'a' and 'href' in attrs_dict:
            self.current_link = attrs_dict['href']
            self.current_text = ""
        elif tag == 'img' and 'src' in attrs_dict:
            src = attrs_dict['src'].strip()
            if src:
                self.images.append(src)

    def handle_data(self, data):
        if self.current_link is not None:
            self.current_text += data.strip() + " "

    def handle_endtag(self, tag):
        if tag == 'a' and self.current_link is not None:
            text = self.current_text.strip() or "[Link]"
            self.links.append((self.current_link, text))
            self.current_link = None
            self.current_text = ""


def get_sitemap_urls(base_url, max_pages=300, log_cb=None):
    """Parses sitemaps (/wp-sitemap.xml, /sitemap_index.xml, /sitemap.xml) or falls back to base_url."""
    sitemap_paths = ['/wp-sitemap.xml', '/sitemap_index.xml', '/sitemap.xml']
    found_urls = set()
    visited_sitemaps = set()

    def parse_xml(url):
        if url in visited_sitemaps or len(found_urls) >= max_pages:
            return
        visited_sitemaps.add(url)
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            resp = urllib.request.urlopen(req, timeout=4, context=ctx)
            content = resp.read()
            tree = ET.fromstring(content)
            for elem in tree.iter():
                if 'loc' in elem.tag and elem.text:
                    loc = elem.text.strip()
                    if loc.endswith('.xml'):
                        parse_xml(loc)
                    else:
                        if len(found_urls) < max_pages:
                            found_urls.add(loc)
        except Exception:
            pass

    for path in sitemap_paths:
        sm_url = urljoin(base_url, path)
        if log_cb:
            log_cb(f"Suche nach Sitemap: {sm_url}")
        parse_xml(sm_url)
        if found_urls:
            if log_cb:
                log_cb(f"Sitemap erfolgreich gefunden ({len(found_urls)} Seiten)")
            break

    if not found_urls:
        if log_cb:
            log_cb(f"Keine XML-Sitemap gefunden — Scan startet direkt auf: {base_url}")
        found_urls.add(base_url)

    return list(found_urls)[:max_pages]


def run_scanner(start_url, max_pages=100, progress_cb=None):
    """
    Main scanner function in German.
    progress_cb(progress_percent, stage_title, log_message)
    Returns: dict with scan results and metrics.
    """
    start_time = time.time()

    def notify(pct, stage, msg=""):
        if progress_cb:
            progress_cb(pct, stage, msg)

    start_url = start_url.strip()
    if not start_url.startswith(('http://', 'https://')):
        start_url = 'https://' + start_url

    parsed_start = urlparse(start_url)
    base_domain = parsed_start.netloc.replace('www.', '')
    is_https = start_url.startswith('https')

    notify(5, "Sitemap-Erkennung", f"Verbindung wird hergestellt mit {start_url} ...")

    # Step 1: Discover pages via Sitemap or fallback
    def sitemap_logger(msg):
        notify(10, "Sitemap-Erkennung", msg)

    pages_to_scan = get_sitemap_urls(start_url, max_pages=max_pages, log_cb=sitemap_logger)
    notify(20, "Seitenstruktur analysieren", f"{len(pages_to_scan)} Seiten zur Überprüfung erfasst")

    assets_to_check = {}  # url -> (source_page, category, text_label)
    security_warnings = []
    broken_results = []
    internal_links_found = set()

    # Step 2: Parallel Page Processing
    def process_page(page_url):
        local_assets = []
        try:
            req = urllib.request.Request(page_url, headers=HEADERS)
            resp = urllib.request.urlopen(req, timeout=3.5, context=ctx)
            content_type = resp.headers.get('Content-Type', '')
            if 'text/html' not in content_type:
                return page_url, []
            
            html = resp.read().decode('utf-8', errors='ignore')
            parser = QAHTMLParser()
            parser.feed(html)

            for href, text in parser.links:
                if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                    continue
                full = urljoin(page_url, href).split('#')[0]
                if any(k in full for k in IGNORE_KEYWORDS):
                    continue

                target_netloc = urlparse(full).netloc.replace('www.', '')
                is_internal = (base_domain in target_netloc)

                # Mixed content check
                if is_https and full.startswith('http://') and is_internal:
                    security_warnings.append({
                        'source': page_url,
                        'url': full,
                        'issue': 'Mixed Content: Interner HTTP-Link auf HTTPS-Website'
                    })

                is_doc = full.lower().split('?')[0].endswith(DOC_EXTENSIONS)
                if is_doc:
                    local_assets.append((full, 'DOKUMENT', text[:40]))
                elif not is_internal:
                    local_assets.append((full, 'EXTERN', text[:40]))
                else:
                    internal_links_found.add(full)

            for src in parser.images:
                if src.startswith('data:'):
                    continue
                full_img = urljoin(page_url, src)
                img_netloc = urlparse(full_img).netloc.replace('www.', '')
                
                # Mixed content check for images
                if is_https and full_img.startswith('http://') and (base_domain in img_netloc):
                    security_warnings.append({
                        'source': page_url,
                        'url': full_img,
                        'issue': 'Unsicheres Bild: Bild wird über unverschlüsseltes HTTP geladen'
                    })
                local_assets.append((full_img, 'BILD', '[BILD]'))
        except Exception as e:
            notify(25, "Seitenstruktur analysieren", f"Zugriffsfehler bei {page_url}: {str(e)[:50]}")
        return page_url, local_assets

    notify(25, "Seitenstruktur analysieren", "Seiteninhalte werden mit 12 Threads parallel analysiert...")
    completed_pages = 0
    total_pages = len(pages_to_scan)

    with ThreadPoolExecutor(max_workers=12) as executor:
        for page, page_assets in executor.map(process_page, pages_to_scan):
            completed_pages += 1
            for asset, cat, label in page_assets:
                if asset not in assets_to_check:
                    assets_to_check[asset] = (page, cat, label)
            
            pct = int(25 + (completed_pages / total_pages) * 30)
            notify(pct, "Seitenstruktur analysieren", f"Analysiert ({completed_pages}/{total_pages}): {page[:60]}...")

    # If only 1 page was in sitemap, add discovered internal links
    if len(pages_to_scan) <= 1 and internal_links_found:
        additional_pages = [u for u in internal_links_found if u not in pages_to_scan][:max(0, max_pages - len(pages_to_scan))]
        if additional_pages:
            notify(56, "Crawling erweitern", f"{len(additional_pages)} interne Links entdeckt. Werden gescannt...")
            with ThreadPoolExecutor(max_workers=12) as executor:
                for page, page_assets in executor.map(process_page, additional_pages):
                    pages_to_scan.append(page)
                    for asset, cat, label in page_assets:
                        if asset not in assets_to_check:
                            assets_to_check[asset] = (page, cat, label)

    total_assets = len(assets_to_check)
    notify(58, "Assets & Links prüfen", f"{total_assets} Assets und Links zur Validierung bereit")

    # Step 3: Parallel Asset Verification (18 Threads)
    def verify_asset(item):
        url, (source, cat, label) = item
        try:
            req = urllib.request.Request(url, headers=HEADERS, method='HEAD')
            urllib.request.urlopen(req, timeout=3.0, context=ctx)
            return None
        except urllib.error.HTTPError as e:
            if e.code in (403, 405):
                try:
                    req_get = urllib.request.Request(url, headers=HEADERS, method='GET')
                    r = urllib.request.urlopen(req_get, timeout=3.0, context=ctx)
                    r.close()
                    return None
                except urllib.error.HTTPError as e2:
                    return {
                        'source': source,
                        'broken_url': url,
                        'status': e2.code,
                        'category': cat,
                        'text': label
                    }
                except Exception:
                    return {
                        'source': source,
                        'broken_url': url,
                        'status': 'Timeout',
                        'category': cat,
                        'text': label
                    }
            return {
                'source': source,
                'broken_url': url,
                'status': e.code,
                'category': cat,
                'text': label
            }
        except urllib.error.URLError as ue:
            reason = str(ue.reason) if hasattr(ue, 'reason') else 'URLError'
            return {
                'source': source,
                'broken_url': url,
                'status': f"Fehler: {reason[:20]}",
                'category': cat,
                'text': label
            }
        except Exception:
            return {
                'source': source,
                'broken_url': url,
                'status': 'Timeout/Fehler',
                'category': cat,
                'text': label
            }

    completed_assets = 0
    with ThreadPoolExecutor(max_workers=18) as executor:
        for res in executor.map(verify_asset, assets_to_check.items()):
            completed_assets += 1
            if res:
                broken_results.append(res)
            if total_assets > 0:
                pct = int(60 + (completed_assets / total_assets) * 35)
                if completed_assets % 10 == 0 or completed_assets == total_assets:
                    notify(pct, "Assets & Links prüfen", f"Geprüft ({completed_assets}/{total_assets}) Elemente...")

    # Statistics
    extern_count = sum(1 for _, (_, c, _) in assets_to_check.items() if c == 'EXTERN')
    images_count = sum(1 for _, (_, c, _) in assets_to_check.items() if c == 'BILD')
    docs_count = sum(1 for _, (_, c, _) in assets_to_check.items() if c == 'DOKUMENT')

    broken_links_count = sum(1 for b in broken_results if b['category'] == 'EXTERN')
    broken_images_count = sum(1 for b in broken_results if b['category'] == 'BILD')
    broken_docs_count = sum(1 for b in broken_results if b['category'] == 'DOKUMENT')

    documents_list = [
        {'source': src, 'url': u, 'label': lbl}
        for u, (src, c, lbl) in assets_to_check.items() if c == 'DOKUMENT'
    ]

    elapsed = round(time.time() - start_time, 2)
    notify(100, "Prüfung abgeschlossen", f"Scan in {elapsed}s beendet. Insgesamt {len(broken_results)} Fehler gefunden.")

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
            'security_warnings_count': len(security_warnings)
        },
        'pages': pages_to_scan,
        'broken_results': broken_results,
        'security_warnings': security_warnings,
        'documents': documents_list[:20]
    }
