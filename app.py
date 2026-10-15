import http.server
import json
import os
import sys
import threading
import time
import uuid
import csv
import io
from urllib.parse import urlparse, parse_qs

from scanner import run_scanner

PORT = 8080
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
ALLOWED_DOMAIN = os.environ.get('ALLOWED_DOMAIN', '@yourcompany.com')

jobs = {}
jobs_lock = threading.Lock()


def get_content_type(path):
    if path.endswith('.html'):
        return 'text/html; charset=utf-8'
    elif path.endswith('.css'):
        return 'text/css; charset=utf-8'
    elif path.endswith('.js'):
        return 'application/javascript; charset=utf-8'
    elif path.endswith('.svg'):
        return 'image/svg+xml'
    elif path.endswith('.png'):
        return 'image/png'
    elif path.endswith('.ico'):
        return 'image/x-icon'
    elif path.endswith('.json'):
        return 'application/json; charset=utf-8'
    return 'application/octet-stream'


class AppRequestHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def send_json_response(self, data, status_code=200):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == '/api/scan':
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                raw_body = self.rfile.read(content_length).decode('utf-8')
                data = json.loads(raw_body) if raw_body else {}
                url = data.get('url', '').strip()
                max_pages = int(data.get('max_pages', 50))
                user_email = data.get('email', '').strip().lower()

                # Security check: Corporate Email Domain Restriction
                if not user_email or not user_email.endswith(ALLOWED_DOMAIN):
                    self.send_json_response({
                        'error': f'Zugriff verweigert: Nur autorisierte Mitarbeiter mit einer {ALLOWED_DOMAIN} E-Mail-Adresse sind zugelassen.'
                    }, status_code=403)
                    return

                if not url:
                    self.send_json_response({'error': 'Bitte eine gültige Website-URL angeben'}, status_code=400)
                    return

                job_id = str(uuid.uuid4())[:8]
                with jobs_lock:
                    jobs[job_id] = {
                        'id': job_id,
                        'url': url,
                        'max_pages': max_pages,
                        'user_email': user_email,
                        'status': 'running',
                        'progress': 2,
                        'stage': 'Prüfung wird vorbereitet...',
                        'logs': [
                            f"Autorisiert durch: {user_email}",
                            f"Scan gestartet für {url}"
                        ],
                        'result': None,
                        'error': None,
                        'created_at': time.time()
                    }

                def worker():
                    def on_progress(pct, stage, msg=""):
                        with jobs_lock:
                            if job_id in jobs:
                                jobs[job_id]['progress'] = pct
                                jobs[job_id]['stage'] = stage
                                if msg:
                                    jobs[job_id]['logs'].append(msg)
                                    if len(jobs[job_id]['logs']) > 100:
                                        jobs[job_id]['logs'] = jobs[job_id]['logs'][-100:]

                    try:
                        result = run_scanner(url, max_pages=max_pages, progress_cb=on_progress)
                        with jobs_lock:
                            if job_id in jobs:
                                jobs[job_id]['status'] = 'completed'
                                jobs[job_id]['progress'] = 100
                                jobs[job_id]['stage'] = 'Abgeschlossen'
                                jobs[job_id]['result'] = result
                    except Exception as e:
                        with jobs_lock:
                            if job_id in jobs:
                                jobs[job_id]['status'] = 'error'
                                jobs[job_id]['error'] = str(e)
                                jobs[job_id]['logs'].append(f"Fehler: {str(e)}")

                thread = threading.Thread(target=worker, daemon=True)
                thread.start()

                self.send_json_response({
                    'job_id': job_id,
                    'status': 'running',
                    'message': 'Prüfung erfolgreich autorisiert und gestartet'
                })
            except Exception as e:
                self.send_json_response({'error': f"Interner Fehler: {str(e)}"}, status_code=500)
        else:
            self.send_json_response({'error': 'Nicht gefunden'}, status_code=404)

    def do_GET(self):
        parsed = urlparse(self.path)
        query_params = parse_qs(parsed.query)

        if parsed.path == '/api/config':
            self.send_json_response({'allowed_domain': ALLOWED_DOMAIN})
            return

        if parsed.path == '/api/status':
            job_id = query_params.get('job_id', [None])[0]
            if not job_id:
                self.send_json_response({'error': 'Parameter job_id fehlt'}, status_code=400)
                return

            with jobs_lock:
                job = jobs.get(job_id)

            if not job:
                self.send_json_response({'error': 'Scan-Auftrag nicht gefunden'}, status_code=404)
                return

            self.send_json_response(job)
            return

        if parsed.path == '/api/export':
            job_id = query_params.get('job_id', [None])[0]
            with jobs_lock:
                job = jobs.get(job_id)

            if not job or job.get('status') != 'completed' or not job.get('result'):
                self.send_json_response({'error': 'Auftrag noch nicht abgeschlossen oder nicht gefunden'}, status_code=400)
                return

            result = job['result']
            output = io.StringIO()
            output.write('\ufeff')
            writer = csv.writer(output)
            writer.writerow(['Fehlertyp / Kategorie', 'HTTP-Status', 'Details / Kontext', 'Defekte oder unsichere Ziel-URL', 'Gefunden auf Seite (Quell-URL)'])

            for b in result.get('broken_results', []):
                writer.writerow([
                    f"Defekter {b.get('category', 'Asset')}",
                    b.get('status', 'Fehler'),
                    b.get('text', ''),
                    b.get('broken_url', ''),
                    b.get('source', '')
                ])

            for w in result.get('security_warnings', []):
                writer.writerow([
                    'Sicherheitswarnung (Mixed Content)',
                    'Unsicheres HTTP',
                    w.get('issue', ''),
                    w.get('url', ''),
                    w.get('source', '')
                ])

            csv_bytes = output.getvalue().encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/csv; charset=utf-8')
            self.send_header('Content-Disposition', f'attachment; filename="qa_bericht_{job_id}.csv"')
            self.send_header('Content-Length', str(len(csv_bytes)))
            self.end_headers()
            self.wfile.write(csv_bytes)
            return

        req_path = parsed.path
        if req_path == '/' or req_path == '':
            req_path = '/index.html'

        rel_path = req_path.lstrip('/')
        file_path = os.path.join(STATIC_DIR, rel_path)

        real_file_path = os.path.realpath(file_path)
        real_static_dir = os.path.realpath(STATIC_DIR)
        if not real_file_path.startswith(real_static_dir) or not os.path.isfile(real_file_path):
            self.send_response(404)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.end_headers()
            self.wfile.write(b"404 Nicht gefunden")
            return

        try:
            with open(real_file_path, 'rb') as f:
                content = f.read()
            self.send_response(200)
            self.send_header('Content-Type', get_content_type(real_file_path))
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"500 Serverfehler: {e}".encode('utf-8'))

    def do_HEAD(self):
        self.do_GET()


def run_server(port=PORT):
    for p in range(port, port + 20):
        try:
            httpd = http.server.ThreadingHTTPServer(('', p), AppRequestHandler)
            print(f"=====================================================")
            print(f" 🚀 CapiBug QA Scanner Web App ist aktiv!")
            print(f" 🔒 Zugriffsbeschraenkung: {ALLOWED_DOMAIN}")
            print(f" 🌐 Im Browser oeffnen: http://localhost:{p}")
            print(f"=====================================================")
            httpd.serve_forever()
            break
        except OSError:
            continue


if __name__ == '__main__':
    p = PORT
    if len(sys.argv) > 1:
        try:
            p = int(sys.argv[1])
        except ValueError:
            pass
    run_server(p)
