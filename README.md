# 🚀 Web QA Auditor — Automated Website Quality & Broken Link Scanner

**Web QA Auditor** is an automated website quality assurance and broken-link auditing platform. It features an interactive, dark-slate web dashboard paired with dual execution engines: a **Cloudflare Pages Serverless Edge Worker** and a **Zero-Dependency Multi-Threaded Python Engine**.

---

## 🌟 Key Features

1. **Automated XML Sitemap Discovery & Recursive Deep Crawl**:
   - Automatically detects and parses XML sitemaps: `/wp-sitemap.xml`, `/sitemap_index.xml`, or `/sitemap.xml`.
   - Cascades through child sitemaps in sitemap index files.
   - Falls back to recursive internal link discovery if no sitemap is present.
   - Configurable scan depth: **10**, **25**, **50**, **100**, **200**, or **up to 300 pages**.

2. **Broken Link & Status Verification**:
   - Concurrently verifies internal and external hyperlinks.
   - Flags dead links (HTTP 404), server errors (HTTP 500), and connection timeouts.

3. **Broken Image & Media Asset Audit**:
   - Inspects `<img>` elements to catch missing, corrupted, or unreachable media assets.

4. **Document Integrity Verification**:
   - Detects and verifies downloadable files across standard formats: `.pdf`, `.doc`, `.docx`, `.xls`, `.xlsx`, `.ppt`, `.pptx`, `.zip`, `.csv`.

5. **Mixed Content Security Warnings**:
   - Identifies insecure HTTP links and HTTP images served on HTTPS websites, safeguarding modern browser security compliance.

6. **Corporate Access Gate**:
   - Configurable corporate email domain verification (e.g. `@yourcompany.com`).
   - Double-layered protection: verified both at the frontend UI gate and server-side on the Cloudflare Edge Worker / Python backend.
   - Domain is dynamically configurable via the `ALLOWED_DOMAIN` environment variable.

7. **Interactive Dashboard & Real-Time Terminal**:
   - Real-time progress bar and live terminal log streaming in German.
   - Dynamic KPI metric cards (Pages Scanned, Total Assets Checked, Broken Links, Insecure Elements, etc.).
   - Instant search and category filtering (All, Links, Images, Documents, Security).
   - In-browser UTF-8 CSV report export compatible with Microsoft Excel.

---

## 🏗️ Architecture & Deployment Options

Web QA Auditor supports two deployment models:

### Option A: Cloudflare Pages & Edge Worker (Recommended for 24/7 Cloud Access)
Runs completely serverless on Cloudflare's global edge network. Requires no running local computer or NAS, 100% free with unlimited uptime.

- **Frontend Assets**: Hosted globally via Cloudflare Pages CDN.
- **Backend Crawler**: Powered by `_worker.js` (Advanced Mode) utilizing Cloudflare Worker runtime.
- **Configurable Domain**: Set `ALLOWED_DOMAIN` in Cloudflare Pages Settings -> Environment Variables.

#### Deploy to Cloudflare Pages via Wrangler CLI:
```bash
# Deploy using Wrangler CLI
npx wrangler pages deploy cloudflare_deploy --project-name web-qa-auditor --branch main --skip-caching
```

---

### Option B: Self-Hosted / Local / Synology NAS (Zero External Dependencies)
Runs locally on any machine, Docker container, or Synology NAS with Python 3. Uses standard library modules only (`urllib`, `http.server`, `concurrent.futures`, `ssl`, `xml.etree`). No `pip install` required.

#### 1. Start the Local Server
```bash
# Optionally set custom authorized domain
export ALLOWED_DOMAIN="@yourcompany.com"

python3 app.py
```

#### 2. Access the Application
Open your browser and navigate to:
👉 **`http://localhost:8080`** (or `http://<YOUR_SERVER_IP>:8080`)

---

## 📁 Project Structure

```text
.
├── cloudflare_deploy/         # Production build for Cloudflare Pages (Direct Upload / Wrangler)
│   ├── _worker.js             # Cloudflare Pages Advanced Worker (Edge Crawler & Corporate Security)
│   ├── index.html             # German QA Dashboard Landing Page
│   ├── style.css              # Dark-slate responsive CSS stylesheet
│   └── app.js                 # Client-orchestrated crawler pipeline & CSV generator
├── functions/
│   └── api/
│       └── scan.js            # Cloudflare Pages Functions API route
├── static/                    # Source frontend assets
│   ├── index.html             # Dashboard markup
│   ├── style.css              # Styling rules & responsive grid
│   └── app.js                 # Frontend application logic
├── app.py                     # Standalone Python HTTP/API backend server
├── scanner.py                 # Multi-threaded Python crawler engine (12 page threads / 18 asset threads)
├── .gitignore                 # Git ignore rules for binaries, archives, and system files
└── README.md                  # Comprehensive project documentation
```

---

## 🔒 Security & Configuration

To restrict access to authorized personnel, set the `ALLOWED_DOMAIN` environment variable:

* **Cloudflare Pages**: Add an environment variable `ALLOWED_DOMAIN` under **Settings** ➔ **Environment Variables** (e.g. `@yourcompany.com`).
* **Python Server**: Set `export ALLOWED_DOMAIN="@yourcompany.com"` before running `python3 app.py`.

If not set, the system defaults to `@yourcompany.com`.

---

## 📄 License & Ownership

Open-source under the MIT License. Feel free to fork, adapt, and use for your web quality assurance workflows.
