#!/usr/bin/env python3
# app.py
"""
Flask single-page UI + async endpoint scanner API.
Usage (local): python app.py
"""

import asyncio
import platform
import time
import random
import json
from urllib.parse import urljoin, urlparse
import urllib.robotparser

from flask import Flask, request, jsonify, render_template_string

# Windows asyncio fix
if platform.system() == "Windows":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import aiohttp

app = Flask(__name__, static_folder="static", template_folder="templates")

# -------------------
# Scanner configuration (same logic as your scanner)
# -------------------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    "curl/8.0.1",
    "python-requests/2.31.0"
]

DEFAULT_WORDLIST = [
    "/", "index.html", "home", "login", "logout", "admin", "dashboard",
    "user", "api/", "api/v1/", "status", "health", "ping",
    "robots.txt", "sitemap.xml", "favicon.ico", ".well-known/security.txt",
    "wp-login.php", "wp-admin", "admin/login", "config", ".well-known/assetlinks.json"
]

TIMEOUT = 10  # seconds
CONCURRENCY = 10
DELAY_BETWEEN_REQUESTS = 0.18  # seconds


async def fetch(session, url, headers, sem, results, retries=1):
    async with sem:
        try:
            async with session.get(url, headers=headers, timeout=TIMEOUT, allow_redirects=True) as resp:
                text_len = None
                try:
                    text_len = resp.content_length
                except Exception:
                    text_len = None
                info = {
                    "url": str(url),
                    "status": resp.status,
                    "reason": resp.reason,
                    "final_url": str(resp.url),
                    "content_length": text_len,
                    "server": resp.headers.get("Server"),
                    "headers": {k: v for k, v in resp.headers.items()}
                }
                results.append(info)
                await asyncio.sleep(DELAY_BETWEEN_REQUESTS + random.random() * 0.1)
        except asyncio.TimeoutError:
            results.append({"url": str(url), "error": "timeout"})
        except aiohttp.ClientResponseError as e:
            results.append({"url": str(url), "error": f"response_error: {e}"})
        except aiohttp.ClientError as e:
            if retries > 0:
                await asyncio.sleep(0.5)
                await fetch(session, url, headers, sem, results, retries - 1)
            else:
                results.append({"url": str(url), "error": f"client_error: {e}"})
        except Exception as e:
            results.append({"url": str(url), "error": f"other_error: {e}"})


def can_fetch_robots(base_url, path):
    """Respect robots.txt using urllib.robotparser"""
    try:
        parsed = urlparse(base_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        rp = urllib.robotparser.RobotFileParser()
        rp.set_url(robots_url)
        rp.read()
        return rp.can_fetch("*", urljoin(base_url, path))
    except Exception:
        # If robots.txt unreadable, allow by default (conservative choice)
        return True


async def scan_target(base_url, paths, concurrency=CONCURRENCY, verify_ssl=False):
    sem = asyncio.Semaphore(concurrency)
    results = []
    timeout = aiohttp.ClientTimeout(total=TIMEOUT)
    # Note: ssl=False used previously to avoid cert issues; in production consider True
    connector = aiohttp.TCPConnector(limit=0, ssl=verify_ssl)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        tasks = []
        for p in paths:
            url = urljoin(base_url.rstrip("/") + "/", p.lstrip("/"))
            if not can_fetch_robots(base_url, p):
                results.append({"url": url, "skipped": "disallowed_by_robots_txt"})
                continue
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            tasks.append(fetch(session, url, headers, sem, results))
        if tasks:
            await asyncio.gather(*tasks)
    return results


# -------------------
# Flask routes
# -------------------

INDEX_HTML = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Endpoint Scanner — UA Toolkit</title>
<style>
  :root{--bg:#071019;--card:#0b1620;--muted:#9aa7b2;--accent:#00f5d4;--danger:#ff6b6b;}
  body{background:linear-gradient(180deg,#031018 0%, #071b2a 100%);color:#e6f0f6;font-family:Inter,ui-sans-serif,system-ui,Segoe UI,Roboto,'Helvetica Neue',Arial;margin:0;padding:24px}
  .container{max-width:980px;margin:0 auto}
  header{display:flex;align-items:center;gap:12px;margin-bottom:18px}
  .logo{width:56px;height:56px;border-radius:8px;background:linear-gradient(135deg,#05202b,#06323f);display:flex;align-items:center;justify-content:center;font-weight:700;color:var(--accent);box-shadow:0 6px 18px rgba(0,0,0,.6)}
  h1{margin:0;font-size:20px}
  p.sub{color:var(--muted);margin:4px 0 0;font-size:13px}
  .card{background:var(--card);border-radius:10px;padding:16px;margin-bottom:14px;box-shadow:0 8px 30px rgba(2,12,20,.6)}
  .form-row{display:flex;gap:8px}
  input[type="text"]{flex:1;padding:10px 12px;border-radius:8px;border:1px solid rgba(255,255,255,.04);background:#071a24;color:#dff7f0;outline:none}
  button{background:var(--accent);border:none;padding:10px 14px;border-radius:8px;color:#012226;font-weight:700;cursor:pointer}
  button[disabled]{opacity:.6;cursor:default}
  .meta{font-size:13px;color:var(--muted);margin-top:8px}
  .results{margin-top:12px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{padding:8px 10px;text-align:left;border-bottom:1px solid rgba(255,255,255,.03)}
  th{color:var(--muted);font-size:12px}
  .status-200{color:#00d27a;font-weight:700}
  .status-3xx{color:#ffd166;font-weight:700}
  .status-4xx{color:#ff6b6b;font-weight:700}
  .status-5xx{color:#ff9f1c;font-weight:700}
  .small{font-size:12px;color:var(--muted)}
  .spinner{width:18px;height:18px;border-radius:50%;border:3px solid rgba(255,255,255,.06);border-top-color:var(--accent);animation:spin 1s linear infinite;display:inline-block;vertical-align:middle}
  @keyframes spin{to{transform:rotate(360deg)}}
  .controls{display:flex;gap:8px;margin-top:8px;align-items:center}
  .download{background:transparent;border:1px solid rgba(255,255,255,.06);color:var(--muted);padding:6px 10px;border-radius:8px;cursor:pointer}
  footer{color:var(--muted);font-size:12px;margin-top:20px;text-align:center}
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="logo">UA</div>
    <div>
      <h1>Endpoint Scanner • UA Toolkit</h1>
      <p class="sub">Enter a domain or full URL (only scan permitted targets). Results show below.</p>
    </div>
  </header>

  <div class="card">
    <div style="display:flex;flex-direction:column;gap:8px">
      <div class="form-row">
        <input id="target" type="text" placeholder="https://example.com or example.com"/>
        <button id="scanBtn">Scan</button>
      </div>
      <div class="controls">
        <label class="small"><input id="useDefault" type="checkbox" checked/> Use default wordlist</label>
        <label class="small" style="margin-left:12px">Concurrency:
          <select id="concurrency">
            <option>6</option><option selected>10</option><option>20</option>
          </select>
        </label>
        <div style="flex:1"></div>
        <div id="status" class="small">Idle</div>
      </div>
      <div class="meta">This tool respects robots.txt. Scan only permitted targets. Results are not stored server-side permanently.</div>
    </div>
  </div>

  <div id="resultsCard" class="card" style="display:none">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <div><strong>Scan results</strong> <span class="small" id="summary"></span></div>
      <div>
        <button id="downloadBtn" class="download">Download JSON</button>
      </div>
    </div>
    <div class="results" id="resultsArea">
      <!-- table injected here -->
    </div>
  </div>

  <footer>Use responsibly — do not scan without permission.</footer>
</div>

<script>
const scanBtn = document.getElementById('scanBtn');
const statusEl = document.getElementById('status');
const resultsCard = document.getElementById('resultsCard');
const resultsArea = document.getElementById('resultsArea');
const summaryEl = document.getElementById('summary');
const downloadBtn = document.getElementById('downloadBtn');

function normalizeUrl(input) {
  if (!input) return '';
  try {
    // try to construct a URL object
    const u = new URL(input);
    return u.origin + u.pathname;
  } catch (e) {
    // if missing scheme, try https
    try {
      const u2 = new URL('https://' + input);
      return u2.origin + u2.pathname;
    } catch (e2) {
      return input;
    }
  }
}

scanBtn.addEventListener('click', async () => {
  const raw = document.getElementById('target').value.trim();
  if (!raw) return alert('Enter a target URL or domain');
  const target = normalizeUrl(raw);
  const useDefault = document.getElementById('useDefault').checked;
  const concurrency = parseInt(document.getElementById('concurrency').value || '10', 10);

  // UI
  scanBtn.disabled = true;
  statusEl.innerHTML = '<span class="spinner"></span> Scanning...';
  resultsCard.style.display = 'none';
  resultsArea.innerHTML = '';

  try {
    const resp = await fetch('/api/scan', {
      method: 'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ target, use_default: useDefault, concurrency })
    });
    if (!resp.ok) {
      const txt = await resp.text();
      throw new Error('Server error: ' + txt);
    }
    const data = await resp.json();
    renderResults(data);
  } catch (err) {
    statusEl.textContent = 'Error: ' + err.message;
  } finally {
    scanBtn.disabled = false;
  }
});

downloadBtn.addEventListener('click', () => {
  const txt = resultsArea.getAttribute('data-json');
  if (!txt) return;
  const blob = new Blob([txt], {type:'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'scan_results.json';
  a.click();
  URL.revokeObjectURL(url);
});

function renderResults(data) {
  resultsCard.style.display = 'block';
  summaryEl.textContent = `• checked ${data.checked || 0} paths • took ${data.duration_s.toFixed(2)}s`;
  statusEl.textContent = 'Done';

  const rows = data.results || [];
  // store JSON for download
  const jsonText = JSON.stringify(data.results, null, 2);
  resultsArea.setAttribute('data-json', jsonText);

  if (rows.length === 0) {
    resultsArea.innerHTML = '<div class="small">No results</div>';
    return;
  }

  let html = '<table><thead><tr><th>Status</th><th>URL</th><th>Final URL</th><th>Server</th><th>Length</th></tr></thead><tbody>';
  for (const r of rows) {
    if (r.skipped) {
      html += `<tr><td class="small">SKIP</td><td colspan="4" class="small">${r.url} (${r.skipped})</td></tr>`;
      continue;
    }
    if (r.error) {
      html += `<tr><td class="small">ERR</td><td colspan="4" class="small">${r.url} → ${r.error}</td></tr>`;
      continue;
    }
    const s = r.status;
    let cls = 'status-4xx';
    if (s >= 200 && s < 300) cls = 'status-200';
    else if (s >= 300 && s < 400) cls = 'status-3xx';
    else if (s >= 500) cls = 'status-5xx';
    html += `<tr>
      <td class="${cls}">${s}</td>
      <td><div class="small">${r.url}</div></td>
      <td class="small">${r.final_url || ''}</td>
      <td class="small">${r.server || ''}</td>
      <td class="small">${r.content_length === null ? '-' : r.content_length}</td>
    </tr>`;
  }
  html += '</tbody></table>';
  resultsArea.innerHTML = html;
}
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(INDEX_HTML)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    Expects JSON: { "target": "https://example.com", "use_default": true, "concurrency": 10, "paths": ["..."] }
    Returns JSON: { results: [...], checked: N, duration_s: X }
    """
    data = request.get_json() or {}
    target = data.get("target")
    if not target:
        return jsonify({"error": "target is required"}), 400

    # normalize: ensure scheme exists
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target

    # choose paths
    use_default = data.get("use_default", True)
    user_paths = data.get("paths")
    if use_default or not user_paths:
        paths = DEFAULT_WORDLIST.copy()
    else:
        # sanitize user supplied paths
        paths = [p.strip() for p in user_paths if p and isinstance(p, str)]

    concurrency = int(data.get("concurrency") or CONCURRENCY)
    concurrency = max(1, min(50, concurrency))

    # run the async scan
    start = time.time()
    try:
        results = asyncio.run(scan_target(target, paths, concurrency=concurrency, verify_ssl=False))
    except Exception as e:
        return jsonify({"error": f"scan failed: {e}"}), 500
    duration = time.time() - start

    # don't keep results server-side permanently (returned to client)
    response = {"results": results, "checked": len(paths), "duration_s": duration}
    return jsonify(response)


if __name__ == "__main__":
    # For local testing only. On Render use gunicorn as start command.
    app.run(host="0.0.0.0", port=5000, debug=True)
