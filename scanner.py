#!/usr/bin/env python3
"""
endpoint_scanner.py
Safe-ish async endpoint scanner for permitted targets.
Usage: python endpoint_scanner.py target.com
"""

import asyncio
import aiohttp
import sys
import json
from urllib.parse import urljoin, urlparse
import urllib.robotparser
import time
import random
import platform

if platform.system() == "Windows":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# Basic user-agents list (add more if needed)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    "curl/8.0.1",
    "python-requests/2.31.0"
]

# Small default wordlist of common endpoints (safe; avoid sensitive file probing)
DEFAULT_WORDLIST = [
    "/", "index.html", "home", "login", "logout", "admin", "dashboard",
    "user", "api/", "api/v1/", "status", "health", "ping",
    "robots.txt", "sitemap.xml", "favicon.ico", ".well-known/security.txt",
    "wp-login.php", "wp-admin", "admin/login", "config", ".well-known/assetlinks.json"
]

# Config
TIMEOUT = 10  # seconds
CONCURRENCY = 10
DELAY_BETWEEN_REQUESTS = 0.2  # seconds (per request delay to avoid hammering)


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
                # small polite delay
                await asyncio.sleep(DELAY_BETWEEN_REQUESTS + random.random() * 0.1)
        except asyncio.TimeoutError:
            results.append({"url": str(url), "error": "timeout"})
        except aiohttp.ClientResponseError as e:
            results.append({"url": str(url), "error": f"response_error: {e}"})
        except aiohttp.ClientError as e:
            # network errors, SSL errors etc.
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
        # if robots.txt unreadable, be conservative and allow (or choose to disallow — here we allow)
        return True


async def scan_target(base_url, paths, concurrency=CONCURRENCY):
    sem = asyncio.Semaphore(concurrency)
    results = []
    timeout = aiohttp.ClientTimeout(total=TIMEOUT)
    connector = aiohttp.TCPConnector(limit=0, ssl=False)  # limit=0 => no connector-level limit
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        tasks = []
        for p in paths:
            # build absolute url
            url = urljoin(base_url.rstrip("/") + "/", p.lstrip("/"))
            # check robots.txt
            if not can_fetch_robots(base_url, p):
                # skip if disallowed
                results.append({"url": url, "skipped": "disallowed_by_robots_txt"})
                continue
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            tasks.append(fetch(session, url, headers, sem, results))
        # run all tasks with graceful handling
        await asyncio.gather(*tasks)
    return results


def load_wordlist_from_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            return lines
    except Exception:
        return None


def save_results(results, filename="results.json"):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)


def pretty_print(results):
    for r in results:
        if "status" in r:
            print(f"[{r['status']}] {r['url']} -> {r.get('final_url','')}, server={r.get('server')}, len={r.get('content_length')}")
        elif "skipped" in r:
            print(f"[SKIP] {r['url']} ({r['skipped']})")
        else:
            print(f"[ERR] {r['url']} -> {r.get('error')}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python endpoint_scanner.py target_url [wordlist_file]")
        print("Example: python endpoint_scanner.py https://example.com endpoints.txt")
        sys.exit(1)

    base_url = sys.argv[1]
    wordlist_file = sys.argv[2] if len(sys.argv) > 2 else None

    paths = DEFAULT_WORDLIST.copy()
    if wordlist_file:
        wl = load_wordlist_from_file(wordlist_file)
        if wl:
            paths = wl
        else:
            print("Could not read wordlist file; using default list.")

    start = time.time()
    results = asyncio.run(scan_target(base_url, paths))
    duration = time.time() - start

    pretty_print(results)
    save_results(results)
    print(f"\nDone. Checked {len(paths)} paths in {duration:.2f}s. Results saved to results.json")


if __name__ == "__main__":
    main()
