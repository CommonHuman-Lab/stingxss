# StingXSS

**Context-aware XSS scanner** — reflected, DOM, stored, and confirmed browser XSS with WAF detection and evasion. No Burp license. Just findings.

```bash
pip install stingxss
pip install stingxss[browser]  # + headless browser engine
```

> Point it at a target. Get findings. Drop it in a pipeline.

---

## Quick start

```bash
# Reflected XSS on a parameter
stingxss -u "https://target.com/search?q=test"

# Confirm DOM XSS in a JavaScript-heavy SPA with a real browser
stingxss -u "https://target.com/#/search?q=test" --browser

# Full crawl + deep payload set + JSON report
stingxss -u "https://target.com/" --crawl --level 3 -o results.json

# Blind XSS via interactsh
stingxss -u "https://target.com/comment" --blind "https://xyz.oast.me"

# POST form with session cookie
stingxss -u "https://target.com/login" -d "user=test&pass=test" -c "session=abc"

# Header injection (Referer, X-Forwarded-For, True-Client-IP, etc.)
stingxss -u "https://target.com/" --inject-headers Referer --inject-headers X-Forwarded-For

# Bulk scan from a URL list
stingxss -L urls.txt --level 2 --crawl -o results.json

# Through a proxy, rate-limited, verbose
stingxss -u "https://target.com/search?q=x" --proxy http://127.0.0.1:8080 --delay 0.5 -v
```

Run with **no arguments** for interactive wizard mode.

---

## CLI flags

| Flag | Description |
|------|-------------|
| `-u URL` | Target URL |
| `-L FILE` | File of URLs, one per line |
| `-V` | Print version and exit |
| `--crawl` | BFS crawler (same-origin) |
| `--blind URL` | Blind XSS callback (interactsh / Burp Collaborator) |
| `-d DATA` | POST body (form-encoded or JSON) |
| `-H KEY:VALUE` | Custom request header (repeatable) |
| `-c COOKIE` | Cookie string |
| `--proxy URL` | HTTP proxy |
| `-t N` | Worker threads 1–20 (default: 5) |
| `--timeout N` | Request timeout in seconds (default: 15) |
| `--delay N` | Seconds between requests (default: 0) |
| `--level 1-3` | Payload depth — 1=fast, 2=thorough, 3=deep (default: 1) |
| `-f FILE` | Custom payloads file, one per line |
| `--max-pages N` | Max pages to crawl (default: 50) |
| `--max-depth N` | Max crawl depth (default: 3) |
| `--exclude PATTERN` | Regex of URLs to skip (repeatable) |
| `--inject-headers HEADER` | Header names to test for XSS reflection (repeatable) |
| `-o FILE` | Write JSON results to file |
| `--json` | Print raw JSON to stdout |
| `-q` | Quiet — suppress all output except errors |
| `-v` | Verbose — show all checks including clean ones |
| `--browser` | Headless browser XSS scan — confirms execution in real Chromium |
| `--no-browser-headless` | Run browser with visible window |
| `--browser-chromium PATH` | Path to Chromium binary (default: auto-detect) |
| `--browser-chromedriver PATH` | Path to chromedriver binary (default: auto-detect) |
| `--dom-include-minified` | Include app bundles (main.js, vendor.js) in DOM analysis |

**Exit codes:** `0` = clean · `1` = findings · `2` = error

---

## What it finds

| Capability | Details |
|-----------|---------|
| **Reflected XSS** | Unique probe markers per scan, reflection context detection, context-aware payloads |
| **Confirmed Browser XSS** | Headless Chromium intercepts `alert()` / `confirm()` calls — no false positives |
| **DOM XSS** | Static source-to-sink flow analysis — 16 sources, 25+ sinks, no browser needed |
| **Blind XSS** | OOB callback variants across crawled forms |
| **Header injection** | Tests arbitrary request headers for XSS reflection and stored execution |
| **SPA / hash-route support** | Discovers and tests `#/path?param=` parameters invisible to the HTTP layer |
| **12 HTML/JS contexts** | `html_body`, `attr_*`, `script_string/bare/template`, `event_handler`, `url_attr`, `css`, `html_comment` |
| **WAF fingerprinting** | Cloudflare, Akamai, Imperva, AWS WAF, ModSecurity, Sucuri, F5 BIG-IP, Barracuda, Wordfence, FortiWeb |
| **WAF evasion** | 9 transforms auto-rotated: case mixing, HTML encode, Unicode escape, double URL encode, chunked tags, null byte, newline inject, comment break, backtick attr |
| **CORS misconfiguration** | Dynamic reflection, startsWith/endsWith/regex bypasses, credential exposure |
| **Crawler** | Multi-threaded BFS, same-origin, captures hidden inputs |
| **External JS** | Fetches and analyses `<script src>` files for DOM XSS |
| **Bulk scanning** | `--url-list` scans a whole target list in one shot |

---

## Browser engine

The `--browser` flag adds a headless Chromium pass after the standard scan. It:

- Injects payloads via Selenium and intercepts `alert()` / `confirm()` / `prompt()` calls using a CDP script hook — **before** the page navigates, so framework sanitisation can't hide it
- Auto-discovers hash-fragment parameters (`#/search?q=`) that are invisible to HTTP-layer scanners
- Tests stored XSS by injecting via headers/params then revisiting candidate pages in the browser
- Marks every finding `[CONFIRMED]` — the JavaScript actually executed

```bash
pip install stingxss[browser]
stingxss -u "https://target.com/#/search?q=test" --browser
```

Requires Chromium and chromedriver. On most systems they are already on `$PATH`.

---

## Python API

```python
from stingxss import scan, ScanOptions

result = scan("https://target.com/search?q=test")

opts = ScanOptions(
    level=2,
    crawl=True,
    threads=10,
    blind_callback="https://xyz.oast.me",
    headers={"Authorization": "Bearer token"},
    cookies="session=abc",
    delay=0.3,
    output="out.json",
    exclude_patterns=[r"logout", r"\.pdf$"],
    inject_headers=["Referer", "X-Forwarded-For"],
    browser=True,
)
result = scan("https://target.com/", opts)

print(f"{result.total_findings} finding(s) in {result.duration_s:.1f}s")

for f in result.reflected:
    print(f"[{'CONFIRMED' if f.confirmed else 'REFLECTED'}] {f.parameter} @ {f.url}")

for d in result.dom:
    print(f"[DOM] {d.source} → {d.sink} @ {d.url}:{d.line}")

for b in result.browser:
    print(f"[BROWSER XSS CONFIRMED] {b.parameter} @ {b.url}")
```

---

## Why not just use X?

Most XSS scanners spray generic payloads and hope something sticks. StingXSS:

- **Reads context first** — `<script>` blocks, attribute values, template literals, event handlers, and URL attributes all get tailored payloads.
- **Confirms execution** — checks if the injected tag ran, not just reflected. The browser engine intercepts actual `alert()` calls.
- **Finds what HTTP scanners miss** — hash-fragment SPA routes (`#/path?param=`) are invisible to every scanner that only looks at HTTP requests.
- **Evades WAFs automatically** — rotates 9 encoding transforms when a straight payload is blocked.
- **No browser required for most scans** — DOM XSS via static analysis, runs anywhere Python runs. Add `[browser]` only when you need execution proof.
- **Pipeline-native** — JSON output, clean exit codes, Python API.

---

## Install from source

```bash
git clone https://github.com/CommonHuman-Lab/stingxss.git
cd stingxss
pip install -e .
pip install -e ".[browser]"  # optional browser engine
```

Requires Python 3.10+. No C extensions.

---

## License

AGPL-3.0. Run it as a service or distribute it — source stays open.
Commercial licensing: contact the author.
