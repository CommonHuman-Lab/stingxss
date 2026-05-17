# StingXSS

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![PyPI](https://img.shields.io/pypi/v/stingxss.svg)](https://pypi.org/project/stingxss/)
[![License](https://img.shields.io/badge/License-AGPLv3-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-XSS%20Scanner-red.svg)](https://github.com/CommonHuman-Lab/stingxss)
[![Browser](https://img.shields.io/badge/Browser-Chromium-blueviolet.svg)](https://github.com/CommonHuman-Lab/stingxss/wiki/Browser-engine)
[![WAF Evasion](https://img.shields.io/badge/WAF%20Evasion-built--in-orange.svg)](https://github.com/CommonHuman-Lab/stingxss)

**Context-aware XSS scanner** — reflected, DOM, stored, and confirmed browser XSS with WAF detection and evasion. No Burp license. Just findings.

```bash
# Kali / Debian / Ubuntu — venv required on externally-managed Python
python3 -m venv .venv && source .venv/bin/activate
pip install stingxss
pip install stingxss[browser]  # + headless browser engine

#Use against target/firerange
stingxss -u "http://127.0.0.1:17477" --browser --crawl --level 2
```

Or from source:

```bash
git clone https://github.com/CommonHuman-Lab/stingxss.git
cd stingxss
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

> Point it at a target. Get findings. Drop it in a pipeline.

---

## Why use StingXSS?

- **Reads context first** — `<script>` blocks, attribute values, template literals, event handlers, and URL attributes all get tailored payloads.
- **Confirms execution** — checks if the injected tag ran, not just reflected. The browser engine intercepts actual `alert()` calls.
- **Finds what HTTP scanners miss** — hash-fragment SPA routes (`#/path?param=`) are invisible to every scanner that only looks at HTTP requests.
- **WAF-aware** — detects common WAFs and applies evasion transforms automatically
- **No browser required for most scans** — DOM XSS via static analysis, runs anywhere Python runs. Add `[browser]` only when you need execution proof.
- **Pipeline-native** — JSON output, clean exit codes, Python API.

---

## Quick start

```bash
stingxss -u "https://target.com/search?q=test"
stingxss -u "https://target.com/#/search?q=test" --browser
stingxss -u "https://target.com/" --crawl --level 3 -o results.json
stingxss -u "https://target.com/comment" --blind "https://xyz.oast.me"
stingxss -u "https://target.com/login" -d "user=test&pass=test" -c "session=abc"
stingxss -u "https://target.com/" --inject-headers Referer --inject-headers X-Forwarded-For
stingxss -L urls.txt --level 2 --crawl -o results.json
stingxss -u "https://target.com/search?q=x" --proxy http://127.0.0.1:8080 --delay 0.5 -v

# Authenticate before scanning
stingxss -u "https://target.com/dashboard" --login-url "https://target.com/login" \
  --login-user admin --login-pass secret

# Import all endpoints from an OpenAPI / Swagger spec
stingxss -u "https://target.com/" --openapi https://target.com/openapi.json

# Discover JS-rendered endpoints first, then scan everything
stingxss -u "https://target.com/" --browser-crawl --level 2
```

Run with **no arguments** for interactive wizard mode.

→ [Full CLI flags reference](https://github.com/CommonHuman-Lab/stingxss/wiki/CLI-flags)

---

## What it finds

| Capability | Details |
|-----------|---------|
| **Reflected XSS** | Unique probe markers, context detection, context-aware payloads |
| **Confirmed Browser XSS** | Headless Chromium intercepts `alert()` / `confirm()` — no false positives |
| **DOM XSS** | Static source-to-sink analysis — 28 sources, 43 sinks, no browser needed |
| **Blind XSS** | OOB callback variants across crawled forms |
| **Stored XSS** | Inject via params/headers, revisit candidate pages to confirm execution |
| **Header injection** | Arbitrary headers tested for reflection and stored execution |
| **SPA / hash-route support** | Discovers `#/path?param=` invisible to HTTP-layer scanners |
| **28 HTML/JS contexts** | `html_body`, `attr_*`, `script_string/bare/template`, `event_handler`, `url_attr`, `css`, `html_comment`, Angular/Vue templates + more |
| **WAF fingerprinting** | Cloudflare, Akamai, Imperva, AWS WAF, ModSecurity, Sucuri, F5 BIG-IP, Barracuda, Wordfence, FortiWeb |
| **WAF evasion** | 10 transforms: case mixing, HTML encode, Unicode escape, double URL encode, chunked tags, null byte, newline inject, comment break, backtick attr, CSS expression |
| **CORS misconfiguration** | Dynamic reflection, bypass patterns, credential exposure |
| **Prototype pollution** | Parameter-based prototype pollution payload injection |
| **DOM clobbering** | Payloads targeting clobberable DOM properties |
| **Clickjacking** | Missing/misconfigured `X-Frame-Options` and `frame-ancestors` |
| **HSTS** | Missing or weak `Strict-Transport-Security` headers |
| **SRI** | `<script>` and `<link>` tags missing `integrity` attributes |
| **JSONP** | Callback parameter detection and exploitation |
| **Mixed content** | HTTPS pages loading HTTP resources |
| **Open redirect** | Parameter-based redirect detection |
| **Vulnerable libraries** | Known CVEs in detected client-side JS libraries |
| **Crawler** | Multi-threaded BFS, same-origin, captures hidden inputs |
| **External JS** | Fetches and analyses `<script src>` files for DOM XSS |
| **Bulk scanning** | `-L` / `--url-list` scans a whole target list in one shot |

---

## Authentication & discovery

```bash
# Form login — authenticate once, scan as the logged-in user
stingxss -u "https://target.com/app" \
  --login-url "https://target.com/login" \
  --login-user admin --login-pass secret

# OpenAPI / Swagger — import every endpoint and scan them all
stingxss -u "https://target.com/" --openapi https://target.com/openapi.json
stingxss -u "https://target.com/" --openapi /path/to/swagger.yaml --base-url https://target.com

# Browser crawl — headless Chromium discovers JS-rendered routes before scanning
# (discovery only — use --browser for XSS execution proof)
stingxss -u "https://target.com/" --browser-crawl --level 2
```

Install optional dependencies as needed:

```bash
pip install stingxss[browser]   # Chromium-based XSS execution + browser-crawl discovery
```

---

## Browser engine

Headless Chromium pass that **confirms** JavaScript execution — not just reflection.

```bash
pip install stingxss[browser]
stingxss -u "https://target.com/#/search?q=test" --browser
```

→ [Browser engine wiki](https://github.com/CommonHuman-Lab/stingxss/wiki/Browser-engine)

---

## Python API

```python
from stingxss import scan, ScanOptions

result = scan("https://target.com/search?q=test")
print(f"{result.total_findings} finding(s) in {result.duration_s:.1f}s")
```

→ [Full API wiki](https://github.com/CommonHuman-Lab/stingxss/wiki/Python-API)

---

## Fire Range

The **StingXSS Fire Range** is a deliberately vulnerable Flask app that ships with [OctoRig](https://github.com/CommonHuman-Lab/OctoRig) (lab slot 8). It provides injectable endpoints that the scanner is verified against on every change.

```bash
# Start the Fire Range (OctoRig required)
./octorig.sh start 8
```

---

## 📜 License

Licensed under the [AGPLv3](LICENSE).
You are free to use, modify, and distribute this software. If you run it as a service or distribute it, the source must remain open.

For commercial licensing, contact the author.
