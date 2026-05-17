# StingXSS

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![PyPI](https://img.shields.io/pypi/v/stingxss.svg)](https://pypi.org/project/stingxss/)
[![License](https://img.shields.io/badge/License-AGPLv3-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-XSS%20Scanner-red.svg)](https://github.com/CommonHuman-Lab/stingxss)
[![Browser](https://img.shields.io/badge/Browser-Chromium-blueviolet.svg)](https://github.com/CommonHuman-Lab/stingxss/wiki/Browser-engine)
[![WAF Evasion](https://img.shields.io/badge/WAF%20Evasion-built--in-orange.svg)](https://github.com/CommonHuman-Lab/stingxss)

**The context-aware XSS scanner** — reflected, DOM, stored, blind, and browser-confirmed XSS with WAF evasion, CRLF injection, XST, and PoC generation. No Burp license. Just findings.

```bash
# Kali / Debian / Ubuntu — venv required on externally-managed Python
python3 -m venv .venv && source .venv/bin/activate
pip install stingxss
pip install stingxss[browser]  # + headless browser engine

# Use against target/firerange
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

## Why StingXSS

Most XSS scanners fire generic payloads and check for reflection. StingXSS goes further at every step:

**Context first.** Before injecting a single payload, StingXSS classifies exactly where the input lands — inside a `<script>` block, a double-quoted attribute, a template literal, an Angular expression, a CSS value. The payloads sent are chosen for that specific context, not sprayed blindly.

**Smarter, not just more.** Filter-probing runs automatically on every reflected parameter: one extra request maps which special characters the server encodes or strips, then only payloads that can actually work in that environment are tried. Fewer requests, higher signal.

**Confirmed, not assumed.** Reflection is a hint. Execution is a finding. The headless Chromium engine intercepts actual `alert()` and `confirm()` calls via Chrome DevTools Protocol — if the JavaScript didn't run, it's not reported as confirmed.

**Finds what HTTP scanners miss.** Single-page apps expose routes through hash fragments (`#/search?q=`). StingXSS discovers and tests those. Static DOM analysis (28 sources × 43 sinks) catches DOM XSS without a browser, in any CI environment.

**From finding to PoC in one step.** `--poc` generates ready-to-use exploitation payloads — cookie-stealers, localStorage exfil, stealth wrappers — for every confirmed finding.

**Pipeline-native.** JSON output, clean exit codes, a Python API. Drop it into a CI job, chain it with other tools, or call it from a script.

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

# Dork DuckDuckGo to discover targets, then scan them all
stingxss --dork "site:example.com inurl:search" --level 2

# Chain evasion transforms manually (overrides WAF auto-detect)
stingxss -u "https://waf.example.com/search?q=test" --evasion unicode,case

# Randomise payload order to evade sequential-pattern WAF rate limiting
stingxss -u "https://target.com/search?q=test" --randomize-payloads

# Load extra payload files (repeatable, supports {marker} template)
stingxss -u "https://target.com/search?q=test" -f my_payloads.txt -f community.txt

# Authenticate before scanning
stingxss -u "https://target.com/dashboard" --login-url "https://target.com/login" \
  --login-user admin --login-pass secret

# Import all endpoints from an OpenAPI / Swagger spec
stingxss -u "https://target.com/" --openapi https://target.com/openapi.json

# Discover JS-rendered endpoints first, then scan everything
stingxss -u "https://target.com/" --browser-crawl --level 2

# Generate ready-to-use PoC payloads for confirmed findings
stingxss -u "https://target.com/search?q=test" --poc

# Thorough scan with PoC output
stingxss -u "https://target.com/" --crawl --level 2 --browser --poc -o results.json
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
| **Blind XSS** | 10 OOB callback variants across crawled forms |
| **Stored XSS** | Inject via params/headers, revisit candidate pages to confirm execution |
| **CRLF / HTTP Response Splitting** | 6 CRLF sequence variants injected into params and reflected headers |
| **Cross-Site Tracing (XST)** | TRACE method detection — HttpOnly cookie exfil via CAPEC-107 |
| **Header injection** | Arbitrary headers tested for reflection and stored execution |
| **SPA / hash-route support** | Discovers `#/path?param=` invisible to HTTP-layer scanners |
| **28 HTML/JS contexts** | `html_body`, `attr_*`, `script_string/bare/template`, `event_handler`, `url_attribute`, `css`, `html_comment`, Angular/Vue templates + more |
| **WAF fingerprinting** | Cloudflare, Akamai, Imperva, AWS WAF, ModSecurity, Sucuri, F5 BIG-IP, Barracuda, Wordfence, FortiWeb |
| **WAF evasion** | 12 transforms: case mixing, HTML encode, Unicode escape, double URL encode, chunked tags, null byte, newline inject, comment break, backtick attr, CSS expression, **String.fromCharCode**, **unescape()** |
| **data: URI payloads** | Plain and base64-encoded `data:text/html`, `data:image/svg+xml`, XHTML, meta-refresh, SVG `use href`, iframe variants |
| **CORS misconfiguration** | Dynamic reflection, bypass patterns, credential exposure — 7 patterns |
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

## Smart scanning by default

**Filter probing** runs automatically on every reflected parameter. Before injecting XSS payloads, stingxss sends a single probe to map which special characters (`<>'"\/;=()`) the server encodes or strips. Payloads that require blocked characters are skipped — fewer requests, fewer false starts, faster results.

Disable with `--no-probe-filter` if you need raw coverage with no pre-probing.

---

## PoC generation

After finding confirmed XSS, `--poc` prints ready-to-use exploitation payloads:

```bash
stingxss -u "https://target.com/search?q=test" --poc
```

---

## WAF evasion

StingXSS detects WAFs and applies the right transforms automatically:

```bash
stingxss -u "https://waf-protected.com/search?q=test" -v
# [*] WAF detected: Cloudflare (confidence: high)
# [*] Evasion strategy: unicode_escape
```

Override with a manual chain using `--evasion` — transforms are applied left to right:

```bash
# Apply unicode escape, then case-mixing, to every payload
stingxss -u "https://target.com/search?q=test" --evasion unicode,case

# Available names: case, html, unicode, double, chunked, null,
#                  newline, comment, backtick, css, fromcharcode, unescape
```

Combine with `--randomize-payloads` to shuffle injection order and break sequential-pattern WAF rate limiting.

---

## Target discovery via dorking

`--dork` queries DuckDuckGo and prepends the discovered URLs to the target list before scanning. No API key required.

```bash
# Discover injectable search pages on a domain, then scan them
stingxss --dork "site:example.com inurl:search"

# Combine with crawling for thorough coverage
stingxss --dork "inurl:q= filetype:php" --crawl --level 2 -o results.json

# Limit result count (default 20)
stingxss --dork "site:example.com inurl:id=" --dork-max 50
```

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

# Access specific finding types
for f in result.reflected:
    print(f.url, f.parameter, f.context, f.confirmed)
for f in result.crlf:
    print(f.url, f.parameter, f.vector)
for f in result.xst:
    print(f.url, f.reason)
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
