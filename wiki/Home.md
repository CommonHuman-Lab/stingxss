# StingXSS

[![PyPI](https://img.shields.io/pypi/v/stingxss.svg)](https://pypi.org/project/stingxss/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-AGPLv3-green.svg)](LICENSE)

**Context-aware XSS scanner** — reflected, DOM, stored, and confirmed browser XSS with WAF detection and evasion. No Burp license. Just findings.

```bash
pip install stingxss
pip install stingxss[browser]  # + headless browser engine
```

---

## Quick start

```bash
# Single URL
stingxss -u "https://target.com/search?q=test"

# With browser confirmation (SPA / hash routes)
stingxss -u "https://target.com/#/search?q=test" --browser

# Crawl + deep scan + save results
stingxss -u "https://target.com/" --crawl --level 3 -o results.json

# Blind XSS
stingxss -u "https://target.com/comment" --blind "https://xyz.oast.me"

# POST request with session cookie
stingxss -u "https://target.com/login" -d "user=test&pass=test" -c "session=abc"

# Header injection
stingxss -u "https://target.com/" --inject-headers Referer --inject-headers X-Forwarded-For

# Bulk scan from URL list
stingxss -L urls.txt --level 2 --crawl -o results.json

# Through a proxy with rate limiting
stingxss -u "https://target.com/search?q=x" --proxy http://127.0.0.1:8080 --delay 0.5 -v
```

Run with **no arguments** to launch the interactive wizard.

---

## What it finds

| Capability | Details |
|---|---|
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
| **Open redirect** | Parameter-based redirect detection |
| **Vulnerable libraries** | Known CVEs in detected client-side JS libraries |

---

## Wiki pages

- [CLI Flags Reference](CLI-flags)
- [Browser Engine](Browser-engine)
- [Python API](Python-API)

---

## Requirements

- Python 3.10+
- No C extensions
- Chromium + chromedriver only needed for `--browser`

## Install from source

```bash
git clone https://github.com/CommonHuman-Lab/stingxss.git
cd stingxss
pip install -e .
pip install -e ".[browser]"  # optional browser engine
```

---

Licensed under [AGPLv3](https://github.com/CommonHuman-Lab/stingxss/blob/main/LICENSE). For commercial licensing, contact the author.
