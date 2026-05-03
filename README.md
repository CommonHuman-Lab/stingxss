# StingXSS

**Context-aware XSS scanner** — reflected, DOM, stored, and confirmed browser XSS with WAF detection and evasion. No Burp license. Just findings.

```bash
pip install stingxss
pip install stingxss[browser]  # + headless browser engine
```

> Point it at a target. Get findings. Drop it in a pipeline.

---

## Why use StingXSS?

- **Reads context first** — `<script>` blocks, attribute values, template literals, event handlers, and URL attributes all get tailored payloads.
- **Confirms execution** — checks if the injected tag ran, not just reflected. The browser engine intercepts actual `alert()` calls.
- **Finds what HTTP scanners miss** — hash-fragment SPA routes (`#/path?param=`) are invisible to every scanner that only looks at HTTP requests.
- **Evades WAFs automatically** — rotates 10 encoding transforms when a straight payload is blocked.
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
