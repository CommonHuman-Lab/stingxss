# StingXSS

**Context-aware XSS scanner** — reflected, DOM, and blind XSS with WAF detection and evasion, header injection testing, and a crawler that actually finds things.

> Drop it into a pipeline, point it at a target, get findings. No Burp license required.

## Install

```bash
pip install stingxss
```

Requires Python 3.10+. No C extensions, no Selenium — pure Python.

## Quick start

```bash
# Reflected XSS on a parameter
stingxss -u "https://target.com/search?q=test"

# Full crawl, deep payload set, report to JSON
stingxss -u "https://target.com/" --crawl --level 3 -o results.json

# Blind XSS via interactsh
stingxss -u "https://target.com/comment" --blind "https://xyz.oast.me"

# POST form with session cookie
stingxss -u "https://target.com/login" -d "user=test&pass=test" -c "session=abc"

# Header injection (Referer, X-Forwarded-For, etc.)
stingxss -u "https://target.com/" --inject-headers Referer --inject-headers X-Forwarded-For

# Bulk scan from a list of URLs
stingxss -L urls.txt --level 2 --crawl -o results.json

# Through a proxy, rate-limited
stingxss -u "https://target.com/search?q=x" --proxy http://127.0.0.1:8080 --delay 0.5
```

Run with **no arguments** to enter interactive wizard mode.

## CLI options

| Flag | Description |
|------|-------------|
| `-u, --url URL` | Target URL |
| `-L, --url-list FILE` | File of target URLs, one per line |
| `-V, --version` | Print version and exit |
| `--crawl` | Enable BFS crawler (same-origin) |
| `--blind URL` | Blind XSS callback URL (interactsh / Burp Collaborator) |
| `-d, --data DATA` | POST body (form-encoded or JSON) |
| `-H KEY:VALUE` | Custom request header (repeatable) |
| `-c, --cookie COOKIE` | Cookie string (`name=val; name2=val2`) |
| `--proxy URL` | HTTP proxy (`http://127.0.0.1:8080`) |
| `-t, --threads N` | Worker threads 1–20 (default: 5) |
| `--timeout N` | Request timeout seconds 5–120 (default: 15) |
| `--delay N` | Seconds between requests (default: 0, e.g. `0.5`) |
| `--level 1-3` | Payload depth — 1=fast, 2=thorough, 3=deep (default: 1) |
| `-f, --payloads FILE` | File with custom payloads, one per line |
| `--max-pages N` | Max pages to crawl (default: 50) |
| `--max-depth N` | Max crawl depth (default: 3) |
| `--exclude PATTERN` | Regex of URLs to skip (repeatable) |
| `--inject-headers HEADER` | Header name(s) to test for XSS reflection (repeatable) |
| `-o, --output FILE` | Write JSON results to file |
| `--json` | Print raw JSON to stdout |
| `-q, --quiet` | Suppress live log output |

**Exit codes:** `0` = clean, `1` = findings, `2` = error.

## Library API

```python
from stingxss import scan, ScanOptions

# One-liner
result = scan("https://target.com/search?q=test")

# Full control
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
)
result = scan("https://target.com/", opts)

print(f"Found {result.total_findings} finding(s) in {result.duration_s:.1f}s")

for f in result.reflected:
    status = "CONFIRMED" if f.confirmed else "REFLECTED"
    print(f"[{status}] {f.parameter} @ {f.url}")

for d in result.dom:
    print(f"[DOM] {d.source} → {d.sink} @ {d.url}:{d.line}")

# JSON-serialisable dict
import json
print(json.dumps(result.to_dict(), indent=2))
```

## Detection capabilities

| Feature | Details |
|---------|---------|
| **Reflected XSS** | Unique per-scan probe markers, reflection context detection, context-aware payload generation |
| **DOM XSS** | Static analysis with proximity + variable-flow tracking — 16 sources, 25 sinks |
| **Blind XSS** | 6 out-of-band callback variants; covers crawled forms, not just seed URL |
| **Header injection** | Tests arbitrary request headers (Referer, X-Forwarded-For, custom) for XSS reflection |
| **Context detection** | 12 HTML/JS contexts: `html_body`, `attr_double/single/unquoted`, `script_string/bare`, `script_template`, `event_handler`, `url_attr`, `css`, `html_comment` |
| **WAF detection** | Fingerprints 10 WAFs: Cloudflare, Akamai, Imperva, AWS WAF, ModSecurity, Sucuri, F5 BIG-IP, Barracuda, Wordfence, FortiWeb |
| **WAF evasion** | 9 transforms rotated until confirmed: case mixing, HTML encode, Unicode escape, double URL encode, chunked tags, null byte, newline inject, comment break, backtick attr |
| **Crawler** | Multi-threaded BFS, same-origin, hidden input capture, configurable depth/pages |
| **External JS** | Fetches and analyses `<script src="...">` files for DOM XSS |
| **Content-type aware** | Skips HTML payload injection on JSON responses |
| **Bulk scanning** | `--url-list` for scanning lists of targets in one shot |

## Why StingXSS?

Most XSS scanners either spray generic payloads and hope something sticks, or require a full browser. StingXSS:

- **Detects context first**, then generates payloads that fit — `<script>` blocks, attribute values, template literals, event handlers, and URL attributes all get different payloads.
- **Confirms findings** by checking if the injected tag actually executed, not just reflected.
- **Evades WAFs automatically** by rotating through 9 encoding transforms when a straight payload is blocked.
- **Finds DOM sinks** without a browser via static source-to-sink flow analysis.
- **Fits in a pipeline** — JSON output, exit codes, and a Python API make it easy to automate.

## License

Licensed under AGPL-3.0. If you run it as a service or distribute it, the source must remain open.
For commercial licensing, contact the author.
