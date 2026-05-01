# StingXSS

Context-aware reflected, DOM, and blind XSS scanner with WAF detection and evasion.

## Install

```bash
pip install stingxss
```

## CLI Usage

```bash
# Basic scan
stingxss -u "https://target.com/search?q=test"

# Deep scan with crawler
stingxss -u "https://target.com/search?q=test" --level 3 --crawl

# POST form scan
stingxss -u "https://target.com/login" -d "user=test&pass=test"

# With custom headers and cookies
stingxss -u "https://target.com/search?q=x" -H "X-Token: abc" -c "session=xyz"

# Blind XSS (interactsh or similar)
stingxss -u "https://target.com/comment" --blind "https://your.interactsh.io"

# Write results to JSON file
stingxss -u "https://target.com/search?q=x" --json -o results.json

# Rate-limited scan through a proxy
stingxss -u "https://target.com/search?q=x" --delay 0.5 --proxy http://127.0.0.1:8080
```

## CLI Options

| Flag | Description |
|------|-------------|
| `-u, --url` | Target URL (required) |
| `--crawl` | Enable BFS crawler |
| `--blind URL` | Blind XSS callback URL |
| `-d, --data` | POST body (form-encoded or JSON) |
| `-H KEY:VALUE` | Custom header (repeatable) |
| `-c, --cookie` | Cookie string (`name=val; name2=val2`) |
| `--proxy URL` | HTTP proxy (e.g. `http://127.0.0.1:8080`) |
| `-t, --threads N` | Worker threads (default: 5, max: 20) |
| `--timeout N` | Request timeout in seconds (default: 15) |
| `--delay N` | Seconds between requests, e.g. `0.5` (default: 0) |
| `--level 1-3` | Payload depth — 1=fast, 2=thorough, 3=deep (default: 1) |
| `-f, --payloads FILE` | File with custom payloads, one per line |
| `--max-pages N` | Max pages to crawl (default: 50) |
| `--max-depth N` | Max crawl depth (default: 3) |
| `-o, --output FILE` | Write JSON results to this file |
| `--json` | Print raw JSON output to stdout |
| `-q, --quiet` | Suppress live log output |

Run with no arguments to enter **interactive wizard mode**.

## Library API

```python
from stingxss import scan, ScanOptions

# Simple scan
result = scan("https://target.com/search?q=test")

# Full options
opts = ScanOptions(
    level=2,
    crawl=True,
    threads=10,
    blind_callback="https://your.interactsh.io",
    headers={"Authorization": "Bearer token"},
    cookies="session=abc",
    delay=0.3,          # 300ms between requests
    output="out.json",  # also write JSON to file
)
result = scan("https://target.com/", opts)

print(f"Found {result.total_findings} finding(s) in {result.duration_s}s")
for f in result.reflected:
    print(f"[{'CONFIRMED' if f.confirmed else 'REFLECTED'}] {f.parameter} @ {f.url}")
for d in result.dom:
    print(f"[DOM] {d.source} → {d.sink} @ {d.url}:{d.line}")

# JSON-serialisable dict
import json
print(json.dumps(result.to_dict(), indent=2))
```

## Detection capabilities

| Feature | Details |
|---------|---------|
| **Reflected XSS** | Injects unique markers, detects reflection context, generates context-aware payloads |
| **DOM XSS** | Static analysis: proximity + variable-flow tracking from 11 sources to 19 sinks |
| **Blind XSS** | 6 out-of-band callback payload variants |
| **Context detection** | 11 HTML/JS contexts: `html_body`, `attr_double/single/unquoted`, `script_string/bare`, `event_handler`, `url_attr`, `css`, `html_comment` |
| **WAF detection** | Fingerprints 10 WAFs: Cloudflare, Akamai, Imperva, AWS WAF, ModSecurity, Sucuri, F5 BIG-IP, Barracuda, Wordfence, FortiWeb |
| **WAF evasion** | 9 transforms: case mixing, HTML encode, Unicode escape, double URL encode, chunked tags, null byte, newline inject, comment break, backtick attr — rotated through all strategies until confirmed |
| **Crawler** | Multi-threaded BFS, same-origin, configurable depth/pages |
| **External JS** | Fetches and analyses `<script src="...">` files for DOM XSS |

## License

Licensed under AGPL-3.0. If you run it as a service or distribute it, the source must remain open.
For commercial licensing, contact the author.
