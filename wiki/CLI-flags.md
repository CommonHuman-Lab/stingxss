# CLI Flags Reference

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
