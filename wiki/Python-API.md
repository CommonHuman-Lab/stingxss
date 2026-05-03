# Python API

```bash
pip install stingxss
pip install stingxss[browser]  # optional — for browser confirmation
```

## Basic usage

```python
from stingxss import scan

result = scan("https://target.com/search?q=test")
print(f"{result.total_findings} finding(s) in {result.duration_s:.1f}s")
```

## Full options

```python
from stingxss import scan, ScanOptions

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
```

## Reading results

```python
for f in result.reflected:
    print(f"[{'CONFIRMED' if f.confirmed else 'REFLECTED'}] {f.parameter} @ {f.url}")

for d in result.dom:
    print(f"[DOM] {d.source} → {d.sink} @ {d.url}:{d.line}")

for b in result.browser:
    print(f"[BROWSER XSS CONFIRMED] {b.parameter} @ {b.url}")
```

## ScanOptions reference

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `level` | int | `1` | Payload depth 1–3 |
| `crawl` | bool | `False` | BFS crawler |
| `threads` | int | `5` | Worker threads (1–20) |
| `blind_callback` | str | `None` | OOB callback URL |
| `headers` | dict | `{}` | Custom request headers |
| `cookies` | str | `None` | Cookie string |
| `delay` | float | `0` | Seconds between requests |
| `output` | str | `None` | JSON output file path |
| `exclude_patterns` | list | `[]` | Regex patterns to skip |
| `inject_headers` | list | `[]` | Header names to test |
| `browser` | bool | `False` | Enable headless Chromium pass |
| `proxy` | str | `None` | HTTP proxy URL |
| `timeout` | int | `15` | Request timeout seconds |
