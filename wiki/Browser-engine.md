# Browser Engine

The `--browser` flag adds a headless Chromium pass after the standard scan.

```bash
pip install stingxss[browser]
stingxss -u "https://target.com/#/search?q=test" --browser
```

Requires Chromium and chromedriver. On most systems they are already on `$PATH`.

## What it does

- Injects payloads via Selenium and intercepts `alert()` / `confirm()` / `prompt()` calls using a CDP script hook — **before** the page navigates, so framework sanitisation can't hide it
- Auto-discovers hash-fragment parameters (`#/search?q=`) that are invisible to HTTP-layer scanners
- Tests stored XSS by injecting via headers/params then revisiting candidate pages in the browser
- Marks every finding `[CONFIRMED]` — the JavaScript actually executed

## When to use it

| Scenario | Use browser? |
|----------|-------------|
| Fast reflected XSS triage | No — default scan is enough |
| JavaScript-heavy SPA with hash routes | Yes |
| Need execution proof, not just reflection | Yes |
| CI pipeline on a budget | No — adds time and requires Chromium |
| Stored XSS confirmation | Yes |

## Custom binary paths

```bash
stingxss -u "https://target.com/" --browser \
  --browser-chromium /usr/bin/chromium \
  --browser-chromedriver /usr/local/bin/chromedriver
```

## Visible window (debug mode)

```bash
stingxss -u "https://target.com/" --browser --no-browser-headless
```
