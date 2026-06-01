# StingXSS

<p align="center">
  <img src="assets/stingxss_logo.png" alt="StingXSS" width="300"/>
</p>

<!-- markdownlint-disable MD033 -->
<p align="center">
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-AGPL--3.0-white?style=for-the-badge&logo=opensourceinitiative&logoColor=black" alt="License">
  </a>
  <a href="https://www.python.org/">
    <img src="https://img.shields.io/badge/Python-3.10+-black?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  </a>
  <img src="https://img.shields.io/badge/XSS-Browser%20Confirmed-white?style=for-the-badge&logo=googlechrome&logoColor=black" alt="XSS Scanner">
  <a href="https://github.com/CommonHuman-Lab/gloomproxy">
    <img src="https://img.shields.io/badge/GloomProxy-Plugin-black?style=for-the-badge" alt="GloomProxy Plugin">
  </a>
</p>
<!-- markdownlint-enable MD033 -->

**The context-aware XSS scanner** — reflected, DOM, stored, blind, and browser-confirmed XSS with WAF evasion, CRLF injection, XST, and PoC generation. No Burp license. Just findings.

```bash
# Kali / Debian / Ubuntu — venv required on externally-managed Python
python3 -m venv .venv && source .venv/bin/activate
pip install stingxss
pip install stingxss[browser]  # + headless browser engine
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
stingxss -u "https://target.com/" --crawl --level 2 -o results.json
stingxss -u "https://target.com/search?q=test" --json | jq .
stingxss -u "https://target.com/search?q=test" --text report.txt
stingxss -u "https://target.com/comment" --blind "https://xyz.oast.me"
stingxss -u "https://target.com/search?q=test" --poc
```

Run with **no arguments** for interactive wizard mode.

→ [Full CLI reference](https://github.com/CommonHuman-Lab/stingxss/wiki/CLI-flags)

---

## What it finds

Reflected, DOM, stored, blind, and browser-confirmed XSS — plus CRLF injection, XST, CORS misconfigurations, prototype pollution, DOM clobbering, clickjacking, HSTS, SRI, JSONP, open redirects, GraphQL and WebSocket injection, and vulnerable client-side libraries. WAF fingerprinting and evasion built in.

→ [Full capabilities table](https://github.com/CommonHuman-Lab/stingxss/wiki/Capabilities)

---

## Documentation

| Topic | Description |
| --- | --- |
| [CLI Flags](https://github.com/CommonHuman-Lab/stingxss/wiki/CLI-flags) | All flags, grouped by function |
| [Capabilities](https://github.com/CommonHuman-Lab/stingxss/wiki/Capabilities) | Every detection type with details |
| [Smart Scanning](https://github.com/CommonHuman-Lab/stingxss/wiki/Smart-Scanning) | Filter probing, scan levels, custom payloads |
| [WAF Evasion](https://github.com/CommonHuman-Lab/stingxss/wiki/WAF-Evasion) | Auto-detection, 12 transforms, manual override |
| [Authentication](https://github.com/CommonHuman-Lab/stingxss/wiki/Authentication) | Form login, HTTP auth, OpenAPI, browser crawl |
| [Output & Reports](https://github.com/CommonHuman-Lab/stingxss/wiki/Output-&-Reports) | PoC, HTML reports, SARIF, JSON, exit codes |
| [Dorking](https://github.com/CommonHuman-Lab/stingxss/wiki/Dorking) | Target discovery via DuckDuckGo / Bing / Yahoo |
| [Browser Engine](https://github.com/CommonHuman-Lab/stingxss/wiki/Browser-engine) | Headless Chromium, confirmed execution |
| [Python API](https://github.com/CommonHuman-Lab/stingxss/wiki/Python-API) | Integration and scripting |
| [Fire Range](https://github.com/CommonHuman-Lab/stingxss/wiki/Fire-Range) | Deliberately vulnerable test lab |

---

## GloomProxy Plugin

StingXSS ships pre-installed with [GloomProxy](https://github.com/CommonHuman-Lab/gloomproxy) and appears in the workspace UI out of the box — no extra setup needed.

---

## Legal & Ethical Use

Only run StingXSS against applications you own or have explicit written authorization to test. Authorized use includes penetration testing engagements, bug bounty programs within defined scope, and CTF competitions.

The authors accept no liability for unauthorized or illegal use.

---

## License

Licensed under the [AGPLv3](LICENSE).
You are free to use, modify, and distribute this software. If you run it as a service or distribute it, the source must remain open.

For commercial licensing, contact the author.
