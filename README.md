# StingXSS

Context-aware reflected and DOM XSS scanner.

## Install

```bash
pip install stingxss
```

## Usage

```bash
stingxss -u "https://target.com/search?q=test"
stingxss -u "https://target.com/search?q=test" --level 3 --crawl
```

## Options

| Flag | Description |
|------|-------------|
| `-u, --url` | Target URL |
| `--crawl` | Enable BFS crawler |
| `--blind URL` | Blind XSS callback URL |
| `-d, --data` | POST body |
| `-H KEY:VALUE` | Custom header (repeatable) |
| `-c, --cookie` | Cookie string |
| `--proxy` | HTTP proxy |
| `--level 1-3` | Scan depth (default 1) |
| `--json` | Raw JSON output |

---

## 📜 License

Licensed under the AGPL3.
You are free to use, modify, and distribute this software. If you run it as a service or distribute it, the source must remain open.

For commercial licensing, contact the author.
