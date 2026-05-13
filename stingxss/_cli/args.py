# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
from __future__ import annotations

import argparse

from commonhuman_cli.colour import CYAN, DIM, YELLOW
from commonhuman_cli.prompts import (
  safe_int as _safe_int,
  prompt as _prompt,
  prompt_bool as _prompt_bool,
  section as _section,
)

try:
  from stingxss import __version__, BANNER
except ImportError:
  __version__ = "0.2.0"
  BANNER = ""


def interactive_prompts() -> argparse.Namespace:
  """Walk the user through all scan options interactively."""
  print(CYAN(BANNER))
  print(DIM("  No arguments supplied — entering interactive mode."))
  print(DIM("  Press Enter to accept defaults. Ctrl+C to exit.\n"))

  _section("Target")
  url = ""
  while not url:
    url = _prompt("  Target URL", hint="e.g. https://target.com/search?q=test")
    if not url:
      print(YELLOW("  [!] URL is required."))
    elif not url.startswith(("http://", "https://")):
      print(YELLOW("  [!] URL must start with http:// or https://"))
      url = ""

  _section("Authentication  (optional)")
  cookie = _prompt("  Cookies", hint="name=val; name2=val2")
  headers_raw: list[str] = []
  while True:
    h = _prompt("  Header", hint="KEY:VALUE  (blank to finish)")
    if not h:
      break
    headers_raw.append(h)

  _section("Request")
  data  = _prompt("  POST body", hint="form-encoded or JSON  (blank = GET)")
  proxy = _prompt("  Proxy", hint="http://127.0.0.1:8080")

  _section("Scan options")
  level_str   = _prompt("  Scan level", default="1", hint="1=fast  2=thorough  3=deep")
  threads_str = _prompt("  Threads",    default="5")
  timeout_str = _prompt("  Timeout",    default="15", hint="seconds per request")

  crawl = _prompt_bool("  Enable crawler", default=False)
  if crawl:
    max_pages_str = _prompt("  Max pages", default="50")
    max_depth_str = _prompt("  Max depth", default="3")
  else:
    max_pages_str = "50"
    max_depth_str = "3"

  blind         = _prompt("  Blind XSS callback", hint="https://your.interactsh.io/x  (blank to skip)")
  payloads_file = _prompt("  Custom payloads file", hint="path to file, one payload per line")
  print()

  return argparse.Namespace(
    url=url,
    url_list="",
    crawl=crawl,
    blind=blind,
    data=data,
    header=headers_raw,
    cookie=cookie,
    proxy=proxy,
    threads=_safe_int(threads_str, 5, 1, 20),
    timeout=_safe_int(timeout_str, 15, 5, 120),
    delay=0.0,
    level=_safe_int(level_str, 1, 1, 3),
    payloads=payloads_file,
    max_pages=_safe_int(max_pages_str, 50, 1, 500),
    max_depth=_safe_int(max_depth_str, 3, 1, 10),
    exclude=[],
    inject_headers=[],
    output="",
    json_output=False,
    quiet=False,
    verbose=False,
    browser=False,
    browser_headless=True,
    chromium_path="",
    chromedriver_path="",
    dom_include_minified=False,
    test_stored=False,
  )


def build_parser() -> argparse.ArgumentParser:
  p = argparse.ArgumentParser(
    prog="stingxss",
    description="StingXSS — native context-aware XSS scanner",
    formatter_class=argparse.RawDescriptionHelpFormatter,
  )
  p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
  p.add_argument("-u", "--url",      default="",  help="Target URL")
  p.add_argument("-L", "--url-list", default="",  metavar="FILE",
                 help="File of target URLs to scan (one per line)")
  p.add_argument("--crawl",          action="store_true", help="Enable BFS crawler")
  p.add_argument("--blind",          default="",  metavar="URL",
                 help="Blind XSS callback URL")
  p.add_argument("-d", "--data",     default="",  help="POST body")
  p.add_argument("-H", "--header",   action="append", default=[], metavar="KEY:VALUE",
                 help="Custom header (repeatable)")
  p.add_argument("-c", "--cookie",   default="",  help="Cookie string")
  p.add_argument("--proxy",          default="",  help="HTTP proxy URL")
  p.add_argument("-t", "--threads",  type=int, default=5,
                 help="Worker threads 1-20 (default 5)")
  p.add_argument("--timeout",        type=int, default=15,
                 help="Request timeout seconds 5-120 (default 15)")
  p.add_argument("--delay",          type=float, default=0.0,
                 help="Seconds between requests (default 0, e.g. 0.5)")
  p.add_argument("--level",          type=int, default=1, choices=[1, 2, 3],
                 help="Scan depth: 1=fast 2=thorough 3=deep (default 1)")
  p.add_argument("-f", "--payloads", default="",  metavar="FILE",
                 help="File with custom payloads (one per line)")
  p.add_argument("--max-pages",      type=int, default=50,
                 help="Max pages to crawl (default 50)")
  p.add_argument("--max-depth",      type=int, default=3,
                 help="Max crawl depth (default 3)")
  p.add_argument("--exclude",        action="append", default=[], metavar="PATTERN",
                 help="Regex pattern of URLs to skip (repeatable)")
  p.add_argument("--inject-headers", action="append", default=[], metavar="HEADER",
                 help="Header name(s) to test for XSS reflection (e.g. Referer, X-Forwarded-For, True-Client-IP)")
  p.add_argument("-o", "--output",   default="",  metavar="FILE",
                 help="Write JSON results to this file")
  p.add_argument("--json",           action="store_true", dest="json_output",
                 help="Output raw JSON")
  p.add_argument("-q", "--quiet",    action="store_true",
                 help="Suppress live log output")
  p.add_argument("-v", "--verbose",  action="store_true",
                 help="Show all checks, including ones with no findings")
  p.add_argument("--browser",        action="store_true",
                 help="Enable headless browser XSS scan (requires selenium)")
  p.add_argument("--no-browser-headless", action="store_false", dest="browser_headless",
                 help="Run browser in non-headless mode (visible window)")
  p.add_argument("--browser-chromium",    default="", metavar="PATH",
                 dest="chromium_path",
                 help="Path to Chromium binary (default: auto-detect)")
  p.add_argument("--browser-chromedriver", default="", metavar="PATH",
                 dest="chromedriver_path",
                 help="Path to chromedriver binary (default: auto-detect)")
  p.add_argument("--dom-include-minified", action="store_true",
                 dest="dom_include_minified",
                 help="Include known minified bundles (main.js, vendor.js, etc.) in DOM XSS analysis (more noise)")
  p.add_argument("--test-stored", action="store_true", dest="test_stored",
                 help="Test for stored XSS (inject payloads into surfaces and revisit pages to detect rendering)")
  return p
