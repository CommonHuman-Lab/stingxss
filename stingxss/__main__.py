# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
StingXSS — __main__.py
Standalone CLI entry point.

Usage (from NyxStrike repo):
    python -m plugins.tools.stingxss -u https://target.com/search?q=test

Usage (from standalone StingXSS repo):
    python -m stingxss -u https://target.com/search?q=test

Run with no arguments for interactive mode.
"""

from __future__ import annotations

import json
import os
import re
import sys

# Allow `python stingxss/__main__.py` in addition to `python -m stingxss`
_HERE   = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
for _p in (_PARENT, _HERE):
  if _p not in sys.path:
    sys.path.insert(0, _p)

from stingxss.engine import scan, ScanOptions
from stingxss.engine.log import get_logger
from stingxss._cli.colour import BOLD, CYAN, YELLOW, BANNER
from stingxss._cli.logging import setup_logging
from stingxss._cli.args import build_parser, interactive_prompts
from stingxss._cli.summary import print_summary

_cli_logger = get_logger("stingxss")


def main() -> None:
  parser = build_parser()
  args   = parser.parse_args()

  setup_logging(verbose=args.verbose, quiet=args.quiet or args.json_output)

  # Collect target URLs
  urls: list[str] = []
  if args.url:
    urls.append(args.url)
  if args.url_list:
    try:
      with open(args.url_list) as fh:
        for line in fh:
          line = line.strip()
          if line and not line.startswith("#"):
            urls.append(line)
    except OSError as e:
      print(f"[!] Cannot read URL list: {e}", file=sys.stderr)
      sys.exit(2)

  # No URL supplied → interactive mode
  if not urls:
    args = interactive_prompts()
    urls = [args.url]
  elif not args.json_output:
    print(CYAN(BANNER))

  if hasattr(args, "timeout") and args.timeout < 5:
    print(YELLOW(f"[!] --timeout {args.timeout} is below minimum; clamping to 5s"), file=sys.stderr)

  # Compile exclude patterns
  exclude_patterns: list[re.Pattern] = []
  for pat in args.exclude:
    try:
      exclude_patterns.append(re.compile(pat))
    except re.error as e:
      print(f"[!] Invalid --exclude pattern '{pat}': {e}", file=sys.stderr)
      sys.exit(2)

  # Parse headers
  headers: dict[str, str] = {}
  for h in args.header:
    if ":" in h:
      k, _, v = h.partition(":")
      headers[k.strip()] = v.strip()

  # Parse custom payload file
  custom_payloads: list[str] = []
  if args.payloads:
    try:
      with open(args.payloads) as fh:
        custom_payloads = [line.strip() for line in fh if line.strip()]
      _cli_logger.info("Loaded %d custom payloads from %s", len(custom_payloads), args.payloads)
    except OSError as e:
      print(f"[!] Cannot read payload file: {e}", file=sys.stderr)
      sys.exit(2)

  opts = ScanOptions(
    crawl=args.crawl,
    blind_callback=args.blind,
    data=args.data,
    headers=headers,
    cookies=args.cookie,
    proxy=args.proxy,
    threads=args.threads,
    timeout=args.timeout,
    delay=args.delay,
    level=args.level,
    custom_payloads=custom_payloads,
    max_pages=args.max_pages,
    max_depth=args.max_depth,
    output=args.output,
    exclude_patterns=exclude_patterns,
    inject_headers=args.inject_headers,
    browser=getattr(args, "browser", False),
    browser_headless=getattr(args, "browser_headless", True),
    chromium_path=getattr(args, "chromium_path", ""),
    chromedriver_path=getattr(args, "chromedriver_path", ""),
    dom_include_minified=getattr(args, "dom_include_minified", False),
  )

  all_results = []
  any_findings = False

  for target_url in urls:
    if any(p.search(target_url) for p in exclude_patterns):
      _cli_logger.info("Skipping excluded URL: %s", target_url)
      continue

    if not args.json_output and not args.quiet:
      print(BOLD(f"[*] Target : {target_url}"))
      print(BOLD(f"[*] Level  : {args.level}  Threads: {args.threads}  Crawl: {args.crawl}"))
      print()

    result = scan(target_url, opts)
    all_results.append(result)
    if result.total_findings > 0:
      any_findings = True

    if args.json_output:
      print(json.dumps(result.to_dict(), indent=2))
      continue

    print_summary(result)

  if args.json_output:
    sys.exit(0 if not any_findings else 1)

  sys.exit(1 if any_findings else 0)


if __name__ == "__main__":
  main()
