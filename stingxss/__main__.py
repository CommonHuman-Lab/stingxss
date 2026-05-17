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
import sys

# Allow `python stingxss/__main__.py` in addition to `python -m stingxss`
_HERE   = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
for _p in (_PARENT, _HERE):
  if _p not in sys.path:
    sys.path.insert(0, _p)

from stingxss import BANNER
from stingxss.engine import scan, ScanOptions
from stingxss.engine.log import get_logger
from stingxss._cli.args import build_parser, interactive_prompts
from stingxss._cli.summary import print_summary
from commonhuman_cli.colour import BOLD, CYAN, YELLOW
from commonhuman_cli.logging import setup_logging
from commonhuman_cli.entrypoint import (
  load_url_list, compile_exclude_patterns, parse_headers, validate_timeout,
)

_cli_logger = get_logger("stingxss")


def _print_poc(result) -> None:
  """Print ready-to-use PoC payloads for confirmed XSS findings."""
  from stingxss.engine.analysis.payload_gen import poc_generate
  confirmed = [f for f in result.reflected if f.confirmed] + \
              [f for f in result.browser if f.confirmed]
  if not confirmed:
    return

  pocs = poc_generate()
  print(BOLD("\n" + "=" * 60))
  print(BOLD("  PoC Payloads — substitute YOUR_OOB_URL with your callback"))
  print(BOLD("=" * 60))
  for i, f in enumerate(confirmed, 1):
    print(CYAN(f"\n  [{i}] {f.url}  param={f.parameter}"))
    print(f"      Confirmed payload : {f.payload[:80]}")
    print()
    for name, tpl in pocs.items():
      print(f"    [{name}]")
      print(f"      {tpl[:120]}")
    print()


def main() -> None:
  parser = build_parser()
  args   = parser.parse_args()

  setup_logging(verbose=args.verbose, quiet=args.quiet or args.json_output, logger_name="stingxss")

  # Collect target URLs
  urls: list[str] = []
  if args.url:
    urls.append(args.url)
  if args.url_list:
    urls.extend(load_url_list(args.url_list))

  # No URL supplied → interactive mode
  if not urls:
    args = interactive_prompts()
    urls = [args.url]
  elif not args.json_output:
    print(CYAN(BANNER))

  validate_timeout(args.timeout)

  exclude_patterns = compile_exclude_patterns(args.exclude)
  headers          = parse_headers(args.header)

  # Form login
  if getattr(args, "login_url", "") and getattr(args, "login_user", ""):
    from commonhuman_core.auth import form_login as _form_login
    if not args.quiet and not args.json_output:
      print(f"[*] Authenticating via {args.login_url} ...")
    auth = _form_login(
      login_url=args.login_url,
      username=args.login_user,
      password=getattr(args, "login_pass", ""),
      username_field=getattr(args, "login_user_field", "username"),
      password_field=getattr(args, "login_pass_field", "password"),
    )
    if auth.cookies and not args.cookie:
      args.cookie = auth.cookies
    headers.update(auth.headers)

  # OpenAPI spec import — prepend discovered URLs to the target list
  if getattr(args, "openapi", ""):
    from commonhuman_core.openapi import load_openapi as _load_openapi
    if not args.quiet and not args.json_output:
      print(f"[*] Loading OpenAPI spec from {args.openapi} ...")
    api_eps = _load_openapi(args.openapi, base_url=getattr(args, "base_url", ""))
    seen_oa = set(urls)
    for ep in api_eps:
      if ep.url not in seen_oa:
        urls.append(ep.url)
        seen_oa.add(ep.url)
    if not args.quiet and not args.json_output:
      print(f"[*] OpenAPI: {len(api_eps)} endpoint(s) added")

  # Browser crawl — headless JS endpoint discovery
  if getattr(args, "browser_crawl", False) and urls:
    from commonhuman_core.browser_crawler import browser_crawl as _browser_crawl
    seed = urls[0]
    if not args.quiet and not args.json_output:
      print(f"[*] Browser-crawling {seed} ...")
    bc_found = _browser_crawl(
      start_url=seed,
      max_pages=args.max_pages,
      max_depth=args.max_depth,
      cookies=args.cookie or "",
      chromium_path=getattr(args, "chromium_path", ""),
      chromedriver_path=getattr(args, "chromedriver_path", ""),
    )
    seen_bc = set(urls)
    new_bc  = [u for u in bc_found if u not in seen_bc]
    urls.extend(new_bc)
    if not args.quiet and not args.json_output:
      print(f"[*] Browser crawl: {len(new_bc)} additional endpoint(s) queued")

  # Parse custom payload file(s) — -f is now repeatable
  custom_payloads: list[str] = []
  for payload_file in (args.payloads or []):
    try:
      with open(payload_file) as fh:
        loaded = [line.strip() for line in fh if line.strip()]
      _cli_logger.info("Loaded %d custom payloads from %s", len(loaded), payload_file)
      custom_payloads.extend(loaded)
    except OSError as e:
      print(f"[!] Cannot read payload file: {e}", file=sys.stderr)
      sys.exit(2)

  # Dork — prepend discovered URLs to the target list
  if getattr(args, "dork", ""):
    from commonhuman_core.dorker import dork as _dork, DorkEngine as _DorkEngine
    _dork_engine = getattr(args, "dork_engine", "ddg")
    _engine_label = {"ddg": "DuckDuckGo", "bing": "Bing", "yahoo": "Yahoo", "all": "All engines"}.get(_dork_engine, _dork_engine)
    if not args.quiet and not args.json_output:
      print(f"[*] Dorking [{_engine_label}]: {args.dork} ...")
    dork_urls = _dork(
      query=args.dork,
      max_results=getattr(args, "dork_max", 20),
      proxy=args.proxy,
      timeout=args.timeout,
      engine=_dork_engine,
    )
    if dork_urls:
      seen_dk = set(urls)
      new_dk  = [u for u in dork_urls if u not in seen_dk]
      urls    = new_dk + urls
      if not args.quiet and not args.json_output:
        print(f"[*] Dork: {len(new_dk)} URL(s) discovered and prepended")
    else:
      if not args.quiet and not args.json_output:
        print("[!] Dork returned no results")

  # Remote payload loading — download custom payloads from a URL
  _payload_url = getattr(args, "payload_url", "")
  if _payload_url:
    import urllib.request as _ureq
    if not args.quiet and not args.json_output:
      print(f"[*] Loading remote payloads from {_payload_url} ...")
    try:
      with _ureq.urlopen(_payload_url, timeout=15) as _resp:  # noqa: S310
        _remote = _resp.read().decode("utf-8", errors="replace")
      _remote_payloads = [ln.strip() for ln in _remote.splitlines() if ln.strip()]
      custom_payloads.extend(_remote_payloads)
      if not args.quiet and not args.json_output:
        print(f"[*] Remote payloads: {len(_remote_payloads)} loaded")
    except Exception as _exc:
      print(f"[!] Cannot load remote payloads: {_exc}", file=sys.stderr)

  # Parse --evasion chain
  evasion_chain: list[str] = []
  _evasion_arg = getattr(args, "evasion", "")
  if _evasion_arg:
    evasion_chain = [e.strip() for e in _evasion_arg.split(",") if e.strip()]

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
    test_stored=getattr(args, "test_stored", False),
    browser=getattr(args, "browser", False),
    browser_headless=getattr(args, "browser_headless", True),
    chromium_path=getattr(args, "chromium_path", ""),
    chromedriver_path=getattr(args, "chromedriver_path", ""),
    dom_include_minified=getattr(args, "dom_include_minified", False),
    probe_filter=getattr(args, "probe_filter", True),
    poc=getattr(args, "poc", False),
    evasion_chain=evasion_chain,
    randomize_payloads=getattr(args, "randomize_payloads", False),
    graphql=getattr(args, "graphql", False),
    websocket=getattr(args, "websocket", False),
    ws_urls=getattr(args, "ws_urls", []),
    source_maps=getattr(args, "source_maps", False),
    payload_url=_payload_url,
    dork_engine=getattr(args, "dork_engine", "ddg"),
  )

  all_results = []
  any_findings = False

  for target_url in urls:
    if any(p.search(target_url) for p in exclude_patterns):
      _cli_logger.info("Skipping excluded URL: %s", target_url)
      continue

    if not args.json_output and not args.quiet:
      print(BOLD(f"[*] Target : {target_url}"))
      _chain_str = ",".join(evasion_chain) if evasion_chain else "auto"
      _rand_str  = "  Randomize: yes" if getattr(args, "randomize_payloads", False) else ""
      print(BOLD(f"[*] Level  : {args.level}  Threads: {args.threads}  Crawl: {args.crawl}  Evasion: {_chain_str}{_rand_str}"))
      print()

    result = scan(target_url, opts)
    all_results.append(result)
    if result.total_findings > 0:
      any_findings = True

    if args.json_output:
      print(json.dumps(result.to_dict(), indent=2))
      continue

    print_summary(result)

    if getattr(args, "poc", False):
      _print_poc(result)

  if args.json_output:
    sys.exit(0 if not any_findings else 1)

  sys.exit(1 if any_findings else 0)


if __name__ == "__main__":
  main()
