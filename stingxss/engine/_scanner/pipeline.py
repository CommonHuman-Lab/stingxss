# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Scan pipeline: WAF → passive checks → surface building → active testing → DOM → blind."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict

from ..log import get_logger
from .. import crawler as crawler_mod
from ..analysis import dom_scanner as dom_mod
from ..http import waf_detect
from ..http.injector import Injector, parse_post_data
from ..checks import redirect as redirect_mod
from ..checks import crlf as crlf_mod
from ..checks import graphql as graphql_mod
from ..reporter import ScanResult
from .options import ScanOptions
from .passive import fetch_seed, run_passive_checks
from .active import test_param, test_header
from .blind import inject_blind
from .stored import run_stored, run_prototype_pollution, run_localstorage
from .path_inject import run_path_injection
from .websocket import run_websocket_scan

logger = get_logger("stingxss.scanner")


def run(url: str, opts: ScanOptions, injector: Injector, result: ScanResult) -> None:
  # 1. WAF detection
  logger.info("Probing for WAF on %s", url)
  first_param = injector.get_params(url)[0] if injector.get_params(url) else None
  waf_result  = waf_detect.detect(injector, url, first_param)

  if waf_result.detected:
    result.waf_detected    = waf_result.name
    result.evasion_applied = waf_result.evasions[0] if waf_result.evasions else None
    logger.warning("WAF detected: %s (confidence: %s)", waf_result.name, waf_result.confidence)
    logger.info("Evasion strategies: %s", ", ".join(waf_result.evasions))

    # Inject WAF-specific payload overrides into custom_payloads so active
    # scanning automatically uses them alongside the standard payload sets.
    if waf_result.name:
      try:
        from commonhuman_payloads.waf import get_waf_payloads
        waf_extras = get_waf_payloads(waf_result.name)
        if waf_extras:
          opts.custom_payloads = list(opts.custom_payloads) + waf_extras
          logger.info(
            "WAF extra payloads: +%d %s-specific payload(s)", len(waf_extras), waf_result.name,
          )
      except ImportError:
        pass
  else:
    logger.debug("No WAF detected")

  # User-supplied evasion chain takes priority over auto-detected WAF evasions.
  evasions: list[str] = (
    ["none"] if opts.evasion_chain
    else (waf_result.evasions if waf_result.evasions else ["none"])
  )

  # 2. Passive checks
  seed_resp = fetch_seed(injector, url)
  run_passive_checks(url, seed_resp, injector, result)

  # 3. Build injectable surfaces
  surfaces: list[dict[str, Any]] = []
  for param in injector.get_params(url):
    surfaces.append({"url": url, "method": "GET", "params": {param: ""}, "single_param": param})
  if opts.data:
    post_params = parse_post_data(opts.data)
    for param in post_params:
      surfaces.append({"url": url, "method": "POST", "params": post_params, "single_param": param})

  page_sources: Dict[str, str] = {}
  crawl_result: Any = None

  if opts.crawl:
    logger.info("Crawling %s (max_pages=%s, depth=%s)", url, opts.max_pages, opts.max_depth)
    crawl_result = crawler_mod.crawl(
      start_url=url, injector=injector,
      max_pages=opts.max_pages, max_depth=opts.max_depth, threads=opts.threads,
    )
    result.crawled_urls = len(crawl_result.visited_urls)
    page_sources.update(crawl_result.page_sources)
    logger.info("Crawled %d URLs, found %d forms", result.crawled_urls, len(crawl_result.form_targets))
    for page_url, params in crawl_result.url_params:
      for param in params:
        surfaces.append({"url": page_url, "method": "GET", "params": {param: ""}, "single_param": param})
    for form in crawl_result.form_targets:
      for param in form.params:
        surfaces.append({
          "url": form.action, "method": form.method,
          "params": {**form.base_data, **form.params}, "single_param": param,
        })
  else:
    if seed_resp is not None:
      page_sources[url] = seed_resp.text

  logger.info("%d injectable surfaces identified", len(surfaces))
  result.params_tested = len(surfaces)

  # 4. Active XSS testing
  with ThreadPoolExecutor(max_workers=opts.threads) as pool:
    futs = [pool.submit(test_param, s, evasions, opts, injector, result) for s in surfaces]
    for f in as_completed(futs):
      try:
        f.result()
      except Exception as exc:
        result.append_error(str(exc))

  # 5. Header injection
  if opts.inject_headers:
    logger.info("Testing %d header(s) for reflection: %s",
                len(opts.inject_headers), ", ".join(opts.inject_headers))
    _header_urls = list(page_sources.keys()) if page_sources else [url]
    for hdr in opts.inject_headers:
      for hurl in _header_urls:
        test_header(hurl, hdr, evasions, opts, injector, result)

  # 5b. Auto-probe common reflected headers on all crawled pages
  _AUTO_HEADERS = [
    "User-Agent", "Referer",
    "X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP",
    "X-Custom-Name", "X-Original-URL",
  ]

  _BOARD_SUFFIXES = ("/board", "/reviews", "/feed", "/timeline")

  def _is_board_url(u: str) -> bool:
    from urllib.parse import urlparse
    path = urlparse(u).path.rstrip("/")
    return any(path.endswith(s) for s in _BOARD_SUFFIXES)

  auto_headers_to_test = [h for h in _AUTO_HEADERS
                           if h not in (opts.inject_headers or [])]
  if auto_headers_to_test:
    _header_urls = [u for u in (list(page_sources.keys()) if page_sources else [url])
                    if not _is_board_url(u)]
    logger.info("Auto-probing %d header(s) on %d page(s)",
                len(auto_headers_to_test), len(_header_urls))
    with ThreadPoolExecutor(max_workers=opts.threads) as pool:
      futs = [
        pool.submit(test_header, hurl, hdr, evasions, opts, injector, result)
        for hdr in auto_headers_to_test
        for hurl in _header_urls
      ]
      for f in as_completed(futs):
        try:
          f.result()
        except Exception as exc:
          result.append_error(str(exc))

  # 5c. Path segment injection (catches <path:var> style routes)
  if opts.crawl and crawl_result:
    logger.info("Testing %d URL(s) for path-segment injection", len(crawl_result.visited_urls))
    run_path_injection(crawl_result.visited_urls, evasions, opts, injector, result)
  else:
    run_path_injection([url], evasions, opts, injector, result)

  # 6. Open redirect testing
  logger.info("Testing %d surface(s) for open redirect", len(surfaces))
  with ThreadPoolExecutor(max_workers=opts.threads) as pool:
    futs = [pool.submit(_test_redirect, s, opts, injector, result) for s in surfaces]
    for f in as_completed(futs):
      try:
        f.result()
      except Exception as exc:
        result.append_error(str(exc))

  # 6b. CRLF / HTTP Response Splitting testing
  logger.info("Testing %d surface(s) for CRLF injection", len(surfaces))
  with ThreadPoolExecutor(max_workers=opts.threads) as pool:
    futs = [pool.submit(_test_crlf_param, s, opts, injector, result) for s in surfaces]
    for f in as_completed(futs):
      try:
        f.result()
      except Exception as exc:
        result.append_error(str(exc))
  # CRLF via reflected headers (run once per unique URL)
  _crlf_urls_seen: set[str] = set()
  for s in surfaces:
    if s["url"] not in _crlf_urls_seen:
      _crlf_urls_seen.add(s["url"])
      for cf in crlf_mod.check_headers(s["url"], injector):
        result.append_crlf(cf)
        logger.finding("CRLF (header): %s reflected CRLF @ %s", cf.parameter, cf.url)

  # 7. DOM XSS static analysis
  logger.info("Running DOM XSS analysis on %d pages", len(page_sources))

  def _js_fetcher(js_url: str) -> str:
    try:
      resp = injector.get(js_url)
      if resp.status_code < 400:
        return resp.text
    except Exception:
      pass
    return ""

  for page_url, html_src in page_sources.items():
    dom_result = dom_mod.scan_page(
      page_url, html_src,
      fetcher=_js_fetcher,
      include_minified=opts.dom_include_minified,
      use_source_maps=opts.source_maps,
    )
    for finding in dom_result.sink_findings:
      result.append_dom(finding)
      logger.finding("DOM XSS: %s → %s @ %s:%d", finding.source, finding.sink, page_url, finding.line)

  # 8. Blind XSS
  if opts.blind_callback:
    logger.info("Injecting blind XSS payloads (callback: %s)", opts.blind_callback)
    inject_blind(url, opts, injector, result, crawl_result=crawl_result)

  # 9. Stored XSS (inject + revisit)
  if opts.test_stored:
    logger.info("Testing %d surface(s) for stored XSS", len(surfaces))
    run_stored(
      seed_url=url, surfaces=surfaces, page_sources=page_sources,
      opts=opts, injector=injector, result=result, crawl_result=crawl_result,
    )

  # 10. Prototype pollution → XSS
  if opts.test_stored:
    logger.info("Testing prototype pollution XSS on %s", url)
    run_prototype_pollution(url, opts, injector, result)

  # 11. localStorage / sessionStorage injection
  if opts.test_stored:
    logger.info("Testing localStorage XSS on %s", url)
    run_localstorage(url, opts, injector, result)

  # 12. Headless browser XSS (optional, requires --browser flag)
  # 13. GraphQL XSS (optional, requires --graphql flag)
  if opts.graphql:
    from urllib.parse import urlparse as _urlparse
    _gql_base = f"{_urlparse(url).scheme}://{_urlparse(url).netloc}"
    logger.info("GraphQL: probing endpoints on %s", _gql_base)
    _gql_endpoints = graphql_mod.discover_endpoints(_gql_base, injector)
    for _ep in opts.graphql_endpoints:
      if _ep not in _gql_endpoints:
        _gql_endpoints.append(_ep)
    if _gql_endpoints:
      logger.info("GraphQL: found %d endpoint(s): %s", len(_gql_endpoints), ", ".join(_gql_endpoints))
      with ThreadPoolExecutor(max_workers=opts.threads) as pool:
        futs = [
          pool.submit(graphql_mod.check, ep, injector, level=opts.level)
          for ep in _gql_endpoints
        ]
        for f in as_completed(futs):
          try:
            for gf in f.result():
              result.append_graphql(gf)
              logger.finding("GraphQL XSS: field=%s op=%s @ %s", gf.field, gf.operation, gf.endpoint)
          except Exception as exc:
            result.append_error(f"GraphQL scan error: {exc}")
    else:
      logger.debug("GraphQL: no endpoints found on %s", _gql_base)

  # 14. WebSocket XSS (optional, requires --websocket flag)
  if opts.websocket:
    logger.info("WebSocket: scanning for injectable endpoints")
    run_websocket_scan(
      seed_url=url,
      page_sources=page_sources,
      opts=opts,
      injector=injector,
      result=result,
      ws_urls=opts.ws_urls or None,
    )

  if opts.browser:
    from ..browser import BrowserEngine, SELENIUM_AVAILABLE
    if not SELENIUM_AVAILABLE:
      result.append_error("--browser requires selenium: pip install stingxss[browser]")
    else:
      _run_browser_scan(url, surfaces, opts, injector, result)

  logger.info("Scan complete — %d finding(s), %d requests sent",
              result.total_findings, injector.request_count)


def _test_crlf_param(surface: dict[str, Any], opts: ScanOptions, injector: Injector, result: ScanResult) -> None:
  target_url  = surface["url"]
  param       = surface["single_param"]
  method      = surface["method"]
  base_params = {k: v for k, v in surface["params"].items() if k != param}
  if any(p.search(target_url) for p in opts.exclude_patterns):
    return
  for cf in crlf_mod.check_params(
    url=target_url, param=param, method=method, injector=injector,
    base_data=base_params if method == "POST" else None,
  ):
    result.append_crlf(cf)
    logger.finding("CRLF (param): %s @ %s", param, target_url)


def _test_redirect(surface: dict[str, Any], opts: ScanOptions, injector: Injector, result: ScanResult) -> None:
  target_url  = surface["url"]
  param       = surface["single_param"]
  method      = surface["method"]
  base_params = {k: v for k, v in surface["params"].items() if k != param}
  if any(p.search(target_url) for p in opts.exclude_patterns):
    return
  for rf in redirect_mod.check_url(
    url=target_url, param=param, method=method, injector=injector,
    base_data=base_params if method == "POST" else None,
  ):
    result.append_redirect(rf)
    logger.finding("Redirect (%s): %s @ %s → %s", rf.issue, param, target_url, rf.location[:60])


def _run_browser_scan(
  url:      str,
  surfaces: list[dict[str, Any]],
  opts:     ScanOptions,
  injector: Injector,
  result:   ScanResult,
) -> None:
  """Stage 12 — run headless browser XSS scan over all GET surfaces.

  Also directly tests the seed URL when it contains hash-fragment params
  (e.g. ``http://target/#/search?q=test``) — those are invisible to the HTTP
  layer and would never appear in *surfaces*.

  Additionally handles header-injection stored XSS (e.g. Juice Shop challenge 8):
  for each ``--inject-headers`` header, injects the XSS payload via HTTP then
  revisits a set of candidate pages in the browser to detect stored execution.
  """
  import urllib.parse as _urlparse
  from ..browser import BrowserEngine
  from ..browser.engine import _hash_params, _BROWSER_PAYLOADS
  from ..analysis.payload_gen import make_confirm_marker

  engine = BrowserEngine(
    chromium_path=opts.chromium_path,
    chromedriver_path=opts.chromedriver_path,
    headless=opts.browser_headless,
    timeout=opts.timeout,
  )
  marker = make_confirm_marker()

  parsed_seed = _urlparse.urlparse(url)
  spa_base    = f"{parsed_seed.scheme}://{parsed_seed.netloc}/"

  # 1. Collect all (url, param) pairs — hash-fragment + GET surfaces, de-duplicated
  seen: set[tuple[str, str]] = set()
  all_pairs: list[tuple[str, str]] = []

  for param in _hash_params(url):
    key = (url, param)
    if key not in seen:
      seen.add(key)
      all_pairs.append(key)

  for s in surfaces:
    if s["method"] != "GET":
      continue
    key = (s["url"], s["single_param"])
    if key in seen:
      continue
    if any(p.search(s["url"]) for p in opts.exclude_patterns):
      continue
    seen.add(key)
    all_pairs.append(key)

  # 2. Scan all surfaces with a single shared Chromium instance
  if all_pairs:
    total = len(all_pairs)
    logger.info("Browser XSS scan: %d surfaces, single Chromium instance (marker=%s)",
                total, marker)

    def _on_progress(current: int, _total: int) -> None:
      step = max(1, _total // 20)
      if current == 1 or current % step == 0 or current == _total:
        logger.info("Browser XSS: %d/%d surfaces tested", current, _total)

    try:
      for f in engine.scan_surfaces_batch(
        all_pairs, marker=marker, base_url=spa_base, on_progress=_on_progress,
      ):
        result.append_browser(f)
        logger.finding(
          "Browser XSS confirmed: param=%s url=%s evidence=%s",
          f.parameter, f.url, f.evidence[:60],
        )
    except Exception as exc:
      result.append_error(f"Browser scan error: {exc}")

  # 3. Cookie / localStorage pre-seed — catches $parse(cookie), $parse(localStorage).
  #    Cap to a reasonable number of unique pages (each costs a full Chromium startup).
  _PRESEED_CAP = 15
  preseed_candidates: list[str] = [url]
  seen_preseed: set[str] = {url}
  for surface in surfaces:
    if len(preseed_candidates) >= _PRESEED_CAP:
      break
    if surface["method"] == "GET" and surface["url"] not in seen_preseed:
      if not any(p.search(surface["url"]) for p in opts.exclude_patterns):
        preseed_candidates.append(surface["url"])
        seen_preseed.add(surface["url"])

  n_preseed = len(preseed_candidates)
  logger.info("Browser storage preseed scan: %d URL(s)", n_preseed)
  for i, candidate_url in enumerate(preseed_candidates, 1):
    logger.info("Browser preseed: %d/%d — %s", i, n_preseed, candidate_url)
    try:
      for f in engine.scan_url_with_preseeded_storage(
        url=candidate_url, marker=marker, base_url=spa_base,
      ):
        result.append_browser(f)
        logger.finding(
          "Browser XSS confirmed (storage): url=%s evidence=%s",
          f.url, f.evidence[:60],
        )
    except Exception as exc:
      result.append_error(f"Browser storage scan error ({candidate_url}): {exc}")

  # 4. Header-injection stored XSS
  #    For each inject_header: send a request with the XSS payload in that header,
  #    then revisit candidate pages in the browser to see if it fires.
  if opts.inject_headers:
    revisit_candidates: list[str] = [url]
    seen_urls: set[str] = {url}
    for surface in surfaces:
      if surface["method"] == "GET" and surface["url"] not in seen_urls:
        revisit_candidates.append(surface["url"])
        seen_urls.add(surface["url"])

    for header_name in opts.inject_headers:
      for payload_tpl in _BROWSER_PAYLOADS:
        payload = payload_tpl.replace("{marker}", marker)
        try:
          injector.get(url, headers={header_name: payload})
        except Exception:
          pass
        finding = engine.check_stored(
          revisit_urls=revisit_candidates,
          marker=marker,
          base_url=spa_base,
        )
        if finding:
          finding.parameter = f"[header] {header_name}"
          finding.payload   = payload
          result.append_browser(finding)
          logger.finding(
            "Browser header XSS confirmed: header=%s url=%s evidence=%s",
            header_name, finding.url, finding.evidence[:60],
          )
          break  # one confirmed payload per header is enough
