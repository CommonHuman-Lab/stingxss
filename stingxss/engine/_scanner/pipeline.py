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
from ..reporter import ScanResult
from .options import ScanOptions
from .passive import fetch_seed, run_passive_checks
from .active import test_param, test_header
from .blind import inject_blind
from .stored import run_stored, run_prototype_pollution, run_localstorage

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
  else:
    logger.debug("No WAF detected")

  evasions: list[str] = waf_result.evasions if waf_result.evasions else ["none"]

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
    for hdr in opts.inject_headers:
      test_header(url, hdr, evasions, opts, injector, result)

  # 6. Open redirect testing
  logger.info("Testing %d surface(s) for open redirect", len(surfaces))
  with ThreadPoolExecutor(max_workers=opts.threads) as pool:
    futs = [pool.submit(_test_redirect, s, opts, injector, result) for s in surfaces]
    for f in as_completed(futs):
      try:
        f.result()
      except Exception as exc:
        result.append_error(str(exc))

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
    dom_result = dom_mod.scan_page(page_url, html_src, fetcher=_js_fetcher,
                                   include_minified=opts.dom_include_minified)
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
  if opts.browser:
    from ..browser import BrowserEngine, SELENIUM_AVAILABLE
    if not SELENIUM_AVAILABLE:
      result.append_error("--browser requires selenium: pip install stingxss[browser]")
    else:
      _run_browser_scan(url, surfaces, opts, injector, result)

  logger.info("Scan complete — %d finding(s), %d requests sent",
              result.total_findings, injector.request_count)


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
  from ..browser.engine import _hash_params
  from ..analysis.payload_gen import make_confirm_marker
  from ..reporter import BrowserFinding

  engine = BrowserEngine(
    chromium_path=opts.chromium_path,
    chromedriver_path=opts.chromedriver_path,
    headless=opts.browser_headless,
    timeout=opts.timeout,
  )
  marker = make_confirm_marker()
  logger.info("Browser XSS scan starting (marker=%s)", marker)

  parsed_seed = _urlparse.urlparse(url)
  spa_base    = f"{parsed_seed.scheme}://{parsed_seed.netloc}/"

  # Collect (url, param) pairs to test — de-duplicated
  seen: set[tuple[str, str]] = set()

  def _test(surf_url: str, param: str) -> None:
    key = (surf_url, param)
    if key in seen:
      return
    seen.add(key)
    if any(p.search(surf_url) for p in opts.exclude_patterns):
      return
    try:
      findings = engine.scan_url(url=surf_url, params={param: ""}, marker=marker)
      for f in findings:
        result.append_browser(f)
        logger.finding(
          "Browser XSS confirmed: param=%s url=%s evidence=%s",
          f.parameter, f.url, f.evidence[:60],
        )
    except Exception as exc:
      result.append_error(f"Browser scan error ({surf_url}): {exc}")

  # 1. Hash-fragment params from the seed URL (SPA hash-router style)
  for param in _hash_params(url):
    _test(url, param)

  # 2. Regular GET surfaces built by the crawler / surface builder
  for surface in surfaces:
    if surface["method"] != "GET":
      continue
    _test(surface["url"], surface["single_param"])

  # 3. Cookie / localStorage pre-seed — catches $parse(cookie), $parse(localStorage), etc.
  #    Test the seed URL and all unique crawled GET surfaces.
  preseed_candidates: list[str] = [url]
  seen_preseed: set[str] = {url}
  for surface in surfaces:
    if surface["method"] == "GET" and surface["url"] not in seen_preseed:
      preseed_candidates.append(surface["url"])
      seen_preseed.add(surface["url"])
  for candidate_url in preseed_candidates:
    if any(p.search(candidate_url) for p in opts.exclude_patterns):
      continue
    try:
      findings = engine.scan_url_with_preseeded_storage(
        url=candidate_url, marker=marker, base_url=spa_base,
      )
      for f in findings:
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
    # Candidate revisit pages: seed URL + all unique crawled GET surface URLs
    revisit_candidates: list[str] = [url]
    seen_urls: set[str] = {url}
    for surface in surfaces:
      if surface["method"] == "GET" and surface["url"] not in seen_urls:
        revisit_candidates.append(surface["url"])
        seen_urls.add(surface["url"])

    from ..browser.engine import _BROWSER_PAYLOADS
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
