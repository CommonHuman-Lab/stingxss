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
    dom_result = dom_mod.scan_page(page_url, html_src, fetcher=_js_fetcher)
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

  logger.info("Scan complete — %d finding(s), %d requests sent",
              result.total_findings, result.requests_sent)


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
