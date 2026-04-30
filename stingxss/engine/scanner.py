"""
StingXSS — engine/scanner.py
Scan orchestrator — the brain of StingXSS.

Pipeline:
  1. WAF detection
  2. Crawl (optional)
  3. Parameter discovery (URL params + form fields)
  4. Reflection probing per parameter
  5. Context analysis on reflected parameters
  6. Context-aware payload generation + injection
  7. DOM XSS static analysis on all collected page sources
  8. Blind XSS injection (optional)
  9. Build and return ScanResult
"""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional

from . import crawler as crawler_mod
from . import dom_scanner as dom_mod
from . import waf_detect
from .injector import Injector, parse_post_data
from .parser import PROBE_MARKER, find_context, is_reflected
from .payload_gen import blind_payloads, generate, make_confirm_marker
from .reporter import (
  BlindFinding,
  ReflectedFinding,
  ReflectionContext,
  ScanResult,
)

logger = logging.getLogger("stingxss.scanner")


# ---------------------------------------------------------------------------
# ScanOptions
# ---------------------------------------------------------------------------

class ScanOptions:
  def __init__(
    self,
    crawl:           bool = False,
    blind_callback:  str  = "",
    data:            str  = "",          # raw POST body
    headers:         Optional[Dict[str, str]] = None,
    cookies:         str  = "",
    proxy:           str  = "",
    threads:         int  = 5,
    timeout:         int  = 15,
    level:           int  = 1,           # 1=fast 2=thorough 3=deep
    custom_payloads: Optional[List[str]] = None,
    max_pages:       int  = 50,
    max_depth:       int  = 3,
    on_log:          Optional[Callable[[str], None]] = None,
  ) -> None:
    self.crawl           = crawl
    self.blind_callback  = blind_callback.strip()
    self.data            = data.strip()
    self.headers         = headers or {}
    self.cookies         = cookies.strip()
    self.proxy           = proxy.strip()
    self.threads         = max(1, min(threads, 20))
    self.timeout         = max(5, min(timeout, 120))
    self.level           = max(1, min(level, 3))
    self.custom_payloads = custom_payloads or []
    self.max_pages       = max_pages
    self.max_depth       = max_depth
    self.on_log          = on_log  # callback for live log lines


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def scan(url: str, options: Optional[ScanOptions] = None) -> ScanResult:
  """
  Run a full StingXSS scan against `url` and return a ScanResult.
  """
  if options is None:
    options = ScanOptions()

  result = ScanResult(target=url)
  _log  = _make_logger(result, options.on_log)

  injector = Injector(
    timeout=options.timeout,
    proxy=options.proxy or None,
    headers=options.headers or None,
    cookies=options.cookies or None,
  )

  try:
    _run(url, options, injector, result, _log)
  except Exception as exc:
    result.errors.append(f"Scan aborted: {exc}")
    logger.exception("StingXSS scan error")
  finally:
    injector.close()
    result.requests_sent = injector.request_count
    result.finish()

  return result


# ---------------------------------------------------------------------------
# Internal pipeline
# ---------------------------------------------------------------------------

def _run(
  url:      str,
  opts:     ScanOptions,
  injector: Injector,
  result:   ScanResult,
  log:      Callable[[str], None],
) -> None:

  # ---- 1. WAF detection --------------------------------------------------
  log(f"[*] Probing for WAF on {url}")
  first_param = injector.get_params(url)[0] if injector.get_params(url) else None
  waf_result  = waf_detect.detect(injector, url, first_param)

  if waf_result.detected:
    result.waf_detected    = waf_result.name
    result.evasion_applied = waf_result.evasions[0] if waf_result.evasions else None
    log(f"[!] WAF detected: {waf_result.name} (confidence: {waf_result.confidence})")
    log(f"[*] Evasion strategy: {result.evasion_applied}")
  else:
    log("[*] No WAF detected")

  evasion = waf_result.evasions[0] if waf_result.evasions else "none"

  # ---- 2. Build initial surface (URL params + optional crawler) ----------
  # Surfaces: list of (url, method, {param: default_value})
  surfaces: List[Dict[str, Any]] = []

  # Always add the seed URL query params
  for param in injector.get_params(url):
    surfaces.append({"url": url, "method": "GET", "params": {param: ""}, "single_param": param})

  # POST data params
  if opts.data:
    post_params = parse_post_data(opts.data)
    for param in post_params:
      surfaces.append({"url": url, "method": "POST", "params": post_params, "single_param": param})

  # Crawl
  page_sources: Dict[str, str] = {}
  if opts.crawl:
    log(f"[*] Crawling {url} (max_pages={opts.max_pages}, depth={opts.max_depth})")
    crawl_result = crawler_mod.crawl(
      start_url=url,
      injector=injector,
      max_pages=opts.max_pages,
      max_depth=opts.max_depth,
      threads=opts.threads,
    )
    result.crawled_urls = len(crawl_result.visited_urls)
    page_sources.update(crawl_result.page_sources)
    log(f"[*] Crawled {result.crawled_urls} URLs, found {len(crawl_result.form_targets)} forms")

    # Add crawled URL params
    for page_url, params in crawl_result.url_params:
      for param in params:
        surfaces.append({"url": page_url, "method": "GET", "params": {param: ""}, "single_param": param})

    # Add form targets
    for form in crawl_result.form_targets:
      for param in form.params:
        surfaces.append({
          "url":          form.action,
          "method":       form.method,
          "params":       form.params,
          "single_param": param,
        })
  else:
    # Fetch seed page for DOM analysis
    try:
      resp = injector.get(url)
      page_sources[url] = resp.text
    except Exception:
      pass

  log(f"[*] {len(surfaces)} injectable surfaces identified")

  # ---- 3. Reflection + XSS testing (threaded) ----------------------------
  result.params_tested = len(surfaces)

  def test_surface(surface: Dict[str, Any]) -> None:
    _test_param(surface, evasion, opts, injector, result, log)

  with ThreadPoolExecutor(max_workers=opts.threads) as pool:
    futs = [pool.submit(test_surface, s) for s in surfaces]
    for f in as_completed(futs):
      try:
        f.result()
      except Exception as exc:
        result.errors.append(str(exc))

  # ---- 4. DOM XSS static analysis ----------------------------------------
  log(f"[*] Running DOM XSS analysis on {len(page_sources)} pages")
  for page_url, html in page_sources.items():
    dom_result = dom_mod.scan_page(page_url, html)
    for finding in dom_result.sink_findings:
      result.dom.append(finding)
      log(f"[+] DOM XSS: {finding.source} → {finding.sink} @ {page_url}:{finding.line}")

  # ---- 5. Blind XSS injection --------------------------------------------
  if opts.blind_callback:
    log(f"[*] Injecting blind XSS payloads (callback: {opts.blind_callback})")
    _inject_blind(url, opts, injector, result, log)

  # ---- Summary -----------------------------------------------------------
  log(f"[*] Scan complete — {result.total_findings} finding(s), "
      f"{result.requests_sent} requests sent")


# ---------------------------------------------------------------------------
# Per-parameter test
# ---------------------------------------------------------------------------

def _test_param(
  surface:  Dict[str, Any],
  evasion:  str,
  opts:     ScanOptions,
  injector: Injector,
  result:   ScanResult,
  log:      Callable[[str], None],
) -> None:
  target_url    = surface["url"]
  method        = surface["method"]
  param         = surface["single_param"]
  base_params   = {k: v for k, v in surface["params"].items() if k != param}

  # 3a. Probe for reflection
  reflected, probe_resp = injector.probe_reflection(
    url=target_url, param=param, marker=PROBE_MARKER,
    method=method, base_data=base_params if method == "POST" else None,
  )

  if not reflected:
    return

  log(f"[~] Reflected: {param} @ {target_url} [{method}]")

  # 3b. Context analysis
  context = find_context(probe_resp.text, PROBE_MARKER)
  log(f"[~] Context: {context}")

  # 3c. Generate payloads
  marker   = make_confirm_marker()
  payloads = generate(
    context=context,
    evasion=evasion,
    marker=marker,
    custom_payloads=opts.custom_payloads,
    level=opts.level,
  )

  # 3d. Inject each payload and check for confirmation marker
  for payload in payloads:
    try:
      if method == "POST":
        resp = injector.inject_post(target_url, param, payload, base_params)
      else:
        resp = injector.inject_get(target_url, param, payload)
    except Exception:
      continue

    # Confirm only when the payload's angle brackets appear unencoded.
    # The marker is embedded inside the payload (e.g. alert('vXSS_EXEC_...')),
    # so it will be present in the response even when the server URL-encodes or
    # HTML-encodes the reflection.  We therefore require that the literal '<'
    # character from the payload also survived into the response unencoded.
    # If the server returned %3C or &lt; the tag cannot execute.
    _text = resp.text
    _marker_present    = marker.lower() in _text.lower()
    _tag_open_literal  = f"<{payload[1:5].lower()}" in _text.lower()   # e.g. '<img ' or '<svg '
    confirmed = _marker_present and _tag_open_literal

    # Capture a small evidence snippet
    idx = resp.text.lower().find(payload[:20].lower())
    evidence = resp.text[max(0, idx - 30): idx + 80].strip() if idx != -1 else ""

    finding = ReflectedFinding(
      url=target_url,
      parameter=param,
      method=method,
      context=context,
      payload=payload,
      confirmed=confirmed,
      evidence=evidence,
    )
    result.reflected.append(finding)

    if confirmed:
      log(f"[+] XSS CONFIRMED: {param} @ {target_url} — {payload[:60]}")
      # Stop testing more payloads for this param once confirmed
      break
    else:
      log(f"[~] Payload reflected (unconfirmed): {payload[:60]}")


# ---------------------------------------------------------------------------
# Blind XSS
# ---------------------------------------------------------------------------

def _inject_blind(
  url:      str,
  opts:     ScanOptions,
  injector: Injector,
  result:   ScanResult,
  log:      Callable[[str], None],
) -> None:
  cb = opts.blind_callback
  payloads = blind_payloads(cb)

  surfaces: List[Dict[str, Any]] = []
  for param in injector.get_params(url):
    surfaces.append({"url": url, "method": "GET", "param": param})
  if opts.data:
    post_params = parse_post_data(opts.data)
    for param in post_params:
      surfaces.append({"url": url, "method": "POST", "param": param})

  for surface in surfaces:
    for payload in payloads:
      try:
        if surface["method"] == "POST":
          injector.inject_post(surface["url"], surface["param"], payload)
        else:
          injector.inject_get(surface["url"], surface["param"], payload)

        result.blind.append(BlindFinding(
          url=surface["url"],
          parameter=surface["param"],
          method=surface["method"],
          payload=payload,
          callback=cb,
        ))
        log(f"[*] Blind payload injected: {surface['param']} @ {surface['url']}")
        break  # one blind payload per param is enough
      except Exception:
        continue


# ---------------------------------------------------------------------------
# Logging helper
# ---------------------------------------------------------------------------

def _make_logger(
  result:  ScanResult,
  on_log:  Optional[Callable[[str], None]],
) -> Callable[[str], None]:
  def _log(msg: str) -> None:
    result.log.append(msg)
    logger.debug(msg)
    if on_log:
      on_log(msg)
  return _log
