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

import html
import json
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Optional

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
    headers:         dict[str, str] | None = None,
    cookies:         str  = "",
    proxy:           str  = "",
    threads:         int  = 5,
    timeout:         int  = 15,
    level:           int  = 1,           # 1=fast 2=thorough 3=deep
    custom_payloads: list[str] | None = None,
    max_pages:       int  = 50,
    max_depth:       int  = 3,
    delay:           float = 0.0,        # seconds between requests
    output:          str  = "",          # path to write JSON results
    on_log:          Callable[[str], None] | None = None,
    exclude_patterns: list[Any] | None = None,  # compiled re.Pattern list
    inject_headers:  list[str] | None = None,   # header names to inject into
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
    self.delay           = max(0.0, delay)
    self.output          = output.strip()
    self.on_log          = on_log  # callback for live log lines
    self.exclude_patterns: list[Any] = exclude_patterns or []
    self.inject_headers: list[str] = inject_headers or []


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def scan(url: str, options: ScanOptions | None = None) -> ScanResult:
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
    delay=options.delay,
  )

  try:
    _run(url, options, injector, result, _log)
  except Exception as exc:
    result.append_error(f"Scan aborted: {exc}")
    logger.exception("StingXSS scan error")
  finally:
    injector.close()
    result.requests_sent = injector.request_count
    result.finish()

  # Write JSON output to file if requested
  if options.output:
    try:
      with open(options.output, "w", encoding="utf-8") as fh:
        json.dump(result.to_dict(), fh, indent=2)
    except OSError as exc:
      result.append_error(f"Failed to write output file: {exc}")

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
    log(f"[*] Evasion strategies: {', '.join(waf_result.evasions)}")
  else:
    log("[*] No WAF detected")

  # All evasion strategies to try in order (first is highest priority)
  evasions: list[str] = waf_result.evasions if waf_result.evasions else ["none"]

  # ---- 2. Build initial surface (URL params + optional crawler) ----------
  # Surfaces: list of (url, method, {param: default_value})
  surfaces: list[dict[str, Any]] = []

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
  crawl_result: Any = None
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
          "params":       {**form.base_data, **form.params},
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

  def test_surface(surface: dict[str, Any]) -> None:
    _test_param(surface, evasions, opts, injector, result, log)

  with ThreadPoolExecutor(max_workers=opts.threads) as pool:
    futs = [pool.submit(test_surface, s) for s in surfaces]
    for f in as_completed(futs):
      try:
        f.result()
      except Exception as exc:
        result.append_error(str(exc))

  # ---- 3b. Header injection testing (optional) ---------------------------
  if opts.inject_headers:
    log(f"[*] Testing {len(opts.inject_headers)} header(s) for reflection: "
        f"{', '.join(opts.inject_headers)}")
    for hdr in opts.inject_headers:
      _test_header(url, hdr, evasions, opts, injector, result, log)

  # ---- 4. DOM XSS static analysis ----------------------------------------
  log(f"[*] Running DOM XSS analysis on {len(page_sources)} pages")

  def _js_fetcher(js_url: str) -> str:
    """Fetch an external JS file and return its text content."""
    try:
      resp = injector.get(js_url)
      if resp.status_code < 400:
        return resp.text
    except Exception:
      pass
    return ""

  for page_url, html in page_sources.items():
    dom_result = dom_mod.scan_page(page_url, html, fetcher=_js_fetcher)
    for finding in dom_result.sink_findings:
      result.append_dom(finding)
      log(f"[+] DOM XSS: {finding.source} → {finding.sink} @ {page_url}:{finding.line}")

  # ---- 5. Blind XSS injection --------------------------------------------
  if opts.blind_callback:
    log(f"[*] Injecting blind XSS payloads (callback: {opts.blind_callback})")
    _inject_blind(url, opts, injector, result, log, crawl_result=crawl_result)

  # ---- Summary -----------------------------------------------------------
  log(f"[*] Scan complete — {result.total_findings} finding(s), "
      f"{result.requests_sent} requests sent")


# ---------------------------------------------------------------------------
# Header injection test
# ---------------------------------------------------------------------------

def _test_header(
  url:      str,
  header:   str,
  evasions: list[str],
  opts:     ScanOptions,
  injector: Injector,
  result:   ScanResult,
  log:      Callable[[str], None],
) -> None:
  reflected, probe_resp = injector.probe_header_reflection(url, header, PROBE_MARKER)
  if not reflected:
    return

  log(f"[~] Reflected header: {header} @ {url}")
  _ct = probe_resp.headers.get("content-type", "").lower()
  if "application/json" in _ct and "text/html" not in _ct:
    log(f"[~] Skipping header {header}: JSON response")
    return

  context = find_context(probe_resp.text, PROBE_MARKER)
  log(f"[~] Header context: {context}")

  for evasion in evasions:
    marker   = make_confirm_marker()
    payloads = generate(context=context, evasion=evasion, marker=marker,
                        custom_payloads=opts.custom_payloads, level=opts.level)
    confirmed_this = False
    for payload in payloads:
      try:
        resp = injector.inject_header(url, header, payload)
      except Exception:
        continue

      _text = html.unescape(resp.text)
      _marker_present = marker.lower() in _text.lower()
      _tag_literal = _extract_tag_literal(payload)
      _tag_open_literal = (_tag_literal.lower() in _text.lower()) if _tag_literal else True
      confirmed = _marker_present and _tag_open_literal

      idx = _text.lower().find(payload[:20].lower())
      evidence = _text[max(0, idx - 30): idx + 80].strip() if idx != -1 else ""

      finding = ReflectedFinding(
        url=url,
        parameter=f"[header] {header}",
        method="GET",
        context=context,
        payload=payload,
        confirmed=confirmed,
        evidence=evidence,
      )
      result.append_reflected(finding)
      if confirmed:
        log(f"[+] XSS CONFIRMED (header): {header} @ {url} — {payload[:60]}")
        confirmed_this = True
        break
      else:
        log(f"[~] Header payload reflected (unconfirmed): {payload[:60]}")
    if confirmed_this:
      break


# ---------------------------------------------------------------------------
# Per-parameter test
# ---------------------------------------------------------------------------

def _test_param(
  surface:  dict[str, Any],
  evasions: list[str],
  opts:     ScanOptions,
  injector: Injector,
  result:   ScanResult,
  log:      Callable[[str], None],
) -> None:
  target_url    = surface["url"]
  method        = surface["method"]
  param         = surface["single_param"]
  base_params   = {k: v for k, v in surface["params"].items() if k != param}

  # Honour exclude patterns
  if any(p.search(target_url) for p in opts.exclude_patterns):
    return

  # 3a. Probe for reflection
  reflected, probe_resp = injector.probe_reflection(
    url=target_url, param=param, marker=PROBE_MARKER,
    method=method, base_data=base_params if method == "POST" else None,
  )

  if not reflected:
    return

  log(f"[~] Reflected: {param} @ {target_url} [{method}]")

  # Skip if response is JSON — reflected markers in JSON bodies are not
  # directly exploitable as XSS in a browser (no HTML parsing).
  _ct = probe_resp.headers.get("content-type", "").lower()
  if "application/json" in _ct and "text/html" not in _ct:
    log(f"[~] Skipping {param}: JSON response (not exploitable as HTML XSS)")
    return

  # 3b. Context analysis
  context = find_context(probe_resp.text, PROBE_MARKER)
  log(f"[~] Context: {context}")

  # 3c. Try each evasion strategy in order, stopping once we get a confirmed hit
  for evasion in evasions:
    if evasion != evasions[0]:
      log(f"[~] Trying evasion strategy: {evasion}")

    marker   = make_confirm_marker()
    payloads = generate(
      context=context,
      evasion=evasion,
      marker=marker,
      custom_payloads=opts.custom_payloads,
      level=opts.level,
    )

    confirmed_this_evasion = False

    # 3d. Inject each payload and check for confirmation marker
    for payload in payloads:
      try:
        if method == "POST":
          resp = injector.inject_post(target_url, param, payload, base_params)
        else:
          resp = injector.inject_get(target_url, param, payload)
      except Exception:
        continue

      _text = html.unescape(resp.text)
      _marker_present = marker.lower() in _text.lower()
      _tag_literal    = _extract_tag_literal(payload)
      if _tag_literal:
        _tag_open_literal = _tag_literal.lower() in _text.lower()
      else:
        # No HTML tag in payload — marker unencoded is sufficient confirmation
        _tag_open_literal = True
      confirmed = _marker_present and _tag_open_literal

      # Capture a small evidence snippet (from the unescaped text)
      idx = _text.lower().find(payload[:20].lower())
      evidence = _text[max(0, idx - 30): idx + 80].strip() if idx != -1 else ""

      finding = ReflectedFinding(
        url=target_url,
        parameter=param,
        method=method,
        context=context,
        payload=payload,
        confirmed=confirmed,
        evidence=evidence,
      )
      result.append_reflected(finding)

      if confirmed:
        log(f"[+] XSS CONFIRMED: {param} @ {target_url} — {payload[:60]}")
        confirmed_this_evasion = True
        # Stop testing more payloads for this param once confirmed
        break
      else:
        log(f"[~] Payload reflected (unconfirmed): {payload[:60]}")

    if confirmed_this_evasion:
      # No need to try remaining evasion strategies
      break


# ---------------------------------------------------------------------------
# Blind XSS
# ---------------------------------------------------------------------------

def _inject_blind(
  url:      str,
  opts:     ScanOptions,
  injector: Injector,
  result:   ScanResult,
  log:      Callable[[str], None],
  crawl_result: Any = None,
) -> None:
  cb = opts.blind_callback
  payloads = blind_payloads(cb)

  surfaces: list[dict[str, Any]] = []
  for param in injector.get_params(url):
    surfaces.append({"url": url, "method": "GET", "param": param, "base_data": {}})
  if opts.data:
    post_params = parse_post_data(opts.data)
    for param in post_params:
      surfaces.append({"url": url, "method": "POST", "param": param, "base_data": post_params})

  # Also cover forms discovered during crawl
  if crawl_result is not None:
    for form in crawl_result.form_targets:
      for param in form.params:
        surfaces.append({
          "url":       form.action,
          "method":    form.method,
          "param":     param,
          "base_data": {**form.base_data, **form.params},
        })

  for surface in surfaces:
    for payload in payloads:
      try:
        if surface["method"] == "POST":
          injector.inject_post(surface["url"], surface["param"], payload, surface["base_data"])
        else:
          injector.inject_get(surface["url"], surface["param"], payload)

        result.append_blind(BlindFinding(
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
  on_log:  Callable[[str], None] | None,
) -> Callable[[str], None]:
  def _log(msg: str) -> None:
    result.append_log(msg)
    logger.debug(msg)
    if on_log:
      on_log(msg)
  return _log


# ---------------------------------------------------------------------------
# Payload tag extraction helper
# ---------------------------------------------------------------------------

_TAG_OPEN_RE = re.compile(r"<([a-zA-Z][\w:-]*)", re.ASCII)


def _extract_tag_literal(payload: str) -> str:
  """
  Return the first '<tagname' literal in the payload (lowercased), or '' if
  the payload contains no HTML tags (e.g. script-context breakout payloads
  like ``"-alert(1)-"``).
  """
  m = _TAG_OPEN_RE.search(payload)
  if m:
    return m.group(0).lower()  # e.g. '<img', '<svg', '<script'
  return ""
