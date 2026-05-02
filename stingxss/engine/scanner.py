# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
# Scan orchestrator — WAF detection → crawl → reflection/XSS → DOM → blind XSS

from __future__ import annotations

import html
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Optional

from .log import ScanResultHandler, get_logger

from . import crawler as crawler_mod
from .analysis import dom_scanner as dom_mod
from .http import waf_detect
from .checks import clickjacking as cj_mod
from .checks import cors as cors_mod
from .checks import hsts as hsts_mod
from .checks import jsonp_some as jsonp_mod
from .checks import mixed_content as mc_mod
from .checks import vuln_libs as vl_mod
from .checks import sri as sri_mod
from .checks import leaked_cookie as lc_mod
from .checks import redirect as redirect_mod
from .http.injector import Injector, parse_post_data
from .analysis.parser import PROBE_MARKER, find_context, is_reflected, page_uses_angular
from .analysis.payload_gen import blind_payloads, generate, make_confirm_marker
from .reporter import (
  BlindFinding,
  HstsFinding,
  ReflectedFinding,
  ReflectionContext,
  ScanResult,
)

logger = get_logger("stingxss.scanner")


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
    delay:           float = 0.0,
    output:          str  = "",
    exclude_patterns: list[Any] | None = None,
    inject_headers:  list[str] | None = None,
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

  # Attach result log handler to the package-root logger so every child
  # logger (scanner, crawler, injector, …) feeds into result.log.
  _root_logger = get_logger("stingxss")
  _handler = ScanResultHandler(result)
  _handler.setFormatter(__import__("logging").Formatter("%(name)s: %(message)s"))
  _root_logger.addHandler(_handler)

  injector = Injector(
    timeout=options.timeout,
    proxy=options.proxy or None,
    headers=options.headers or None,
    cookies=options.cookies or None,
    delay=options.delay,
  )

  try:
    _run(url, options, injector, result)
  except Exception as exc:
    result.append_error(f"Scan aborted: {exc}")
    logger.exception("StingXSS scan error")
  finally:
    # Remove handler first so result.finish() messages don't double-log.
    _root_logger.removeHandler(_handler)
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
) -> None:

  # ---- 1. WAF detection --------------------------------------------------
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

  # ---- 1b–1j. Passive header / page checks --------------------------------
  seed_resp = _fetch_seed(injector, url)
  _run_passive_checks(url, seed_resp, injector, result)

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
    logger.info("Crawling %s (max_pages=%s, depth=%s)", url, opts.max_pages, opts.max_depth)
    crawl_result = crawler_mod.crawl(
      start_url=url,
      injector=injector,
      max_pages=opts.max_pages,
      max_depth=opts.max_depth,
      threads=opts.threads,
    )
    result.crawled_urls = len(crawl_result.visited_urls)
    page_sources.update(crawl_result.page_sources)
    logger.info("Crawled %d URLs, found %d forms", result.crawled_urls, len(crawl_result.form_targets))

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
    # Use already-fetched seed page for DOM analysis
    if seed_resp is not None:
      page_sources[url] = seed_resp.text

  logger.info("%d injectable surfaces identified", len(surfaces))

  # ---- 3. Reflection + XSS testing (threaded) ----------------------------
  result.params_tested = len(surfaces)

  def test_surface(surface: dict[str, Any]) -> None:
    _test_param(surface, evasions, opts, injector, result)

  with ThreadPoolExecutor(max_workers=opts.threads) as pool:
    futs = [pool.submit(test_surface, s) for s in surfaces]
    for f in as_completed(futs):
      try:
        f.result()
      except Exception as exc:
        result.append_error(str(exc))

  # ---- 3b. Header injection testing (optional) ---------------------------
  if opts.inject_headers:
    logger.info("Testing %d header(s) for reflection: %s",
                len(opts.inject_headers), ", ".join(opts.inject_headers))
    for hdr in opts.inject_headers:
      _test_header(url, hdr, evasions, opts, injector, result)

  # ---- 3c. Open redirect / javascript-redirect testing --------------------
  logger.info("Testing %d surface(s) for open redirect", len(surfaces))

  def test_redirect_surface(surface: dict[str, Any]) -> None:
    target_url  = surface["url"]
    param       = surface["single_param"]
    method      = surface["method"]
    base_params = {k: v for k, v in surface["params"].items() if k != param}
    if any(p.search(target_url) for p in opts.exclude_patterns):
      return
    redir_findings = redirect_mod.check_url(
      url=target_url,
      param=param,
      method=method,
      injector=injector,
      base_data=base_params if method == "POST" else None,
    )
    for rf in redir_findings:
      result.append_redirect(rf)
      logger.finding("Redirect (%s): %s @ %s → %s", rf.issue, param, target_url, rf.location[:60])
  with ThreadPoolExecutor(max_workers=opts.threads) as pool:
    futs = [pool.submit(test_redirect_surface, s) for s in surfaces]
    for f in as_completed(futs):
      try:
        f.result()
      except Exception as exc:
        result.append_error(str(exc))

  # ---- 4. DOM XSS static analysis ----------------------------------------
  logger.info("Running DOM XSS analysis on %d pages", len(page_sources))

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
      logger.finding("DOM XSS: %s → %s @ %s:%d", finding.source, finding.sink, page_url, finding.line)

  # ---- 5. Blind XSS injection --------------------------------------------
  if opts.blind_callback:
    logger.info("Injecting blind XSS payloads (callback: %s)", opts.blind_callback)
    _inject_blind(url, opts, injector, result, crawl_result=crawl_result)

  logger.info("Scan complete — %d finding(s), %d requests sent",
              result.total_findings, result.requests_sent)


# ---------------------------------------------------------------------------
# Passive check helpers
# ---------------------------------------------------------------------------

def _fetch_seed(injector: Injector, url: str):
  """Fetch the seed URL once; return the response or None on error."""
  try:
    return injector.get(url)
  except Exception:
    return None


def _run_passive_checks(url: str, seed_resp, injector, result: ScanResult) -> None:
  """Run all header/page passive checks against the seed response."""
  headers = dict(seed_resp.headers) if seed_resp else {}
  body    = seed_resp.text if seed_resp else ""

  # Clickjacking
  try:
    cj = cj_mod.check(url, headers)
    if cj:
      result.append_clickjacking(cj)
      logger.warning("Clickjacking: %s", cj.reason)
    else:
      logger.debug("Clickjacking: page appears protected against framing")
  except Exception:
    pass

  # HSTS
  try:
    for hf in hsts_mod.check(url, headers):
      result.append_hsts(hf)
      logger.warning("HSTS (%s): %s", hf.issue, hf.reason)
    if not result.hsts:
      logger.debug("HSTS: header present and well-configured")
  except Exception:
    pass

  # CORS
  try:
    for cf in cors_mod.check(url, injector):
      result.append_cors(cf)
      logger.warning("CORS (%s): %s", cf.issue, cf.reason)
    if not result.cors:
      logger.debug("CORS: no misconfigurations detected")
  except Exception:
    pass

  # JSONP/SOME
  try:
    for jf in jsonp_mod.check(url, injector):
      result.append_jsonp_some(jf)
      logger.warning("JSONP/SOME (%s): %s", jf.issue, jf.reason)
    if not result.jsonp_some:
      logger.debug("JSONP/SOME: no callback injection detected")
  except Exception:
    pass

  # Mixed content
  try:
    for mcf in mc_mod.check(url, body):
      result.append_mixed_content(mcf)
      logger.warning("Mixed content: <%s> loads %s", mcf.tag, mcf.resource_url)
    if not result.mixed_content:
      logger.debug("Mixed content: none detected")
  except Exception:
    pass

  # Vulnerable JS libraries
  try:
    for vf in vl_mod.check(url, body):
      result.append_vuln_lib(vf)
      logger.warning("Vulnerable library: %s %s (%s) @ %s", vf.library, vf.version, vf.source, url)
    if not result.vuln_libs:
      logger.debug("Vulnerable libraries: none detected")
  except Exception:
    pass

  # SRI
  try:
    for sf in sri_mod.check(url, body):
      result.append_sri(sf)
      logger.warning("SRI missing (%s): %s", sf.issue, sf.script_src)
    if not result.sri:
      logger.debug("SRI: no insecure third-party scripts detected")
  except Exception:
    pass

  # Leaked httpOnly cookie
  try:
    for lcf in lc_mod.check(url=url, response_headers=headers, response_body=body, injector=injector):
      result.append_leaked_cookie(lcf)
      logger.warning("Leaked httpOnly cookie '%s' (%s) @ %s", lcf.cookie_name, lcf.leak_type, url)
    if not result.leaked_cookie:
      logger.debug("Leaked cookie: no httpOnly cookie leaks detected")
  except Exception:
    pass


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
) -> None:
  reflected, probe_resp = injector.probe_header_reflection(url, header, PROBE_MARKER)
  if not reflected:
    return

  logger.debug("Reflected header: %s @ %s", header, url)
  _ct = probe_resp.headers.get("content-type", "").lower()
  if "application/json" in _ct and "text/html" not in _ct:
    logger.debug("Skipping header %s: JSON response", header)
    return

  context = find_context(probe_resp.text, PROBE_MARKER)
  logger.debug("Header context: %s", context)

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
        logger.finding("XSS CONFIRMED (header): %s @ %s — %s", header, url, payload[:60])
        confirmed_this = True
        break
      else:
        logger.debug("Header payload reflected (unconfirmed): %s", payload[:60])
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
) -> None:
  target_url    = surface["url"]
  method        = surface["method"]
  param         = surface["single_param"]
  base_params   = {k: v for k, v in surface["params"].items() if k != param}

  if any(p.search(target_url) for p in opts.exclude_patterns):
    return

  reflected, probe_resp = injector.probe_reflection(
    url=target_url, param=param, marker=PROBE_MARKER,
    method=method, base_data=base_params if method == "POST" else None,
  )

  if not reflected:
    return

  logger.debug("Reflected: %s @ %s [%s]", param, target_url, method)

  _ct = probe_resp.headers.get("content-type", "").lower()
  if "application/json" in _ct and "text/html" not in _ct:
    logger.debug("Skipping %s: JSON response", param)
    return

  context = find_context(probe_resp.text, PROBE_MARKER)
  logger.debug("Context: %s", context)

  # Angular template injection payloads — the marker may be reflected as raw
  # body text on an ng-app page where {{ }} aren't added server-side.
  extra_contexts: list[ReflectionContext] = []
  if page_uses_angular(probe_resp.text) and context in (
    ReflectionContext.HTML_BODY,
    ReflectionContext.ATTR_DOUBLE,
    ReflectionContext.ATTR_SINGLE,
    ReflectionContext.ATTR_UNQUOTED,
    ReflectionContext.UNKNOWN,
  ):
    RC = ReflectionContext  # alias for brevity below
    # Try both standard and alt-symbol Angular payloads
    extra_contexts = [RC.ANGULAR_TEMPLATE, RC.ANGULAR_TEMPLATE_ALT]

  # 3c. Try each evasion strategy in order, stopping once we get a confirmed hit
  for evasion in evasions:
    if evasion != evasions[0]:
      logger.debug("Trying evasion strategy: %s", evasion)

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
        logger.finding("XSS CONFIRMED: %s @ %s — %s", param, target_url, payload[:60])
        confirmed_this_evasion = True
        break
      else:
        logger.debug("Payload reflected (unconfirmed): %s", payload[:60])

    if confirmed_this_evasion:
      # No need to try remaining evasion strategies
      break

  # 3e. Extra-context payloads (e.g. Angular SSTI) — injected regardless of
  #     the primary context when the page is detected as an Angular app.
  for extra_ctx in extra_contexts:
    for evasion in evasions:
      marker   = make_confirm_marker()
      payloads = generate(
        context=extra_ctx,
        evasion=evasion,
        marker=marker,
        custom_payloads=opts.custom_payloads,
        level=opts.level,
      )
      confirmed_extra = False
      for payload in payloads:
        try:
          if method == "POST":
            resp = injector.inject_post(target_url, param, payload, base_params)
          else:
            resp = injector.inject_get(target_url, param, payload)
        except Exception:
          continue

        _text = html.unescape(resp.text)
        # Angular template payloads don't contain HTML tags — marker presence
        # in the unescaped response is the confirmation signal.
        confirmed = marker.lower() in _text.lower()

        idx = _text.lower().find(payload[:20].lower())
        evidence = _text[max(0, idx - 30): idx + 80].strip() if idx != -1 else ""

        finding = ReflectedFinding(
          url=target_url,
          parameter=param,
          method=method,
          context=extra_ctx,
          payload=payload,
          confirmed=confirmed,
          evidence=evidence,
        )
        result.append_reflected(finding)

        if confirmed:
          logger.finding("XSS CONFIRMED (Angular SSTI): %s @ %s — %s", param, target_url, payload[:60])
          confirmed_extra = True
          break
        else:
          logger.debug("Angular payload reflected (unconfirmed): %s", payload[:60])

      if confirmed_extra:
        break  # no need to try more evasions for this extra context


# ---------------------------------------------------------------------------
# Blind XSS
# ---------------------------------------------------------------------------

def _inject_blind(
  url:      str,
  opts:     ScanOptions,
  injector: Injector,
  result:   ScanResult,
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
        logger.finding("Blind XSS payload injected: %s @ %s", surface["param"], surface["url"])
        break  # one blind payload per param is enough
      except Exception:
        continue


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
