# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Active XSS reflection testing: per-param and per-header injection."""

from __future__ import annotations

import html
import re
from typing import Any

from ..log import get_logger
from ..analysis.parser import PROBE_MARKER, find_context, page_uses_angular
from ..analysis.payload_gen import generate, make_confirm_marker
from ..http.injector import Injector
from ..http import waf_detect as _waf_detect
from ..reporter import ReflectedFinding, ReflectionContext, ScanResult
from .options import ScanOptions

logger = get_logger("stingxss.scanner")

_TAG_OPEN_RE = re.compile(r"<([a-zA-Z][\w:-]*)", re.ASCII)
_SHORT_XSS = "<svg onload=1>"
_LENGTH_LIMIT_THRESHOLD = 20


def _extract_tag_literal(payload: str) -> str:
  """Return the first '<tagname' from payload, or '' if none."""
  m = _TAG_OPEN_RE.search(payload)
  return m.group(0).lower() if m else ""


def _confirm(text: str, marker: str, payload: str) -> tuple[bool, str]:
  """Return (confirmed, evidence_snippet)."""
  unesc = html.unescape(text)
  tag   = _extract_tag_literal(payload)
  ok    = marker.lower() in unesc.lower() and (not tag or tag in unesc.lower())
  idx   = unesc.lower().find(payload[:20].lower())
  snip  = unesc[max(0, idx - 30): idx + 80].strip() if idx != -1 else ""
  return ok, snip


def test_param(
  surface:  dict[str, Any],
  evasions: list[str],
  opts:     ScanOptions,
  injector: Injector,
  result:   ScanResult,
) -> None:
  target_url  = surface["url"]
  method      = surface["method"]
  param       = surface["single_param"]
  base_params = {k: v for k, v in surface["params"].items() if k != param}

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

  # Detect server-side length truncation
  _probe_in_resp = PROBE_MARKER.lower() in html.unescape(probe_resp.text).lower()
  if not _probe_in_resp:
    # Probe wasn't reflected after all — shouldn't normally reach here, but guard.
    pass
  else:
    # Estimate max input length: re-inject a 30-char probe and check if it is
    # truncated in the response.
    _long_probe = "A" * 30
    try:
      _lp_resp = (injector.inject_post(target_url, param, _long_probe, base_params)
                  if method == "POST"
                  else injector.inject_get(target_url, param, _long_probe))
      _lp_body = html.unescape(_lp_resp.text)
      _reflected_len = 0
      for i in range(len(_long_probe), 0, -1):
        if "A" * i in _lp_body:
          _reflected_len = i
          break
      if 0 < _reflected_len <= _LENGTH_LIMIT_THRESHOLD:
        # Try the short known-working payload
        try:
          _sr = (injector.inject_post(target_url, param, _SHORT_XSS, base_params)
                 if method == "POST"
                 else injector.inject_get(target_url, param, _SHORT_XSS))
          _sr_body = html.unescape(_sr.text)
          _short_ok = _SHORT_XSS.lower() in _sr_body.lower()
          _idx = _sr_body.lower().find(_SHORT_XSS[:8].lower())
          _snip = _sr_body[max(0, _idx - 20): _idx + 40].strip() if _idx != -1 else ""
          result.append_reflected(ReflectedFinding(
            url=target_url, parameter=param, method=method,
            context=context, payload=_SHORT_XSS,
            confirmed=_short_ok,
            evidence=f"[LENGTH-LIMITED max~{_reflected_len}] {_snip}",
          ))
          if _short_ok:
            logger.finding(
              "XSS CONFIRMED (length-limited, max~%d): %s @ %s — %s",
              _reflected_len, param, target_url, _SHORT_XSS,
            )
        except Exception:
          pass
        return  # Don't waste time on full payload list — marker can't fit
    except Exception:
      pass

  extra_contexts: list[ReflectionContext] = []
  if page_uses_angular(probe_resp.text) and context in (
    ReflectionContext.HTML_BODY, ReflectionContext.ATTR_DOUBLE,
    ReflectionContext.ATTR_SINGLE, ReflectionContext.ATTR_UNQUOTED,
    ReflectionContext.UNKNOWN,
  ):
    extra_contexts = [ReflectionContext.ANGULAR_TEMPLATE, ReflectionContext.ANGULAR_TEMPLATE_ALT]

  # Primary context payloads
  for evasion in evasions:
    if evasion != evasions[0]:
      logger.debug("Trying evasion strategy: %s", evasion)
    marker   = make_confirm_marker()
    payloads = generate(context=context, evasion=evasion, marker=marker,
                        custom_payloads=opts.custom_payloads, level=opts.level)
    confirmed_this = False
    for payload in payloads:
      try:
        resp = (injector.inject_post(target_url, param, payload, base_params)
                if method == "POST"
                else injector.inject_get(target_url, param, payload))
      except Exception:
        continue
      ok, snip = _confirm(resp.text, marker, payload)
      result.append_reflected(ReflectedFinding(
        url=target_url, parameter=param, method=method,
        context=context, payload=payload, confirmed=ok, evidence=snip,
      ))
      if ok:
        logger.finding("XSS CONFIRMED: %s @ %s — %s", param, target_url, payload[:60])
        confirmed_this = True
        break
      logger.debug("Payload reflected (unconfirmed): %s", payload[:60])
    if confirmed_this:
      break

  # Per-surface WAF fallback (w1d style): if nothing confirmed, re-probe this
  # specific URL — the global WAF probe runs against the seed URL and misses
  # per-challenge WAFs.  If a new evasion is detected (e.g. double-encode),
  # retry with it.
  _per_surface_extra_evasions: list[str] = []
  if not confirmed_this:
    try:
      _local_waf = _waf_detect.detect(injector, target_url, param)
      _per_surface_extra_evasions = [
        e for e in _local_waf.evasions
        if e not in evasions and e != _waf_detect.EVASION_NONE
      ]
    except Exception:
      pass

  for evasion in _per_surface_extra_evasions:
    logger.debug("Per-surface evasion fallback: %s @ %s", evasion, target_url)
    marker   = make_confirm_marker()
    payloads = generate(context=context, evasion=evasion, marker=marker,
                        custom_payloads=opts.custom_payloads, level=opts.level)
    confirmed_this = False
    for payload in payloads:
      try:
        resp = (injector.inject_post(target_url, param, payload, base_params)
                if method == "POST"
                else injector.inject_get(target_url, param, payload))
      except Exception:
        continue
      ok, snip = _confirm(resp.text, marker, payload)
      result.append_reflected(ReflectedFinding(
        url=target_url, parameter=param, method=method,
        context=context, payload=payload, confirmed=ok, evidence=snip,
      ))
      if ok:
        logger.finding("XSS CONFIRMED (per-surface WAF bypass %s): %s @ %s — %s",
                       evasion, param, target_url, payload[:60])
        confirmed_this = True
        break
    if confirmed_this:
      break

  # Extra-context payloads (Angular SSTI)
  for extra_ctx in extra_contexts:
    for evasion in evasions:
      marker   = make_confirm_marker()
      payloads = generate(context=extra_ctx, evasion=evasion, marker=marker,
                          custom_payloads=opts.custom_payloads, level=opts.level)
      confirmed_extra = False
      for payload in payloads:
        try:
          resp = (injector.inject_post(target_url, param, payload, base_params)
                  if method == "POST"
                  else injector.inject_get(target_url, param, payload))
        except Exception:
          continue
        unesc = html.unescape(resp.text)
        ok    = marker.lower() in unesc.lower()
        idx   = unesc.lower().find(payload[:20].lower())
        snip  = unesc[max(0, idx - 30): idx + 80].strip() if idx != -1 else ""
        result.append_reflected(ReflectedFinding(
          url=target_url, parameter=param, method=method,
          context=extra_ctx, payload=payload, confirmed=ok, evidence=snip,
        ))
        if ok:
          logger.finding("XSS CONFIRMED (Angular SSTI): %s @ %s — %s", param, target_url, payload[:60])
          confirmed_extra = True
          break
        logger.debug("Angular payload reflected (unconfirmed): %s", payload[:60])
      if confirmed_extra:
        break


def test_header(
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
      ok, snip = _confirm(resp.text, marker, payload)
      result.append_reflected(ReflectedFinding(
        url=url, parameter=f"[header] {header}", method="GET",
        context=context, payload=payload, confirmed=ok, evidence=snip,
      ))
      if ok:
        logger.finding("XSS CONFIRMED (header): %s @ %s — %s", header, url, payload[:60])
        confirmed_this = True
        break
      logger.debug("Header payload reflected (unconfirmed): %s", payload[:60])
    if confirmed_this:
      break
