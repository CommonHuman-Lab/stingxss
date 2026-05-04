# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Stored XSS, prototype pollution, and localStorage/sessionStorage injection testing.

Strategy:
  1. Inject stored-XSS payloads into every surface (GET/POST params, form fields).
  2. Revisit the seed URL and all crawled pages to detect delayed rendering.
  3. Inject prototype-pollution parameter pairs (?__proto__[key]=value) and check
     for reflection/execution on the same response.
  4. Inject localStorage-seeding payloads and check for execution via revisit.
"""

from __future__ import annotations

import html
from typing import Any

from ..log import get_logger
from ..analysis.payload_gen import (
  make_confirm_marker,
  stored_xss_payloads,
  prototype_pollution_params,
)
from ..http.injector import Injector, parse_post_data
from ..reporter import StoredFinding, ScanResult
from .options import ScanOptions

logger = get_logger("stingxss.scanner")

_REVISIT_LIMIT = 100   # max number of pages to revisit per surface


def _marker_in(text: str, marker: str) -> tuple[bool, str]:
  """Return (found, snippet) — True if unescaped marker present."""
  unesc = html.unescape(text)
  found = marker.lower() in unesc.lower()
  idx   = unesc.lower().find(marker.lower())
  snip  = unesc[max(0, idx - 40): idx + 80].strip() if idx != -1 else ""
  return found, snip


def run_stored(
  seed_url:     str,
  surfaces:     list[dict[str, Any]],
  page_sources: dict[str, str],
  opts:         ScanOptions,
  injector:     Injector,
  result:       ScanResult,
  crawl_result: Any = None,
) -> None:
  """
  Inject stored XSS payloads into all surfaces and revisit pages to confirm.
  """
  revisit_urls = list(page_sources.keys())[:_REVISIT_LIMIT] or [seed_url]

  for surface in surfaces:
    target_url  = surface["url"]
    param       = surface["single_param"]
    method      = surface["method"]
    base_params = {k: v for k, v in surface["params"].items() if k != param}

    if any(p.search(target_url) for p in opts.exclude_patterns):
      continue

    marker   = make_confirm_marker()
    payloads = stored_xss_payloads(marker)

    for payload in payloads:
      try:
        if method == "POST":
          injector.inject_post(target_url, param, payload, base_params)
        else:
          injector.inject_get(target_url, param, payload)
      except Exception:
        continue

      # Revisit pages to check for stored rendering
      confirmed = False
      for revisit_url in revisit_urls:
        try:
          resp = injector.get(revisit_url)
        except Exception:
          continue
        found, snip = _marker_in(resp.text, marker)
        result.append_stored(StoredFinding(
          inject_url=target_url, revisit_url=revisit_url,
          parameter=param, method=method,
          payload=payload, confirmed=found, evidence=snip,
        ))
        if found:
          logger.finding(
            "STORED XSS CONFIRMED: %s @ %s → found on %s — %s",
            param, target_url, revisit_url, payload[:60],
          )
          confirmed = True
          break
      if confirmed:
        break   # one confirmed finding per surface is sufficient


def run_prototype_pollution(
  seed_url:  str,
  opts:      ScanOptions,
  injector:  Injector,
  result:    ScanResult,
) -> None:
  """
  Inject prototype-pollution parameter pairs (?__proto__[key]=value) into the
  seed URL and check the immediate response for payload rendering.
  """
  if any(p.search(seed_url) for p in opts.exclude_patterns):
    return

  marker = make_confirm_marker()
  pairs  = prototype_pollution_params(marker)

  for param_name, value in pairs:
    # Build a URL with the pollution param appended
    sep = "&" if "?" in seed_url else "?"
    url = f"{seed_url}{sep}{param_name}={value}"
    try:
      resp = injector.get(url)
    except Exception:
      continue
    found, snip = _marker_in(resp.text, marker)
    if found:
      result.append_stored(StoredFinding(
        inject_url=url, revisit_url=url,
        parameter=param_name, method="GET",
        payload=value, confirmed=True, evidence=snip,
      ))
      logger.finding(
        "PROTOTYPE POLLUTION XSS CONFIRMED: %s @ %s — %s",
        param_name, seed_url, value[:60],
      )


def run_localstorage(
  seed_url:  str,
  opts:      ScanOptions,
  injector:  Injector,
  result:    ScanResult,
) -> None:
  """
  Inject localStorage-seeding payloads as URL parameter values and check
  for execution on a page revisit (the page must read from localStorage).
  """
  if any(p.search(seed_url) for p in opts.exclude_patterns):
    return

  marker = make_confirm_marker()
  # These payloads tell the app to store tainted data and then render it
  ls_payloads = [
    f"<img src=x onerror=alert('{marker}')>",
    f"</script><script>alert('{marker}')</script>",
    f"<svg onload=alert('{marker}')>",
  ]
  # Try to poison common localStorage keys via query parameters
  ls_params = ["q", "search", "name", "value", "data", "input", "text", "msg", "message"]

  for param in ls_params:
    for payload in ls_payloads:
      try:
        resp = injector.inject_get(seed_url, param, payload)
      except Exception:
        continue
      found, snip = _marker_in(resp.text, marker)
      if not found:
        # Try revisit
        try:
          resp2 = injector.get(seed_url)
          found, snip = _marker_in(resp2.text, marker)
        except Exception:
          pass
      if found:
        result.append_stored(StoredFinding(
          inject_url=seed_url, revisit_url=seed_url,
          parameter=param, method="GET",
          payload=payload, confirmed=True, evidence=snip,
        ))
        logger.finding(
          "LOCALSTORAGE XSS CONFIRMED: %s @ %s — %s",
          param, seed_url, payload[:60],
        )
        return   # one find is enough
