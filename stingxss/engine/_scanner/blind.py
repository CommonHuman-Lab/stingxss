# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Blind XSS payload injection."""

from __future__ import annotations

from typing import Any

from ..log import get_logger
from ..analysis.payload_gen import blind_payloads
from ..http.injector import Injector, parse_post_data
from ..reporter import BlindFinding, ScanResult
from .options import ScanOptions

logger = get_logger("stingxss.scanner")


def inject_blind(
  url:          str,
  opts:         ScanOptions,
  injector:     Injector,
  result:       ScanResult,
  crawl_result: Any = None,
) -> None:
  cb       = opts.blind_callback
  payloads = blind_payloads(cb)

  surfaces: list[dict[str, Any]] = []
  for param in injector.get_params(url):
    surfaces.append({"url": url, "method": "GET", "param": param, "base_data": {}})
  if opts.data:
    post_params = parse_post_data(opts.data)
    for param in post_params:
      surfaces.append({"url": url, "method": "POST", "param": param, "base_data": post_params})

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
          url=surface["url"], parameter=surface["param"],
          method=surface["method"], payload=payload, callback=cb,
        ))
        logger.finding("Blind XSS payload injected: %s @ %s", surface["param"], surface["url"])
        break
      except Exception:
        continue
