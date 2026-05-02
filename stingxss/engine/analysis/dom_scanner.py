# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
# Static DOM XSS analysis — no browser required.
# Scans inline/external JS for source→sink flows via proximity and variable tracking.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from ..reporter import DomFinding
from ._dom.html_scan import extract_inline_scripts, extract_script_srcs, scan_html_attributes
from ._dom.analysis import analyse_js


@dataclass
class DomScanResult:
  url:           str
  sink_findings: List[DomFinding] = field(default_factory=list)
  sinks_found:   List[str]        = field(default_factory=list)
  sources_found: List[str]        = field(default_factory=list)


def scan_page(url: str, html: str, fetcher=None) -> DomScanResult:
  """Scan a full HTML page for DOM XSS. Fetches external JS if `fetcher` provided."""
  result = DomScanResult(url=url)

  for script_src in extract_inline_scripts(html):
    analyse_js(url, script_src, result)

  if fetcher:
    for script_url in extract_script_srcs(html, url):
      try:
        js_src = fetcher(script_url)
        if js_src:
          analyse_js(script_url, js_src, result)
      except Exception:
        pass

  scan_html_attributes(url, html, result)
  return result


def scan_js(url: str, js_source: str) -> DomScanResult:
  """Scan a standalone JS source for DOM XSS indicators."""
  result = DomScanResult(url=url)
  analyse_js(url, js_source, result)
  return result
