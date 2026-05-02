# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
# Static DOM XSS analysis — no browser required.
# Scans inline/external JS for source→sink flows via proximity and variable tracking.

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List

from ..reporter import DomFinding
from ._dom.html_scan import extract_inline_scripts, extract_script_srcs, scan_html_attributes
from ._dom.analysis import analyse_js

# Script URLs matching these patterns are known app bundles or framework/vendor
# files that produce mass false positives from variable tracking in minified code.
# Skipped by default; pass include_minified=True to scan them anyway.
_MINIFIED_BUNDLE_RE = re.compile(
  r'(?i)(?:'
  # Generic app bundles (Angular CLI, Create React App, Vite, etc.)
  r'main(?:\.min)?\.js|'
  r'scripts(?:\.min)?\.js|'
  r'app(?:\.min)?\.js|'
  r'bundle(?:\.min)?\.js|'
  r'index(?:\.min)?\.js|'
  # Named framework/vendor bundles
  r'vendor[.\-]|'
  r'polyfills[.\-]|'
  r'runtime[.\-]|'
  r'jquery(?:\.min)?\.js|'
  r'bootstrap(?:\.min)?\.js|'
  r'angular(?:\.min)?\.js|'
  r'react(?:\.min)?\.js|'
  r'vue(?:\.min)?\.js|'
  r'zone(?:\.min)?\.js|'
  # Webpack / Vite chunk filenames
  r'chunk-[0-9A-Fa-f]+\.js|'
  r'[0-9]+\.[0-9a-f]+\.js'
  r')'
)


@dataclass
class DomScanResult:
  url:           str
  sink_findings: List[DomFinding] = field(default_factory=list)
  sinks_found:   List[str]        = field(default_factory=list)
  sources_found: List[str]        = field(default_factory=list)


def _is_minified_bundle(url: str) -> bool:
  """Return True if the URL looks like a known minified app/vendor bundle."""
  path = url.split("?")[0].split("#")[0]
  filename = path.rsplit("/", 1)[-1]
  return bool(_MINIFIED_BUNDLE_RE.search(filename))


def scan_page(url: str, html: str, fetcher=None, include_minified: bool = False) -> DomScanResult:
  """Scan a full HTML page for DOM XSS. Fetches external JS if `fetcher` provided.

  Args:
    include_minified: If False (default), known app bundles and framework files
      (main.js, scripts.js, vendor.js, etc.) are skipped — they produce mass
      false positives from variable-tracking in minified code.  Pass True to
      scan them anyway (e.g. via ``--dom-include-minified``).
  """
  result = DomScanResult(url=url)

  for script_src in extract_inline_scripts(html):
    analyse_js(url, script_src, result)

  if fetcher:
    for script_url in extract_script_srcs(html, url):
      if not include_minified and _is_minified_bundle(script_url):
        continue
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
