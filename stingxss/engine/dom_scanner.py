# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
StingXSS — engine/dom_scanner.py
Static DOM XSS analysis — no browser required.

Scans HTML page sources and inline/external JavaScript for:
  - Dangerous sinks (innerHTML, document.write, eval, ...)
  - Attacker-controlled sources (location.*, document.referrer, ...)
  - Direct source→sink flows via:
      * Proximity analysis (source and sink within N lines)
      * Variable tracking (variable assigned from source, then used in sink)

Returns a list of DomFinding dataclasses.
"""

from __future__ import annotations

import re
import urllib.parse as up
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set, Tuple

from .reporter import DomFinding

# ---------------------------------------------------------------------------
# Sources — values the attacker can influence
# ---------------------------------------------------------------------------
_SOURCES: List[Tuple[str, str]] = [
  # (pattern, human_name)
  (r"location\.hash",           "location.hash"),
  (r"location\.search",         "location.search"),
  (r"location\.href",           "location.href"),
  (r"location\.pathname",       "location.pathname"),
  (r"window\.location(?![\.\[])", "window.location"),
  (r"document\.referrer",       "document.referrer"),
  (r"document\.URL\b",          "document.URL"),
  (r"document\.baseURI",        "document.baseURI"),
  (r"document\.documentURI",    "document.documentURI"),
  (r"document\.URLUnencoded",   "document.URLUnencoded"),
  (r"document\.cookie",         "document.cookie"),
  (r"document\.domain",         "document.domain"),
  (r"window\.name",             "window.name"),
  (r"history\.state",           "history.state"),
  (r"postMessage",              "postMessage"),
  (r"URLSearchParams",          "URLSearchParams"),
  (r"localStorage\.getItem",    "localStorage.getItem"),
  (r"sessionStorage\.getItem",  "sessionStorage.getItem"),
  (r"frames\[",                 "frames[n].name"),
]

# ---------------------------------------------------------------------------
# Sinks — dangerous execution / rendering points
# ---------------------------------------------------------------------------
_SINKS: List[Tuple[str, str]] = [
  # (pattern, human_name)
  (r"\.innerHTML\s*=",              "innerHTML"),
  (r"\.outerHTML\s*=",              "outerHTML"),
  (r"\.insertAdjacentHTML\s*\(",    "insertAdjacentHTML"),
  (r"document\.write\s*\(",         "document.write"),
  (r"document\.writeln\s*\(",       "document.writeln"),
  (r"\beval\s*\(",                  "eval"),
  (r"setTimeout\s*\(\s*['\"`]",     "setTimeout(string)"),
  (r"setInterval\s*\(\s*['\"`]",    "setInterval(string)"),
  (r"new\s+Function\s*\(",          "new Function()"),
  (r"\.setAttribute\s*\(\s*['\"]on","setAttribute(on...)"),
  (r"\.setAttribute\s*\(\s*['\"]src","setAttribute(src)"),
  (r"\.setAttribute\s*\(\s*['\"]href","setAttribute(href)"),
  (r"\.setAttribute\s*\(\s*['\"]action","setAttribute(action)"),
  (r"\.createContextualFragment\s*\(", "createContextualFragment"),
  (r"location\.href\s*=",           "location.href="),
  (r"(?<!location)\.href\s*=",      ".href="),
  (r"document\.location\s*=",       "document.location="),
  (r"location\.replace\s*\(",       "location.replace()"),
  (r"location\.assign\s*\(",        "location.assign()"),
  (r"window\.open\s*\(",            "window.open()"),
  (r"\.src\s*=",                    ".src="),
  (r"\.srcdoc\s*=",                 ".srcdoc="),
  (r"\.action\s*=",                 ".action="),
  (r"\.formAction\s*=",             ".formAction="),
  (r"\.data\s*=",                   ".data="),
  (r"\$\s*\(\s*['\"`][^'\"`]*location", "jQuery(location...)"),
  (r"\.html\s*\(",                  "jQuery.html()"),
  (r"dangerouslySetInnerHTML",      "React dangerouslySetInnerHTML"),
  (r"document\.execCommand\s*\(",   "document.execCommand"),
  (r"\$\$?\.globalEval\s*\(",       "$.globalEval()"),
  (r"angular\.element.*\.html\s*\(","angular.html()"),
]

# ---------------------------------------------------------------------------
# Patterns that indicate source→sink proximity in the same JS block
# (We look for a source followed by a sink within N lines)
# ---------------------------------------------------------------------------
_PROXIMITY_LINES = 20  # lines to look ahead from source

# Regex for simple variable assignment:  var/let/const name = <expr>
# Also catches:  name = <expr>
_VAR_ASSIGN_RE = re.compile(
  r'(?:(?:var|let|const)\s+)?([a-zA-Z_$][\w$]*)\s*=\s*(.+)',
)


@dataclass
class DomScanResult:
  url:           str
  sink_findings: List[DomFinding]   = field(default_factory=list)
  # Plain sink/source mentions (not necessarily exploitable flows)
  sinks_found:   List[str]          = field(default_factory=list)
  sources_found: List[str]          = field(default_factory=list)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_page(url: str, html: str, fetcher=None) -> DomScanResult:
  """
  Scan `html` (a full page body) for DOM XSS indicators.
  Extracts inline <script> blocks + analyses data-* / on* attributes.

  If `fetcher` is provided (callable: url -> str), external JS files
  referenced via <script src="..."> will be fetched and analysed.
  """
  result = DomScanResult(url=url)

  # 1. Extract all inline JS
  scripts = _extract_inline_scripts(html)

  # 2. Analyse each inline script block
  for script_src in scripts:
    _analyse_js(url, script_src, result)

  # 3. Fetch and analyse external JS files
  if fetcher:
    for script_url in _extract_script_srcs(html, url):
      try:
        js_src = fetcher(script_url)
        if js_src:
          _analyse_js(script_url, js_src, result)
      except Exception:
        pass

  # 4. Scan HTML attributes for inline handlers using location/window.name etc.
  _scan_html_attributes(url, html, result)

  return result


def scan_js(url: str, js_source: str) -> DomScanResult:
  """Scan a standalone JS file source for DOM XSS indicators."""
  result = DomScanResult(url=url)
  _analyse_js(url, js_source, result)
  return result


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------

def _extract_inline_scripts(html: str) -> List[str]:
  """Return contents of all <script>...</script> blocks (no src attribute)."""
  return re.findall(
    r"<script(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>",
    html,
    re.DOTALL | re.IGNORECASE,
  )


class _ScriptSrcParser(HTMLParser):
  """Extracts src values from <script src="..."> tags."""

  def __init__(self, base_url: str) -> None:
    super().__init__()
    self.base_url = base_url
    self.srcs: List[str] = []

  def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
    if tag.lower() != "script":
      return
    attr_dict = {k.lower(): (v or "").strip() for k, v in attrs}
    src = attr_dict.get("src", "")
    if not src or src.startswith(("data:", "javascript:")):
      return
    try:
      abs_url = up.urljoin(self.base_url, src)
      self.srcs.append(abs_url)
    except Exception:
      pass


def _extract_script_srcs(html: str, base_url: str) -> List[str]:
  """Return absolute URLs of all external <script src="..."> references."""
  parser = _ScriptSrcParser(base_url)
  try:
    parser.feed(html)
  except Exception:
    pass
  return parser.srcs


def _analyse_js(url: str, js: str, result: DomScanResult) -> None:
  """
  Find sinks and sources in `js`, then look for flows via:
  1. Proximity (source → sink within _PROXIMITY_LINES lines)
  2. Variable tracking (var = source; ... sink(var))
  """
  lines = js.splitlines()

  # Collect sink line indices
  sink_lines: List[Tuple[int, str]] = []  # (line_idx, sink_name)
  for line_idx, line in enumerate(lines):
    for pattern, name in _SINKS:
      if re.search(pattern, line):
        if name not in result.sinks_found:
          result.sinks_found.append(name)
        sink_lines.append((line_idx, name))

  # Collect source line indices
  source_lines: List[Tuple[int, str]] = []  # (line_idx, source_name)
  for line_idx, line in enumerate(lines):
    for pattern, name in _SOURCES:
      if re.search(pattern, line):
        if name not in result.sources_found:
          result.sources_found.append(name)
        source_lines.append((line_idx, name))

  def _report(src_name: str, sink_name: str, src_idx: int, sink_idx: int) -> None:
    already = any(
      f.source == src_name and f.sink == sink_name and f.url == url
      for f in result.sink_findings
    )
    if not already:
      snippet = "\n".join(lines[src_idx: sink_idx + 2])
      result.sink_findings.append(DomFinding(
        url=url,
        source=src_name,
        sink=sink_name,
        line=sink_idx + 1,  # 1-indexed
        snippet=snippet[:300],
      ))

  # --- Pass 1: Proximity analysis -------------------------------------------
  for src_idx, src_name in source_lines:
    window_end = src_idx + _PROXIMITY_LINES
    for sink_idx, sink_name in sink_lines:
      if src_idx <= sink_idx <= window_end:
        _report(src_name, sink_name, src_idx, sink_idx)

  # --- Pass 2: Variable-tracking analysis -----------------------------------
  # Build a map: variable_name -> (source_name, assigned_at_line_idx)
  tainted_vars: Dict[str, Tuple[str, int]] = {}

  for line_idx, line in enumerate(lines):
    m = _VAR_ASSIGN_RE.search(line)
    if not m:
      continue
    var_name = m.group(1)
    rhs      = m.group(2)

    # Check if the RHS contains a known source
    for src_pat, src_name in _SOURCES:
      if re.search(src_pat, rhs):
        tainted_vars[var_name] = (src_name, line_idx)
        break
    else:
      # Check if the RHS re-assigns from another tainted variable
      for tv_name, (tv_src, tv_line) in tainted_vars.items():
        # Simple heuristic: tainted var appears in the rhs expression
        if re.search(rf'\b{re.escape(tv_name)}\b', rhs):
          tainted_vars[var_name] = (tv_src, tv_line)
          break

  # Now look for tainted variables flowing into sinks
  for sink_idx, sink_line in enumerate(lines):
    for sink_pat, sink_name in _SINKS:
      if not re.search(sink_pat, sink_line):
        continue
      for var_name, (src_name, assign_idx) in tainted_vars.items():
        if assign_idx <= sink_idx and re.search(rf'\b{re.escape(var_name)}\b', sink_line):
          _report(src_name, sink_name, assign_idx, sink_idx)


def _scan_html_attributes(url: str, html: str, result: DomScanResult) -> None:
  """
  Look for inline event handlers that reference known sources directly.
  e.g. <div onclick="location.href=location.hash.slice(1)">
  """
  # Find all on* attribute values
  inline_handlers = re.findall(
    r'\bon\w+\s*=\s*["\']([^"\']+)["\']',
    html,
    re.IGNORECASE,
  )
  for handler in inline_handlers:
    for src_pat, src_name in _SOURCES:
      if re.search(src_pat, handler):
        for sink_pat, sink_name in _SINKS:
          if re.search(sink_pat, handler):
            already = any(
              f.source == src_name and f.sink == sink_name and f.url == url
              for f in result.sink_findings
            )
            if not already:
              result.sink_findings.append(DomFinding(
                url=url,
                source=src_name,
                sink=sink_name,
                line=0,
                snippet=handler[:200],
              ))
