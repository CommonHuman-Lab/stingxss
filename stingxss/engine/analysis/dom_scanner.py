# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
# Static DOM XSS analysis — no browser required.
# Scans inline/external JS for source→sink flows via proximity and variable tracking.

from __future__ import annotations

import re
import urllib.parse as up
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set, Tuple

from ..reporter import DomFinding

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
  (r"\bmsg\.data\b",            "msg.data"),
  (r"URLSearchParams",          "URLSearchParams"),
  (r"localStorage\.getItem",    "localStorage.getItem"),
  (r"localStorage\[",           "localStorage[key]"),
  (r"localStorage\.[a-zA-Z_$][\w$]*(?!\s*[\(\[])", "localStorage.property"),
  (r"sessionStorage\.getItem",  "sessionStorage.getItem"),
  (r"sessionStorage\[",         "sessionStorage[key]"),
  (r"sessionStorage\.[a-zA-Z_$][\w$]*(?!\s*[\(\[])", "sessionStorage.property"),
  (r"\bwindow\.status\b",       "window.status"),
  (r"\be\.target\.value\b",     "e.target.value"),
  (r"\.value\b",                ".value"),
  (r"\bmsg\.data\.\w+",         "msg.data.*"),
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
  (r"setTimeout\s*\(\s*(?!function\b)[a-zA-Z_$][\w$]*\s*,", "setTimeout(variable)"),
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
  (r"(?:\$parse\s*\(|get\s*\(\s*['\"]?\$parse['\"]?\s*\))", "$parse()"),
  # URL/resource sinks — attacker-controlled URL fetched or navigated to
  (r"\bfetch\s*\(",                 "fetch()"),
  (r"(?:xhttp|xhr|req)\s*\.open\s*\(", "xhr.open()"),
  (r"\.setAttributeNS\s*\(",        "setAttributeNS()"),
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


# ---------------------------------------------------------------------------
# Improper postMessage origin validation patterns
# ---------------------------------------------------------------------------
# These patterns match msg.origin checks that can be bypassed:
#   .includes('trusted.com')  → bypassable with trusted.com.attacker.com
#   .startsWith('trusted.com')→ bypassable with trusted.com.attacker.com
#   .indexOf('trusted.com')   → same
#   regex without anchoring $  → bypassable with trusted.com.attacker.com path
_IMPROPER_ORIGIN_RE = re.compile(
  r"msg\.origin\s*\.\s*(?:includes|startsWith|indexOf)\s*\(",
  re.IGNORECASE,
)
# Regex check: present but dot not escaped and/or missing end-of-string anchor
_ORIGIN_REGEX_RE = re.compile(
  r"(?:msg\.origin)\s*\.\s*match\s*\(|/[^/]*\.\s*(?:google|example|[a-z]+)\s*\.[a-z]+[^$]*/"
)


def _check_improper_origin_validation(url: str, js: str, result: DomScanResult) -> None:
  """Flag weak postMessage origin checks that can be bypassed by an attacker."""
  lines = js.splitlines()

  # --- Pass A: substring/indexOf checks on msg.origin ---
  for line_idx, line in enumerate(lines):
    if _IMPROPER_ORIGIN_RE.search(line):
      if not _already_reported(result, url, "msg.origin", "improper-origin-check"):
        result.sink_findings.append(DomFinding(
          url=url, source="msg.origin", sink="improper-origin-check",
          line=line_idx + 1, snippet=line.strip()[:300],
        ))

  # --- Pass B: regex-based origin checks ---
  # Strategy:
  #  1. Collect all regex literals in the JS block and check for weak patterns
  #     (unescaped dot OR missing end-anchor $).
  #  2. If any weak regex exists AND msg.origin.match() is also present,
  #     flag it as improper-origin-regexp.
  has_origin_match = bool(re.search(r"msg\.origin\s*\.\s*match\s*\(", js, re.IGNORECASE))
  if has_origin_match:
    # Find all regex literals /.../ in the JS
    for rx_m in re.finditer(r'/([^/\n]+)/', js):
      rx_body = rx_m.group(1)
      # Skip trivially short or obviously non-origin regexes
      if len(rx_body) < 5:
        continue
      # Weak if unescaped dot present OR no end-anchor $
      if re.search(r'(?<!\\)\.', rx_body) or not rx_body.endswith('$'):
        if not _already_reported(result, url, "msg.origin", "improper-origin-regexp"):
          match_line = next(
            (i + 1 for i, l in enumerate(lines)
             if re.search(r"msg\.origin\s*\.\s*match\s*\(", l, re.IGNORECASE)),
            0,
          )
          result.sink_findings.append(DomFinding(
            url=url, source="msg.origin", sink="improper-origin-regexp",
            line=match_line, snippet=rx_m.group(0)[:300],
          ))
          break


def _already_reported(result: DomScanResult, url: str, source: str, sink: str) -> bool:
  return any(f.source == source and f.sink == sink and f.url == url for f in result.sink_findings)


def _report(
  result: DomScanResult, url: str,
  src_name: str, sink_name: str,
  lines: list[str], src_idx: int, sink_idx: int,
) -> None:
  if _already_reported(result, url, src_name, sink_name):
    return
  snippet = "\n".join(lines[src_idx: sink_idx + 2])
  result.sink_findings.append(DomFinding(
    url=url, source=src_name, sink=sink_name,
    line=sink_idx + 1, snippet=snippet[:300],
  ))


def _analyse_js(url: str, js: str, result: DomScanResult) -> None:
  """Find source→sink flows via proximity and variable tracking."""
  _check_improper_origin_validation(url, js, result)
  lines = js.splitlines()

  sink_lines:   list[tuple[int, str]] = []
  source_lines: list[tuple[int, str]] = []
  tainted_vars: Dict[str, Tuple[str, int]] = {}

  # Single pass: collect sinks, sources, and tainted variable assignments
  for line_idx, line in enumerate(lines):
    for pattern, name in _SINKS:
      if re.search(pattern, line):
        if name not in result.sinks_found:
          result.sinks_found.append(name)
        sink_lines.append((line_idx, name))

    for pattern, name in _SOURCES:
      if re.search(pattern, line):
        if name not in result.sources_found:
          result.sources_found.append(name)
        source_lines.append((line_idx, name))

    # Variable tracking: var/let/const name = <expr>
    m = _VAR_ASSIGN_RE.search(line)
    if m:
      var_name = m.group(1)
      rhs      = m.group(2)
      for src_pat, src_name in _SOURCES:
        if re.search(src_pat, rhs):
          tainted_vars[var_name] = (src_name, line_idx)
          break
      else:
        for tv_name, (tv_src, _) in tainted_vars.items():
          if re.search(rf'\b{re.escape(tv_name)}\b', rhs):
            tainted_vars[var_name] = (tv_src, line_idx)
            break

  # Pass 1: Proximity analysis
  for src_idx, src_name in source_lines:
    window_end = src_idx + _PROXIMITY_LINES
    for sink_idx, sink_name in sink_lines:
      if src_idx <= sink_idx <= window_end:
        _report(result, url, src_name, sink_name, lines, src_idx, sink_idx)

  # Pass 2: Variable-tracking — tainted vars flowing into sinks
  for sink_idx, sink_line in enumerate(lines):
    for sink_pat, sink_name in _SINKS:
      if not re.search(sink_pat, sink_line):
        continue
      for var_name, (src_name, assign_idx) in tainted_vars.items():
        if assign_idx <= sink_idx and re.search(rf'\b{re.escape(var_name)}\b', sink_line):
          _report(result, url, src_name, sink_name, lines, assign_idx, sink_idx)


def _scan_html_attributes(url: str, html: str, result: DomScanResult) -> None:
  """
  Look for inline event handlers and javascript: URIs that reference known sources.
  e.g. <div onclick="location.href=location.hash.slice(1)">
       <a href="javascript:location.href=location.href">
  """
  def _check_js_snippet(snippet: str) -> None:
    for src_pat, src_name in _SOURCES:
      if re.search(src_pat, snippet):
        for sink_pat, sink_name in _SINKS:
          if re.search(sink_pat, snippet):
            if not _already_reported(result, url, src_name, sink_name):
              result.sink_findings.append(DomFinding(
                url=url, source=src_name, sink=sink_name,
                line=0, snippet=snippet[:200],
              ))

  # on* event handlers
  for handler in re.findall(r'\bon\w+\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
    _check_js_snippet(handler)

  # javascript: URIs in href / src / action attributes
  for js_uri in re.findall(r'''(?:href|src|action)\s*=\s*["']javascript:([^"']+)["']''', html, re.IGNORECASE):
    _check_js_snippet(js_uri)
