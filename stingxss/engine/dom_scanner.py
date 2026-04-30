"""
StingXSS — engine/dom_scanner.py
Static DOM XSS analysis — no browser required.

Scans HTML page sources and inline/external JavaScript for:
  - Dangerous sinks (innerHTML, document.write, eval, ...)
  - Attacker-controlled sources (location.*, document.referrer, ...)
  - Direct source→sink flows

Returns a list of DomFinding dataclasses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .reporter import DomFinding

# ---------------------------------------------------------------------------
# Sources — values the attacker can influence
# ---------------------------------------------------------------------------
_SOURCES: List[Tuple[str, str]] = [
  # (pattern, human_name)
  (r"location\.hash",       "location.hash"),
  (r"location\.search",     "location.search"),
  (r"location\.href",       "location.href"),
  (r"location\.pathname",   "location.pathname"),
  (r"document\.referrer",   "document.referrer"),
  (r"document\.URL",        "document.URL"),
  (r"document\.baseURI",    "document.baseURI"),
  (r"document\.cookie",     "document.cookie"),
  (r"window\.name",         "window.name"),
  (r"postMessage",          "postMessage"),
  (r"URLSearchParams",      "URLSearchParams"),
]

# ---------------------------------------------------------------------------
# Sinks — dangerous execution / rendering points
# ---------------------------------------------------------------------------
_SINKS: List[Tuple[str, str]] = [
  # (pattern, human_name)
  (r"\.innerHTML\s*=",          "innerHTML"),
  (r"\.outerHTML\s*=",          "outerHTML"),
  (r"\.insertAdjacentHTML\s*\(","insertAdjacentHTML"),
  (r"document\.write\s*\(",     "document.write"),
  (r"document\.writeln\s*\(",   "document.writeln"),
  (r"\beval\s*\(",              "eval"),
  (r"setTimeout\s*\(\s*['\"`]", "setTimeout(string)"),
  (r"setInterval\s*\(\s*['\"`]","setInterval(string)"),
  (r"new\s+Function\s*\(",      "new Function()"),
  (r"\.setAttribute\s*\(\s*['\"]on", "setAttribute(on...)"),
  (r"location\.href\s*=",       "location.href="),
  (r"location\.replace\s*\(",   "location.replace()"),
  (r"location\.assign\s*\(",    "location.assign()"),
  (r"window\.open\s*\(",        "window.open()"),
  (r"\.src\s*=",                ".src="),
  (r"\.action\s*=",             ".action="),
  (r"\$\s*\(\s*['\"`][^'\"`]*location", "jQuery(location...)"),
  (r"\.html\s*\(",              "jQuery.html()"),
  (r"dangerouslySetInnerHTML",  "React dangerouslySetInnerHTML"),
]

# ---------------------------------------------------------------------------
# Patterns that indicate source→sink proximity in the same JS block
# (We look for a source followed by a sink within N lines)
# ---------------------------------------------------------------------------
_PROXIMITY_LINES = 20  # lines to look ahead from source


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

def scan_page(url: str, html: str) -> DomScanResult:
  """
  Scan `html` (a full page body) for DOM XSS indicators.
  Extracts inline <script> blocks + analyses data-* / on* attributes.
  """
  result = DomScanResult(url=url)

  # 1. Extract all inline JS
  scripts = _extract_inline_scripts(html)

  # 2. Analyse each script block
  for script_src in scripts:
    _analyse_js(url, script_src, result)

  # 3. Scan HTML attributes for inline handlers using location/window.name etc.
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
  """Return contents of all <script>...</script> blocks."""
  return re.findall(
    r"<script[^>]*>(.*?)</script>",
    html,
    re.DOTALL | re.IGNORECASE,
  )


def _analyse_js(url: str, js: str, result: DomScanResult) -> None:
  """
  Find sinks and sources in `js`, then look for proximity-based flows.
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

  # Proximity analysis: for each source, check if a sink appears within
  # _PROXIMITY_LINES lines after it
  for src_idx, src_name in source_lines:
    window_end = src_idx + _PROXIMITY_LINES
    for sink_idx, sink_name in sink_lines:
      if src_idx <= sink_idx <= window_end:
        # Deduplicate: only report unique (source, sink) pairs per url
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
