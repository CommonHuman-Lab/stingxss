# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""HTML extraction helpers: inline scripts, external script URLs, attribute scanning."""

from __future__ import annotations

import re
import urllib.parse as up
from html.parser import HTMLParser
from typing import List, Optional, Tuple

from ...reporter import DomFinding
from .patterns import SOURCES, SINKS


def extract_inline_scripts(html: str) -> List[str]:
  """Return contents of all <script> blocks without a src attribute."""
  return re.findall(
    r"<script(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>",
    html,
    re.DOTALL | re.IGNORECASE,
  )


class _ScriptSrcParser(HTMLParser):
  """Collects src values from <script src="..."> tags."""

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
      self.srcs.append(up.urljoin(self.base_url, src))
    except Exception:
      pass


def extract_script_srcs(html: str, base_url: str) -> List[str]:
  """Return absolute URLs of all external <script src="..."> references."""
  parser = _ScriptSrcParser(base_url)
  try:
    parser.feed(html)
  except Exception:
    pass
  return parser.srcs


def scan_html_attributes(url: str, html: str, result) -> None:
  """Flag inline event handlers and javascript: URIs that reference sources+sinks."""
  def _check(snippet: str) -> None:
    for src_pat, src_name in SOURCES:
      if re.search(src_pat, snippet):
        for sink_pat, sink_name in SINKS:
          if re.search(sink_pat, snippet):
            if not any(f.source == src_name and f.sink == sink_name and f.url == url
                       for f in result.sink_findings):
              result.sink_findings.append(DomFinding(
                url=url, source=src_name, sink=sink_name,
                line=0, snippet=snippet[:200],
              ))

  for handler in re.findall(r'\bon\w+\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
    _check(handler)

  for js_uri in re.findall(
    r'''(?:href|src|action)\s*=\s*["']javascript:([^"']+)["']''', html, re.IGNORECASE
  ):
    _check(js_uri)
