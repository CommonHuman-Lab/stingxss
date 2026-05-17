# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""JS source→sink flow analysis: proximity, variable tracking, origin checks."""

from __future__ import annotations

import re
from typing import Dict, Tuple

from commonhuman_cli.severity import Severity
from ...reporter import DomFinding
from .patterns import SOURCES, ALL_SINKS

_PROXIMITY_LINES = 20        # look-ahead window for normal files
_MINIFIED_LINE_LEN = 300     # avg line length threshold → treat as minified

# Matches: var/let/const name = expr   OR   name = expr
_VAR_ASSIGN_RE = re.compile(
  r'(?:(?:var|let|const)\s+)?([a-zA-Z_$][\w$]*)\s*=\s*(.+)',
)

# Weak postMessage origin checks bypassable via substring tricks
_IMPROPER_ORIGIN_RE = re.compile(
  r"msg\.origin\s*\.\s*(?:includes|startsWith|indexOf)\s*\(",
  re.IGNORECASE,
)

# Severity assigned per DOM finding category
_CATEGORY_SEVERITY: Dict[str, str] = {
  "dom_xss":               Severity.MEDIUM,
  "dom_open_redirect":     Severity.MEDIUM,
  "link_manipulation":     Severity.LOW,
  "dom_data_manipulation": Severity.LOW,
  "prototype_pollution":   Severity.HIGH,
}


def _already_reported(result, url: str, source: str, sink: str) -> bool:
  return any(f.source == source and f.sink == sink and f.url == url
             for f in result.sink_findings)


def _report(result, url: str, src_name: str, sink_name: str,
            lines: list, src_idx: int, sink_idx: int, category: str = "dom_xss") -> None:
  if _already_reported(result, url, src_name, sink_name):
    return
  snippet = "\n".join(lines[src_idx: sink_idx + 2])
  sev = _CATEGORY_SEVERITY.get(category, Severity.MEDIUM)
  result.sink_findings.append(DomFinding(
    url=url, source=src_name, sink=sink_name,
    line=sink_idx + 1, snippet=snippet[:300],
    severity=sev, category=category,
  ))


def check_improper_origin(url: str, js: str, result) -> None:
  """Flag weak postMessage origin checks."""
  lines = js.splitlines()

  for line_idx, line in enumerate(lines):
    if _IMPROPER_ORIGIN_RE.search(line):
      if not _already_reported(result, url, "msg.origin", "improper-origin-check"):
        result.sink_findings.append(DomFinding(
          url=url, source="msg.origin", sink="improper-origin-check",
          line=line_idx + 1, snippet=line.strip()[:300],
          category="dom_xss",
        ))

  has_match = bool(re.search(r"msg\.origin\s*\.\s*match\s*\(", js, re.IGNORECASE))
  if has_match:
    for rx_m in re.finditer(r'/([^/\n]+)/', js):
      rx_body = rx_m.group(1)
      if len(rx_body) < 5:
        continue
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
            category="dom_xss",
          ))
          break


def analyse_js(url: str, js: str, result) -> None:
  """Find source→sink flows via proximity and variable tracking."""
  check_improper_origin(url, js, result)
  lines = js.splitlines()

  # Detect minified files — very long average line length.
  # Proximity matching is meaningless in a 50k-char "line" (source and sink
  # coexist everywhere), so skip it entirely and rely only on variable tracking.
  is_minified = bool(lines and sum(len(l) for l in lines) / len(lines) > _MINIFIED_LINE_LEN)

  sink_lines:   list[tuple[int, str, str]] = []
  source_lines: list[tuple[int, str]]      = []
  tainted_vars: Dict[str, Tuple[str, int]] = {}

  for line_idx, line in enumerate(lines):
    for pattern, name, cat in ALL_SINKS:
      if re.search(pattern, line):
        if name not in result.sinks_found:
          result.sinks_found.append(name)
        sink_lines.append((line_idx, name, cat))

    for pattern, name in SOURCES:
      if re.search(pattern, line):
        if name not in result.sources_found:
          result.sources_found.append(name)
        source_lines.append((line_idx, name))

    m = _VAR_ASSIGN_RE.search(line)
    if m:
      var_name, rhs = m.group(1), m.group(2)
      for src_pat, src_name in SOURCES:
        if re.search(src_pat, rhs):
          tainted_vars[var_name] = (src_name, line_idx)
          break
      else:
        for tv_name, (tv_src, _) in tainted_vars.items():
          if re.search(rf'\b{re.escape(tv_name)}\b', rhs):
            tainted_vars[var_name] = (tv_src, line_idx)
            break

  # Proximity pass — skipped for minified files (same-line matching in a
  # 50k-char blob is not meaningful; variable tracking handles those).
  if not is_minified:
    for src_idx, src_name in source_lines:
      window_end = src_idx + _PROXIMITY_LINES
      for sink_idx, sink_name, sink_cat in sink_lines:
        if src_idx <= sink_idx <= window_end:
          _report(result, url, src_name, sink_name, lines, src_idx, sink_idx, sink_cat)

  # Variable-tracking pass
  for sink_idx, sink_line in enumerate(lines):
    for sink_pat, sink_name, sink_cat in ALL_SINKS:
      if not re.search(sink_pat, sink_line):
        continue
      for var_name, (src_name, assign_idx) in tainted_vars.items():
        if assign_idx <= sink_idx and re.search(rf'\b{re.escape(var_name)}\b', sink_line):
          _report(result, url, src_name, sink_name, lines, assign_idx, sink_idx, sink_cat)
