# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
# HTML / JavaScript context analyser.
# Locates the marker in the response body and classifies its syntactic context.

from __future__ import annotations

import html
import re
from typing import Optional

from ..reporter import ReflectionContext
from ._parser.probe import PROBE_MARKER, is_reflected, probe_filter  # noqa: F401  (re-exported)
from ._parser.helpers import rfind_tag, in_comment, in_css_value
from ._parser.script import classify_script
from ._parser.attribute import classify_attribute, classify_angular

_NG_APP_RE = re.compile(r'\bng-app\b', re.IGNORECASE)


def page_uses_angular(body: str) -> bool:
  """Return True if the page appears to use AngularJS."""
  if _NG_APP_RE.search(body):
    return True
  return bool(re.search(r'angular(?:js)?[\./]', body, re.IGNORECASE))


def find_context(body: str, marker: str = PROBE_MARKER) -> ReflectionContext:
  """Locate `marker` in `body` and return its HTML/JS reflection context."""
  normalised = html.unescape(body)
  pos = normalised.lower().find(marker.lower())
  if pos == -1:
    return ReflectionContext.UNKNOWN
  return _classify(normalised[:pos], normalised, pos)


def _classify(before: str, full: str, pos: int) -> ReflectionContext:
  # 1. Inside a <script> block?
  last_script_open  = rfind_tag(before, "script", opening=True)
  last_script_close = rfind_tag(before, "script", opening=False)
  in_script = (
    last_script_open is not None
    and (last_script_close is None or last_script_close < last_script_open)
  )
  if in_script:
    tag_close_pos = before.find(">", last_script_open)
    if tag_close_pos == -1:
      in_script = False  # still inside opening <script ...> tag

  if in_script:
    return classify_script(before[last_script_open:], full[pos:pos + 30])

  # 2. HTML comment?
  if in_comment(before):
    return ReflectionContext.COMMENT

  # 3. Raw-text elements: textarea, title, noscript
  for tag, ctx in (
    ("textarea", ReflectionContext.TEXTAREA),
    ("title",    ReflectionContext.TITLE),
    ("noscript", ReflectionContext.NOSCRIPT),
  ):
    open_pos  = rfind_tag(before, tag, opening=True)
    close_pos = rfind_tag(before, tag, opening=False)
    if open_pos is not None and (close_pos is None or close_pos < open_pos):
      if before.find(">", open_pos) != -1:
        return ctx

  # 4. Inside a <style> block?
  style_open  = rfind_tag(before, "style", opening=True)
  style_close = rfind_tag(before, "style", opening=False)
  if style_open is not None and (style_close is None or style_close < style_open):
    style_body = before[before.find(">", style_open) + 1:]
    return ReflectionContext.CSS_VALUE if in_css_value(style_body) else ReflectionContext.CSS

  # 5. Inside an HTML tag attribute?
  attr_ctx = classify_attribute(before, full, pos)
  if attr_ctx is not None:
    return attr_ctx

  # 6. As a tag name? (last unclosed < followed immediately by the marker)
  last_open  = before.rfind("<")
  last_close = before.rfind(">")
  if last_open != -1 and last_close < last_open:
    tag_fragment = before[last_open + 1:].lstrip()
    if tag_fragment == "" or tag_fragment.isspace():
      return ReflectionContext.TAG_NAME

  # 7. AngularJS template?
  angular_ctx = classify_angular(before, full, pos)
  if angular_ctx is not None:
    return angular_ctx

  return ReflectionContext.HTML_BODY
