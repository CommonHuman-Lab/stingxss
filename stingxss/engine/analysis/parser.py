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
  """Locate *all* occurrences of `marker` in `body` and return the most
  dangerous context.  Pages that echo a parameter in multiple places (e.g.
  in a safe ``<input value="">`` attribute AND via ``{{ q | safe }}`` in the
  body) would otherwise be reported with the first — least dangerous — hit."""
  normalised = html.unescape(body)
  needle = marker.lower()
  text   = normalised.lower()
  seen: list[ReflectionContext] = []
  start = 0
  while True:
    pos = text.find(needle, start)
    if pos == -1:
      break
    seen.append(_classify(normalised[:pos], normalised, pos))
    start = pos + 1
  if not seen:
    return ReflectionContext.UNKNOWN
  return _most_dangerous(seen)


_CTX_RANK: dict[ReflectionContext, int] = {
  ReflectionContext.SCRIPT_BARE:          0,
  ReflectionContext.EVENT_HANDLER:        1,
  ReflectionContext.SCRIPT_STRING_D:      2,
  ReflectionContext.SCRIPT_STRING_S:      3,
  ReflectionContext.SCRIPT_TEMPLATE:      4,
  ReflectionContext.SCRIPT_REGEX:         5,
  ReflectionContext.SCRIPT_COMMENT:       6,
  ReflectionContext.HTML_BODY:            7,
  ReflectionContext.TAG_NAME:             8,
  ReflectionContext.ATTR_UNQUOTED:        9,
  ReflectionContext.ATTR_NAME:            10,
  ReflectionContext.ANGULAR_TEMPLATE:     11,
  ReflectionContext.ANGULAR_TEMPLATE_ALT: 12,
  ReflectionContext.ANGULAR_ATTR:         13,
  ReflectionContext.VUE_TEMPLATE:         14,
  ReflectionContext.ATTR_SINGLE:          15,
  ReflectionContext.ATTR_DOUBLE:          16,
  ReflectionContext.IFRAME_SRCDOC:        17,
  ReflectionContext.OBJECT_DATA:          18,
  ReflectionContext.URL_ATTR:             19,
  ReflectionContext.SCRIPT_SRC:           20,
  ReflectionContext.COMMENT:              21,
  ReflectionContext.DANGLING_MARKUP:      22,
  ReflectionContext.JS_HOISTING:          23,
  ReflectionContext.TEXTAREA:             24,
  ReflectionContext.TITLE:                25,
  ReflectionContext.NOSCRIPT:             26,
  ReflectionContext.CSS:                  27,
  ReflectionContext.CSS_VALUE:            28,
  ReflectionContext.UNKNOWN:              99,
}


def _most_dangerous(contexts: list[ReflectionContext]) -> ReflectionContext:
  return min(contexts, key=lambda c: _CTX_RANK.get(c, 99))


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
