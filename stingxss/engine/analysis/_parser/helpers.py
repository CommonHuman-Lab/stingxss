# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Helpers: tag finder, comment check, CSS-value detection."""

from __future__ import annotations

import re
from typing import Optional

# Pre-compiled open/close patterns for each raw-text element
_TAG_RES: dict[str, tuple[re.Pattern, re.Pattern]] = {
  tag: (
    re.compile(rf"<{tag}[\s>/]", re.IGNORECASE),
    re.compile(rf"</{tag}\s*>",  re.IGNORECASE),
  )
  for tag in ("script", "textarea", "title", "noscript", "style")
}


def rfind_tag(text: str, tag: str, opening: bool) -> Optional[int]:
  """Return the start position of the last opening or closing tag, or None."""
  pattern = _TAG_RES[tag][0 if opening else 1]
  last = None
  for m in pattern.finditer(text):
    last = m.start()
  return last


def in_comment(before: str) -> bool:
  """True if position is inside an HTML comment."""
  return len(re.findall(r"<!--", before)) > len(re.findall(r"-->", before))


def in_css_value(style_body: str) -> bool:
  """True if the cursor is inside a CSS property value (after a colon)."""
  stripped = style_body.rstrip()
  if not stripped:
    return False
  if stripped[-1] == ":":
    return True
  last_delim = max(stripped.rfind("{"), stripped.rfind(";"))
  since_delim = stripped[last_delim + 1:] if last_delim != -1 else stripped
  return ":" in since_delim
