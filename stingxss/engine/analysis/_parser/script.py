# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Classify the JS context of a marker inside a <script> block."""

from __future__ import annotations

from ...reporter import ReflectionContext


def classify_script(script_before: str, _after: str = "") -> ReflectionContext:
  """Walk `script_before` tracking string/regex/comment state; return context."""
  in_double = in_single = in_template = in_regex = in_block = False
  i = 0
  s = script_before

  while i < len(s):
    c = s[i]

    if not in_double and not in_single and not in_template and not in_regex:
      if s[i:i+2] == "/*":
        in_block = True
        i += 2
        continue

    if in_block:
      if s[i:i+2] == "*/":
        in_block = False
        i += 2
        continue
      i += 1
      continue

    if c == "\\" and i + 1 < len(s):
      i += 2
      continue
    if c == '"' and not in_single and not in_template and not in_regex:
      in_double = not in_double
    elif c == "'" and not in_double and not in_template and not in_regex:
      in_single = not in_single
    elif c == "`" and not in_double and not in_single and not in_regex:
      in_template = not in_template
    elif c == "/" and not in_double and not in_single and not in_template:
      prev = s[:i].rstrip()
      if prev and prev[-1] in ("=", "(", "[", "!", "&", "|", ",", "{", "}", ";", "\n") \
         or prev.endswith(("return", "typeof", "in", "instanceof")):
        in_regex = not in_regex
    i += 1

  if in_block:    return ReflectionContext.SCRIPT_COMMENT
  if in_double:   return ReflectionContext.SCRIPT_STRING_D
  if in_single:   return ReflectionContext.SCRIPT_STRING_S
  if in_template: return ReflectionContext.SCRIPT_TEMPLATE
  if in_regex:    return ReflectionContext.SCRIPT_REGEX
  return ReflectionContext.SCRIPT_BARE
