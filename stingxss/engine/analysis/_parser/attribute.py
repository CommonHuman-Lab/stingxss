# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Attribute and AngularJS context classifiers."""

from __future__ import annotations

import re
from typing import Optional

from ...reporter import ReflectionContext

_LAST_ATTR_RE = re.compile(r'\b([\w:-]+)\s*=\s*(["\']?)', re.IGNORECASE)
_NG_APP_RE    = re.compile(r'\bng-app\b', re.IGNORECASE)
_NG_START_RE  = re.compile(r"startSymbol\s*\(\s*['\"](.+?)['\"]", re.IGNORECASE)
_NG_END_RE    = re.compile(r"endSymbol\s*\(\s*['\"](.+?)['\"]",   re.IGNORECASE)

# URL-bearing attributes that accept attacker-controlled URLs
_URL_ATTRS = {"href", "src", "action", "formaction", "data", "ping", "poster", "background"}


def classify_attribute(before: str, _full: str = "", _pos: int = 0) -> Optional[ReflectionContext]:
  """Return the attribute context, or None if not inside a tag."""
  last_open  = before.rfind("<")
  last_close = before.rfind(">")
  if last_open == -1 or last_close > last_open:
    return None

  inside_tag = before[last_open:]
  last_attr = None
  for m in _LAST_ATTR_RE.finditer(inside_tag):
    last_attr = m

  if last_attr is None:
    if re.match(r"<(\w[\w:-]*)\s+", inside_tag):
      return ReflectionContext.ATTR_NAME
    return None

  attr_name  = last_attr.group(1).lower()
  quote_char = last_attr.group(2)

  if re.match(r'^on\w+$', attr_name):
    return ReflectionContext.EVENT_HANDLER

  if attr_name in _URL_ATTRS:
    tag_m = re.match(r"<(\w[\w:-]*)", inside_tag)
    if attr_name == "src" and tag_m and tag_m.group(1).lower() == "script":
      return ReflectionContext.SCRIPT_SRC
    if attr_name == "data" and tag_m and tag_m.group(1).lower() == "object":
      return ReflectionContext.OBJECT_DATA
    return ReflectionContext.URL_ATTR

  if attr_name == "srcdoc":
    return ReflectionContext.IFRAME_SRCDOC

  if attr_name == "value":
    tag_m = re.match(r"<(\w[\w:-]*)", inside_tag)
    if tag_m and tag_m.group(1).lower() == "param":
      return ReflectionContext.OBJECT_DATA

  if quote_char == '"':  return ReflectionContext.ATTR_DOUBLE
  if quote_char == "'":  return ReflectionContext.ATTR_SINGLE
  return ReflectionContext.ATTR_UNQUOTED


def classify_angular(before: str, full: str, _pos: int) -> Optional[ReflectionContext]:
  """Return an Angular context if the page uses AngularJS and the marker is inside {{ }} or ng-*."""
  if not _NG_APP_RE.search(full):
    return None

  start_sym, end_sym = "{{", "}}"
  m_s, m_e = _NG_START_RE.search(full), _NG_END_RE.search(full)
  if m_s and m_e:
    start_sym, end_sym = m_s.group(1), m_e.group(1)
  alt = start_sym != "{{"

  if before.rstrip().endswith(start_sym):
    return ReflectionContext.ANGULAR_TEMPLATE_ALT if alt else ReflectionContext.ANGULAR_TEMPLATE

  last_start = before.rfind(start_sym)
  if last_start != -1 and end_sym not in before[last_start + len(start_sym):]:
    return ReflectionContext.ANGULAR_TEMPLATE_ALT if alt else ReflectionContext.ANGULAR_TEMPLATE

  last_open  = before.rfind("<")
  last_close = before.rfind(">")
  if last_open != -1 and last_close < last_open:
    inside_tag = before[last_open:]
    last_attr = None
    for m in _LAST_ATTR_RE.finditer(inside_tag):
      last_attr = m
    if last_attr:
      name = last_attr.group(1).lower()
      if name.startswith("ng-") or name.startswith("data-ng-"):
        return ReflectionContext.ANGULAR_ATTR

  return None
