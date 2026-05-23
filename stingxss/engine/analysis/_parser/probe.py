# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Probe marker, filter-probing, and quick reflection checks."""

from __future__ import annotations

import html
import random
import string
import urllib.parse as up
from typing import Optional, Set

# Per-process random token; reduces false-positive risk vs a static string.
PROBE_MARKER: str = "vXSS" + "".join(
  random.choices(string.ascii_lowercase + string.digits, k=12)
)

# Characters that, when blocked, rule out whole payload classes
_FILTER_CHARS = "<>\"'\\;/=()"


def is_reflected(body: str, marker: str = PROBE_MARKER) -> bool:
  """Return True if `marker` appears anywhere in the (HTML-unescaped) body."""
  return marker.lower() in html.unescape(body).lower()


def probe_filter(
  url: str,
  param: str,
  method: str,
  injector,
  base_data: Optional[dict] = None,
) -> Set[str]:
  """Return the set of special characters that the server encodes or strips.

  Sends a single request containing all characters in ``_FILTER_CHARS`` and
  compares them in the raw response text.  Characters that don't appear
  verbatim are considered "blocked" by the server-side filter.

  Example:
    blocked = probe_filter(url, "q", "GET", injector)
    # blocked == {"<", ">"}  → HTML-injection payloads won't work
  """
  sentinel = "stingFilter"
  probe_value = sentinel + _FILTER_CHARS + sentinel
  try:
    if method.upper() == "POST":
      resp = injector.inject_post(url, param, probe_value, base_data)
    else:
      resp = injector.inject_get(url, param, probe_value)
  except Exception:
    return set()

  if resp is not None and (resp.status_code is None or resp.status_code >= 500):
    return set()
  body = html.unescape(resp.text) if resp is not None else ""
  if sentinel not in body:
    # Parameter not reflected at all — can't determine filter
    return set(_FILTER_CHARS)

  blocked: Set[str] = set()
  for ch in _FILTER_CHARS:
    # Check if the char appears verbatim anywhere near our sentinel in the body
    if ch not in body:
      blocked.add(ch)

  return blocked
