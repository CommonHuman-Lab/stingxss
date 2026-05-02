# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Probe marker and quick reflection check."""

from __future__ import annotations

import html
import random
import string

# Per-process random token; reduces false-positive risk vs a static string.
PROBE_MARKER: str = "vXSS" + "".join(
  random.choices(string.ascii_lowercase + string.digits, k=12)
)


def is_reflected(body: str, marker: str = PROBE_MARKER) -> bool:
  """Return True if `marker` appears anywhere in the (HTML-unescaped) body."""
  return marker.lower() in html.unescape(body).lower()
