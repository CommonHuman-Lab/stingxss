# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
StingXSS — engine/clickjacking.py
Clickjacking protection header analyser.

Inspects X-Frame-Options and Content-Security-Policy headers on a response
and returns a ClickjackingFinding if the page appears to be frameable.

Two vulnerability classes (matching Google Firing Range /clickjacking/):
  1. X-Frame-Options set to 'ALLOWALL' — deprecated non-standard directive
     that browsers do not honour as a framing restriction.
  2. Content-Security-Policy present but missing 'frame-ancestors' directive
     — the policy does not restrict who can frame the page.

Additionally detects the trivial case: no framing-protection header at all.
"""

from __future__ import annotations

import re
from typing import Optional

from ..reporter import ClickjackingFinding

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check(url: str, headers: dict) -> Optional[ClickjackingFinding]:
  """
  Inspect `headers` (a case-insensitive dict of response headers) and return
  a ClickjackingFinding if the page is potentially frameable, or None if it
  appears properly protected.

  Parameters
  ----------
  url     : The page URL (used to populate the finding).
  headers : Response headers dict (keys are compared case-insensitively).
  """
  xfo = _get_header(headers, "x-frame-options")
  csp = _get_header(headers, "content-security-policy")

  # ---- 1. X-Frame-Options checks -----------------------------------------
  if xfo is not None:
    xfo_clean = xfo.strip().upper()

    # ALLOWALL is a non-standard directive; no browser treats it as a
    # framing restriction.
    if xfo_clean == "ALLOWALL":
      return ClickjackingFinding(
        url=url,
        reason=(
          "X-Frame-Options header is set to 'ALLOWALL', which is a non-standard "
          "directive that browsers do not recognise as a framing restriction. "
          "The page can be embedded in any iframe."
        ),
        xfo_header=xfo,
        csp_header=csp or "",
      )

    # DENY or SAMEORIGIN — properly protected by XFO alone.
    if xfo_clean in ("DENY", "SAMEORIGIN"):
      # Check CSP as well; if CSP overrides with frame-ancestors that allows
      # all origins we'd still be vulnerable, but that's an edge case beyond
      # this analyser's scope.  Treat as protected.
      return None

    # Any other non-empty XFO value (e.g. ALLOW-FROM) — browsers increasingly
    # ignore ALLOW-FROM; flag as potentially misconfigured but only if CSP
    # also lacks frame-ancestors.
    if not _csp_has_frame_ancestors(csp):
      return ClickjackingFinding(
        url=url,
        reason=(
          f"X-Frame-Options is set to '{xfo}' which may not be respected by "
          "modern browsers, and the Content-Security-Policy does not contain "
          "a 'frame-ancestors' directive."
        ),
        xfo_header=xfo,
        csp_header=csp or "",
      )
    return None

  # ---- 2. No X-Frame-Options — check CSP frame-ancestors -----------------
  if _csp_has_frame_ancestors(csp):
    # CSP frame-ancestors is present — protected.
    return None

  # ---- 3. Neither XFO nor CSP frame-ancestors -----------------------------
  if csp is not None:
    # CSP exists but lacks frame-ancestors
    return ClickjackingFinding(
      url=url,
      reason=(
        "The Content-Security-Policy header is present but does not include "
        "a 'frame-ancestors' directive. Without X-Frame-Options or "
        "'frame-ancestors' the page can be embedded in any iframe."
      ),
      xfo_header="",
      csp_header=csp,
    )

  # Completely unprotected
  return ClickjackingFinding(
    url=url,
    reason=(
      "Neither X-Frame-Options nor a Content-Security-Policy with "
      "'frame-ancestors' is present. The page can be embedded in any iframe."
    ),
    xfo_header="",
    csp_header="",
  )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_header(headers: dict, name: str) -> Optional[str]:
  """Case-insensitive header lookup."""
  for k, v in headers.items():
    if k.lower() == name.lower():
      return v
  return None


def _csp_has_frame_ancestors(csp: Optional[str]) -> bool:
  """Return True if the CSP value contains a 'frame-ancestors' directive."""
  if not csp:
    return False
  return bool(re.search(r'\bframe-ancestors\b', csp, re.IGNORECASE))
