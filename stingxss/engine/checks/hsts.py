# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
# HTTP Strict Transport Security (HSTS) header analyser.
# Covers: hsts_missing, hsts_max_age_too_low, hsts_max_age_missing,
#         hsts_includesubdomains_missing, hsts_preload_missing

from __future__ import annotations

import re
from typing import Dict, List, Optional

from ..reporter import HstsFinding

# 1 year (HSTS preload minimum); warn below 18 weeks (Chrome DevTools threshold)
_MIN_MAX_AGE  = 31_536_000
_WARN_MAX_AGE = 10_886_400

_MAX_AGE_RE = re.compile(r'\bmax-age\s*=\s*(\d+)', re.IGNORECASE)


def check(url: str, headers: Dict[str, str]) -> List[HstsFinding]:
  """Analyse Strict-Transport-Security for *url*. Returns findings (may be empty)."""
  findings: List[HstsFinding] = []

  if not url.lower().startswith("https://"):
    return findings

  hsts_value = _get_header(headers, "strict-transport-security")

  if hsts_value is None:
    findings.append(HstsFinding(
      url=url,
      issue="hsts_missing",
      reason=(
        "The Strict-Transport-Security header is absent. "
        "Without HSTS the browser will not enforce HTTPS on future visits, "
        "leaving users exposed to SSL-stripping and downgrade attacks."
      ),
      header_value="",
    ))
    return findings

  raw = hsts_value.strip()

  max_age_m = _MAX_AGE_RE.search(raw)
  if max_age_m is None:
    findings.append(HstsFinding(
      url=url,
      issue="hsts_max_age_missing",
      reason=(
        "The Strict-Transport-Security header is present but contains no "
        "max-age directive. Per RFC 6797 a missing max-age makes the header "
        "invalid; browsers will ignore it entirely."
      ),
      header_value=raw,
    ))
  else:
    max_age = int(max_age_m.group(1))
    if max_age < _WARN_MAX_AGE:
      findings.append(HstsFinding(
        url=url,
        issue="hsts_max_age_too_low",
        reason=(
          f"The HSTS max-age is {max_age} seconds (~{max_age // 86400} days), "
          f"below the recommended minimum of {_MIN_MAX_AGE} seconds (1 year). "
          "Short lifetimes leave a window for SSL-stripping and disqualify the "
          "domain from HSTS preload lists."
        ),
        header_value=raw,
      ))

  if not re.search(r'\bincludeSubDomains\b', raw, re.IGNORECASE):
    findings.append(HstsFinding(
      url=url,
      issue="hsts_includesubdomains_missing",
      reason=(
        "The HSTS header lacks includeSubDomains. Subdomains can still be "
        "reached over plain HTTP, enabling cookie theft and SSL-stripping on "
        "subdomain traffic."
      ),
      header_value=raw,
    ))

  if not re.search(r'\bpreload\b', raw, re.IGNORECASE):
    findings.append(HstsFinding(
      url=url,
      issue="hsts_preload_missing",
      reason=(
        "The HSTS header lacks the preload flag. Without it the domain cannot "
        "be submitted to browser HSTS preload lists, which protect first-time "
        "visitors who have never seen the header."
      ),
      header_value=raw,
    ))

  return findings


def _get_header(headers: Dict[str, str], name: str) -> Optional[str]:
  """Case-insensitive header lookup; returns None if absent."""
  for k, v in headers.items():
    if k.lower() == name.lower():
      return v
  return None
