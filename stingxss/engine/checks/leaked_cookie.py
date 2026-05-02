# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
StingXSS — engine/leaked_cookie.py
httpOnly cookie leak detector.

Vulnerability class (Google Firing Range /leakedcookie/)
---------------------------------------------------------
A server sets a cookie with the HttpOnly flag, which is supposed to prevent
JavaScript from reading it via document.cookie.  However, if the server also
echoes the cookie *value* somewhere in:

  1. The HTML response body of the same (or any) page.
  2. A resource (JS file, JSON endpoint, etc.) referenced by the page.

…then an attacker who can read the DOM (e.g. via XSS) can trivially recover
the "protected" value, negating the HttpOnly protection entirely.

Detection strategy
------------------
1. Fetch the target URL and parse all Set-Cookie response headers.
2. For each cookie marked HttpOnly, check whether its *value* appears
   verbatim in the response body.  If so → "leaked_in_body".
3. Extract all <script src="..."> URLs from the page.
4. Fetch each referenced resource.  If the cookie value appears there
   → "leaked_in_resource".
5. Report a LeakedCookieFinding for every (cookie, leak_location) pair.

Notes
-----
- Only cookies with the HttpOnly flag set are interesting here.
- Cookie values shorter than 4 characters are skipped (too many false
  positives from short/generic values like "0", "1", "true", etc.).
- The check is case-sensitive because cookie values are case-sensitive.
"""

from __future__ import annotations

import re
import urllib.parse as up
from dataclasses import dataclass
from typing import List, Optional


# Minimum length of a cookie value before we consider it worth checking
_MIN_VALUE_LEN = 4

# Regex to parse Set-Cookie header — extracts name, value, and flags
_SET_COOKIE_RE = re.compile(
    r'^(?P<name>[^=\s]+)\s*=\s*(?P<value>[^;]*)',
)
_HTTPONLY_FLAG_RE = re.compile(r'\bHttpOnly\b', re.IGNORECASE)

# Tags whose src/href URLs we fetch looking for leaked values
_RESOURCE_ATTR_RE = re.compile(
    r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)


@dataclass
class LeakedCookieFinding:
    url:          str    # page URL where the cookie was set
    cookie_name:  str
    cookie_value: str    # partial — we show up to 30 chars for safety
    leak_type:    str    # "leaked_in_body" | "leaked_in_resource"
    resource_url: str    # URL of the resource where the value was found (empty for body)
    evidence:     str    # snippet surrounding the leaked value
    reason:       str


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check(
    url: str,
    response_headers: dict,
    response_body: str,
    injector=None,
) -> List[LeakedCookieFinding]:
    """
    Check for httpOnly cookie values leaked in the response body or resources.

    Parameters
    ----------
    url              : The URL that was fetched.
    response_headers : Response headers dict (case-insensitive keys accepted).
    response_body    : Text body of the response.
    injector         : Optional Injector instance.  If provided, referenced JS
                       resources will be fetched and checked too.

    Returns a (possibly empty) list of LeakedCookieFinding.
    """
    findings: List[LeakedCookieFinding] = []

    httponly_cookies = _parse_httponly_cookies(response_headers)
    if not httponly_cookies:
        return findings

    # --- Case 1: value leaked in the HTML body --------------------------------
    for name, value in httponly_cookies.items():
        if len(value) < _MIN_VALUE_LEN:
            continue
        if value in response_body:
            idx = response_body.find(value)
            evidence = response_body[max(0, idx - 30): idx + len(value) + 30].strip()
            findings.append(LeakedCookieFinding(
                url=url,
                cookie_name=name,
                cookie_value=value[:30],
                leak_type="leaked_in_body",
                resource_url="",
                evidence=evidence[:200],
                reason=(
                    f"HttpOnly cookie '{name}' has its value echoed verbatim in the HTML "
                    f"response body of {url}.  The HttpOnly flag is ineffective because "
                    "any script that can read the DOM can recover the cookie value."
                ),
            ))

    # --- Case 2: value leaked in a referenced resource -----------------------
    if injector is None:
        return findings

    resource_urls = _extract_resource_urls(response_body, url)
    for res_url in resource_urls:
        try:
            resp = injector.get(res_url)
            resource_body = resp.text
        except Exception:
            continue

        for name, value in httponly_cookies.items():
            if len(value) < _MIN_VALUE_LEN:
                continue
            # Skip if already flagged as leaked-in-body (avoid duplicate)
            already_body = any(
                f.cookie_name == name and f.leak_type == "leaked_in_body"
                for f in findings
            )
            if value in resource_body:
                idx = resource_body.find(value)
                evidence = resource_body[max(0, idx - 30): idx + len(value) + 30].strip()
                findings.append(LeakedCookieFinding(
                    url=url,
                    cookie_name=name,
                    cookie_value=value[:30],
                    leak_type="leaked_in_resource",
                    resource_url=res_url,
                    evidence=evidence[:200],
                    reason=(
                        f"HttpOnly cookie '{name}' has its value echoed verbatim in the "
                        f"resource {res_url} referenced by {url}.  The HttpOnly flag is "
                        "ineffective because any script that can read the resource can "
                        "recover the cookie value."
                    ),
                ))

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_httponly_cookies(headers: dict) -> dict:
    """
    Return {name: value} for every Set-Cookie header that carries the
    HttpOnly flag.  Handles both single-value and multi-value header dicts.
    """
    result: dict = {}

    # Collect all Set-Cookie header values (may be a list or a single string)
    raw_values: List[str] = []
    for key, val in headers.items():
        if key.lower() == "set-cookie":
            if isinstance(val, list):
                raw_values.extend(val)
            else:
                raw_values.append(str(val))

    for raw in raw_values:
        if not _HTTPONLY_FLAG_RE.search(raw):
            continue  # not HttpOnly — skip
        m = _SET_COOKIE_RE.match(raw.strip())
        if m:
            name  = m.group("name").strip()
            value = m.group("value").strip()
            if value:
                result[name] = value

    return result


def _extract_resource_urls(body: str, base_url: str) -> List[str]:
    """Return absolute URLs of <script src="..."> references in body."""
    urls = []
    for m in _RESOURCE_ATTR_RE.finditer(body):
        src = m.group(1).strip()
        if not src or src.startswith(("data:", "javascript:")):
            continue
        try:
            abs_url = up.urljoin(base_url, src)
            urls.append(abs_url)
        except Exception:
            pass
    return urls
