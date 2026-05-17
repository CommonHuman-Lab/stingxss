# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""CRLF / HTTP Response Splitting detector.

Injects CR+LF sequences into query parameters and common headers, then checks
whether the injected header name appears in the actual HTTP response headers.
A hit means the server is copying user input into an outgoing header without
sanitising newlines — classic HTTP Response Splitting (CWE-113).
"""

from __future__ import annotations

import urllib.parse as up
from typing import List, Optional

from ..reporter import CRLFFinding

_INJECTED_HEADER = "X-StingXSS-Crlf"
_INJECTED_VALUE  = "stingxss-crlf-detected"

# CRLF sequences to try — ordered from most to least likely to work
_CRLF_SEQUENCES = [
    "%0d%0a",         # standard URL-encoded CRLF
    "%0D%0A",         # uppercase variant
    "%0a",            # LF-only (sufficient in HTTP/1.1 with some parsers)
    "%250d%250a",     # double URL-encoded CRLF
    "%E5%98%8A%E5%98%8D",  # UTF-8 overlong encoding of CRLF (CVE-2019-15605 class)
    "\r\n",           # raw (reaches server when transport doesn't sanitise)
]

# Headers that commonly reflect user-supplied values back into response headers
_TEST_HEADERS = [
    "X-Forwarded-Host",
    "X-Forwarded-For",
    "Referer",
    "X-Custom-Name",
]


def check_params(
    url: str,
    param: str,
    method: str,
    injector,
    base_data: Optional[dict] = None,
) -> List[CRLFFinding]:
    """Probe a single (url, param) surface for CRLF injection via query/body parameters."""
    findings: List[CRLFFinding] = []
    canary = f"{_INJECTED_HEADER}: {_INJECTED_VALUE}"

    for seq in _CRLF_SEQUENCES:
        payload = f"stingxss{seq}{canary}"
        resp = _inject_param(injector, url, param, method, payload, base_data)
        if resp is None:
            continue
        if _header_injected(resp):
            findings.append(CRLFFinding(
                url=url,
                parameter=param,
                method=method,
                vector="param",
                payload=payload,
                injected_header=_INJECTED_HEADER,
                reason=(
                    f"Parameter '{param}' is reflected into an HTTP response header "
                    f"without sanitising newlines (CRLF sequence: {seq!r}).  "
                    "An attacker can inject arbitrary headers or split the HTTP "
                    "response to smuggle a second response body."
                ),
            ))
            break  # one finding per param is enough

    return findings


def check_headers(
    url: str,
    injector,
) -> List[CRLFFinding]:
    """Probe common reflected request headers for CRLF injection."""
    findings: List[CRLFFinding] = []
    canary = f"{_INJECTED_HEADER}: {_INJECTED_VALUE}"

    for header in _TEST_HEADERS:
        for seq in _CRLF_SEQUENCES:
            payload = f"stingxss{seq}{canary}"
            try:
                resp = injector.get(url, headers={header: payload})
            except Exception:
                continue
            if resp is None:
                continue
            if _header_injected(resp):
                findings.append(CRLFFinding(
                    url=url,
                    parameter=header,
                    method="GET",
                    vector="header",
                    payload=payload,
                    injected_header=_INJECTED_HEADER,
                    reason=(
                        f"Header '{header}' value is reflected into an HTTP response "
                        f"header without sanitising newlines (CRLF sequence: {seq!r}).  "
                        "An attacker can inject arbitrary response headers."
                    ),
                ))
                break  # one finding per header is enough

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _inject_param(injector, url, param, method, payload, base_data):
    try:
        parsed    = up.urlparse(url)
        qs        = up.parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        new_qs    = up.urlencode(qs, doseq=True)
        target    = up.urlunparse(parsed._replace(query=new_qs))
        return injector.get(target, allow_redirects=False)
    except Exception:
        return None


def _header_injected(resp) -> bool:
    """Return True if our injected header name appears in the response headers."""
    key_lower = _INJECTED_HEADER.lower()
    return any(k.lower() == key_lower for k in resp.headers)
