# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Cross-Site Tracing (XST) detector.

Sends an HTTP TRACE request to the target.  If the server returns 200 with the
request body echoed back (Content-Type: message/http), the TRACE method is
enabled.  Combined with a browser XSS bug, an attacker can read HttpOnly cookies
via XHR in older browsers — CWE-693 / CAPEC-107.

Modern browsers block cross-origin TRACE, but TRACE being enabled is still a
security misconfiguration that should be reported.
"""

from __future__ import annotations

import urllib.parse as up
from typing import Optional

from ..reporter import XSTFinding


def check(url: str, injector) -> Optional[XSTFinding]:
    """Send a TRACE request to *url*.  Return an XSTFinding if TRACE is enabled."""
    origin = _origin(url)
    try:
        resp = injector._session.request(
            "TRACE", origin, timeout=injector.timeout, allow_redirects=False
        )
    except Exception:
        return None

    if resp is None:
        return None

    # TRACE is enabled when the server echoes our request headers back
    # with a 200 status and Content-Type: message/http.
    ct = resp.headers.get("Content-Type", "").lower()
    if resp.status_code == 200 and "message/http" in ct:
        return XSTFinding(
            url=origin,
            reason=(
                "HTTP TRACE method is enabled on this server.  A TRACE request "
                "is reflected back as 'Content-Type: message/http', which means "
                "the server echoes all request headers — including HttpOnly cookies "
                "and Authorization headers — in the response body.  Combined with "
                "a browser-based XSS vulnerability, an attacker can exfiltrate "
                "those headers via XHR (Cross-Site Tracing, CAPEC-107)."
            ),
        )

    # Some servers return 200 without the correct Content-Type but still echo
    # the TRACE verb in the response body (non-standard but equally dangerous).
    if resp.status_code == 200 and "TRACE" in (resp.text or "")[:200]:
        return XSTFinding(
            url=origin,
            reason=(
                "HTTP TRACE method is enabled (server responded 200 and echoed "
                "the TRACE verb in the response body).  This allows Cross-Site "
                "Tracing attacks when combined with a browser XSS vulnerability."
            ),
        )

    return None


def _origin(url: str) -> str:
    """Return scheme://host[:port]/ — the root of the target."""
    p = up.urlparse(url)
    return f"{p.scheme}://{p.netloc}/"
