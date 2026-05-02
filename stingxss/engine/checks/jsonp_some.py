# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
StingXSS — engine/jsonp_some.py
JSONP callback-injection and Universal Reverse ClickJacking (SOME) detector.

A JSONP endpoint is vulnerable when the `callback` (or similar) parameter is
reflected verbatim into a JS execution context:

    callbackValue({...});

If an attacker can control that value they can inject arbitrary JavaScript
(full XSS) or at minimum call any zero-argument method reachable from the
global scope (SOME / Reverse ClickJacking).

Detection strategy
------------------
1. Probe a set of common JSONP callback parameter names with a unique marker.
2. If the marker appears in the response **outside a quoted string** (i.e. in
   a code position) the endpoint is vulnerable.
3. Additionally, scan page source for <script src="...?callback=..."> patterns
   where the callback value is derived from a user-controlled source
   (location.search / location.hash) — client-side SOME.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

# ---------------------------------------------------------------------------
# Common JSONP callback parameter names to probe
# ---------------------------------------------------------------------------
_CALLBACK_PARAMS = [
    "callback",
    "cb",
    "jsonp",
    "jsonpcallback",
    "call",
    "fn",
    "func",
    "handler",
    "method",
    "on",
    "jsoncallback",
]

# Marker used for probing
_JSONP_PROBE = "stingxss_jsonp_probe"

# Pattern: marker appears at the very start of a non-whitespace token that is
# directly followed by ( — meaning it is being called as a function.
_REFLECTED_CALL_RE = re.compile(
    r'(?:^|[\s;,])(' + re.escape(_JSONP_PROBE) + r')\s*\(',
    re.MULTILINE,
)

# Broader: marker reflected anywhere not inside a quoted string
_REFLECTED_RE = re.compile(re.escape(_JSONP_PROBE))


@dataclass
class JsonpSomeFinding:
    url:         str
    parameter:   str          # e.g. "callback"
    issue:       str          # "jsonp_callback" or "some_callback"
    reason:      str
    # Whether the marker appeared in a callable position (function call)
    callable_reflection: bool = False
    evidence:    str = ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check(url: str, injector) -> List[JsonpSomeFinding]:
    """
    Probe `url` for JSONP callback injection / SOME.

    Parameters
    ----------
    url      : The URL to probe (query parameters already present are preserved).
    injector : An Injector instance for making HTTP requests.

    Returns a (possibly empty) list of JsonpSomeFinding.
    """
    findings: List[JsonpSomeFinding] = []

    for param in _CALLBACK_PARAMS:
        try:
            resp = injector.inject_get(url, param, _JSONP_PROBE)
        except Exception:
            continue

        body = resp.text
        if _REFLECTED_RE.search(body):
            callable_reflection = bool(_REFLECTED_CALL_RE.search(body))
            # Grab evidence snippet
            m = _REFLECTED_RE.search(body)
            start = max(0, m.start() - 30)
            evidence = body[start: m.start() + 60].strip()

            findings.append(JsonpSomeFinding(
                url=url,
                parameter=param,
                issue="jsonp_callback",
                reason=(
                    f"JSONP callback parameter '{param}' is reflected in the response body. "
                    + ("Reflected in a callable position — full JS injection possible."
                       if callable_reflection else
                       "Reflected outside a callable position — may allow SOME/reverse clickjacking.")
                ),
                callable_reflection=callable_reflection,
                evidence=evidence,
            ))
            break  # one finding per URL is enough for now

    return findings


# ---------------------------------------------------------------------------
# Static analysis helper — scan page HTML for client-side SOME patterns
# ---------------------------------------------------------------------------

# Matches: script src="...?callback=location.something"
# or:      script src="...?callback=" + location.hash ...
_CLIENT_SIDE_SOME_RE = re.compile(
    r'<script[^>]+src\s*=\s*["\'][^"\']*\?[^"\']*callback=[^"\']*(?:location|document\.URL)',
    re.IGNORECASE,
)
# Also catch JS patterns like: src = "/jsonp?callback=" + location.hash
_CLIENT_SIDE_SOME_JS_RE = re.compile(
    r'''(?:src\s*=\s*|\.src\s*=\s*)["\'][^"\']*\?[^"\']*callback=|'''
    r'''["\'][^"\']*callback=["\'].*\+.*(?:location\.(?:hash|search|href)|document\.URL)''',
    re.IGNORECASE,
)


def scan_page_for_some(url: str, html: str) -> List[JsonpSomeFinding]:
    """
    Scan `html` (page source) for client-side SOME indicators:
    JSONP <script> tags whose callback value derives from location/document.URL.
    """
    findings: List[JsonpSomeFinding] = []

    for m in _CLIENT_SIDE_SOME_RE.finditer(html):
        findings.append(JsonpSomeFinding(
            url=url,
            parameter="callback",
            issue="some_callback",
            reason="Page loads a JSONP script whose callback parameter is derived from a user-controlled URL source.",
            evidence=m.group(0)[:200],
        ))
        break

    return findings
