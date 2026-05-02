# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
StingXSS — engine/mixed_content.py
Mixed content detector.

Mixed content occurs when an HTTPS page loads active resources (scripts,
iframes, objects) over HTTP.  This allows a network attacker to inject
malicious JavaScript by tampering with the HTTP response.

Detection: fetch the page and look for http:// src/href references in
active-content tags (<script>, <iframe>, <object>, <embed>).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List
import urllib.parse as up


@dataclass
class MixedContentFinding:
    url:          str
    resource_url: str   # the http:// resource that was found
    tag:          str   # e.g. "script", "iframe", "object"
    reason:       str


# Active content tags that can execute code when loaded over HTTP
_ACTIVE_TAGS = {"script", "iframe", "object", "embed"}

# Match http:// src/href/data in active tags
_HTTP_SRC_RE = re.compile(
    r'<(script|iframe|object|embed)[^>]+(?:src|href|data)\s*=\s*["\']?(http://[^"\'>\s]+)',
    re.IGNORECASE,
)


def check(page_url: str, html: str) -> List[MixedContentFinding]:
    """
    Scan `html` (fetched from `page_url`) for mixed content.

    Only reports findings if `page_url` is HTTPS.
    """
    findings: List[MixedContentFinding] = []

    parsed = up.urlparse(page_url)
    if parsed.scheme.lower() != "https":
        return findings  # Not HTTPS — mixed content is not a security concern

    for m in _HTTP_SRC_RE.finditer(html):
        tag          = m.group(1).lower()
        resource_url = m.group(2)
        findings.append(MixedContentFinding(
            url=page_url,
            resource_url=resource_url,
            tag=tag,
            reason=(
                f"HTTPS page loads active <{tag}> resource over HTTP: {resource_url}. "
                "A network attacker can replace the resource with malicious content."
            ),
        ))

    return findings
