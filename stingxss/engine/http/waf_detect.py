# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""StingXSS — WAF detection"""

from __future__ import annotations

from typing import Optional

from commonhuman_payloads.waf import WafResult, detect as _detect
from commonhuman_payloads.waf.signatures import WafSignature  # noqa: F401 (re-export)
from commonhuman_payloads.encoders import (
    EVASION_NONE,
    EVASION_CASE_MIXING,
    EVASION_HTML_ENCODE,
    EVASION_UNICODE,
    EVASION_DOUBLE_ENCODE,
    EVASION_CHUNKED_TAGS,
    EVASION_NULL_BYTE,
    EVASION_NEWLINE,
    EVASION_COMMENT_BREAK,
    EVASION_BACKTICK,
    EVASION_CSS_EXPR,
)

# XSS probe — triggers most WAFs
_PROBE_PAYLOAD = "<script>alert(1)</script>"

__all__ = [
    "WafResult", "WafSignature", "detect",
    "EVASION_NONE", "EVASION_CASE_MIXING", "EVASION_HTML_ENCODE",
    "EVASION_UNICODE", "EVASION_DOUBLE_ENCODE", "EVASION_CHUNKED_TAGS",
    "EVASION_NULL_BYTE", "EVASION_NEWLINE", "EVASION_COMMENT_BREAK",
    "EVASION_BACKTICK", "EVASION_CSS_EXPR",
]


def detect(injector, url: str, param: Optional[str] = None) -> WafResult:
    """Probe for a WAF using the XSS probe payload."""
    return _detect(
        injector.get,
        url,
        param,
        probe_payload=_PROBE_PAYLOAD,
        check_reflection=True,
    )
