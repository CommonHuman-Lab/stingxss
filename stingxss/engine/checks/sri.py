# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
StingXSS — engine/sri.py
Subresource Integrity (SRI) / insecure third-party script detector.

Vulnerability classes (Google Firing Range /insecurethirdpartyscripts/)
-----------------------------------------------------------------------
1. **Static third-party script without integrity**
   A <script src="//..."> or <script src="https://..."> tag loads a resource
   from a cross-origin host but carries no `integrity` attribute.  Without SRI
   the browser will execute whatever content the CDN (or an attacker who has
   compromised it) serves.

   Detection: parse all <script src="..."> tags whose src resolves to a
   different origin from the page; flag those that lack a valid `integrity`
   attribute (sha256-..., sha384-..., or sha512-...).

2. **Dynamically added third-party script without integrity**
   Inline JavaScript creates a <script> element and assigns a cross-origin URL
   to `.src` (e.g. `script.src = '//nonexistent.google'`) without setting
   `.integrity` before the element is appended.  Because the script is added
   at runtime there is no static tag to inspect, so SRI can never be enforced
   by the browser.

   Detection: search inline <script> blocks for patterns that construct a
   <script> element and assign a cross-origin URL to `.src` without a
   corresponding `.integrity` assignment in the same block.

Cross-origin definition
-----------------------
A src URL is "cross-origin" when:
  - It is protocol-relative (//host/...) — the host differs from the page host.
  - It is absolute (https://host/...) — the host differs from the page host.
  - Same-origin relative paths (/path, ./path) are NOT flagged.

`integrity` is considered present when:
  - For static tags: the `integrity` attribute exists and starts with sha256-,
    sha384-, or sha512-.
  - For dynamic scripts: a `.integrity =` assignment appears in the same inline
    block as the `.src` assignment.
"""

from __future__ import annotations

import re
import urllib.parse as up
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class SriFinding:
    url:        str    # page URL where the issue was found
    issue:      str    # "static_no_integrity" | "dynamic_no_integrity"
    script_src: str    # the cross-origin URL that has no integrity check
    reason:     str    # human-readable explanation
    evidence:   str    # the raw tag or JS snippet (truncated to 300 chars)


# ---------------------------------------------------------------------------
# HTML parser — collects <script> tag attributes
# ---------------------------------------------------------------------------

class _ScriptTagParser(HTMLParser):
    """Collects (src, integrity, is_inline_block) for every <script> tag."""

    def __init__(self) -> None:
        super().__init__()
        # List of (src_value, integrity_value) for every <script src="..."> tag
        self.external_scripts: List[Tuple[str, str]] = []
        # Raw text of every inline <script>...</script> block
        self.inline_blocks: List[str] = []
        self._capturing: bool = False
        self._buf: str = ""

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() != "script":
            return
        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        src = attr_dict.get("src", "").strip()
        integrity = attr_dict.get("integrity", "").strip()
        if src:
            self.external_scripts.append((src, integrity))
            self._capturing = False
        else:
            self._capturing = True
            self._buf = ""

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._capturing:
            self.inline_blocks.append(self._buf)
            self._capturing = False
            self._buf = ""

    def handle_data(self, data: str) -> None:
        if self._capturing:
            self._buf += data


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Valid SRI integrity attribute prefix
_VALID_INTEGRITY_RE = re.compile(r'^sha(?:256|384|512)-', re.IGNORECASE)

# Detects dynamic script src assignment: script.src = '//...' or "https://..."
_DYN_SRC_RE = re.compile(
    r'\.src\s*=\s*[\'"]'       # .src = ' or .src = "
    r'((?:https?:)?//[^\'"]+)'  # protocol-relative or absolute URL
    r'[\'"]',
    re.IGNORECASE,
)

# Detects .integrity = 'sha...' assignment in inline JS
_DYN_INTEGRITY_RE = re.compile(r'\.integrity\s*=\s*[\'"]sha(?:256|384|512)-', re.IGNORECASE)


def _is_cross_origin(page_url: str, src: str) -> bool:
    """
    Return True when `src` resolves to a different host than `page_url`.
    Relative paths that stay on the same host are not cross-origin.
    """
    if not src:
        return False
    # Protocol-relative: //host/path
    if src.startswith("//"):
        src_host = src[2:].split("/")[0].lower()
    elif src.lower().startswith("http://") or src.lower().startswith("https://"):
        src_host = up.urlparse(src).hostname or ""
    else:
        # Relative path — same origin by definition
        return False

    page_host = (up.urlparse(page_url).hostname or "").lower()
    return src_host != page_host


def _has_valid_integrity(integrity: str) -> bool:
    return bool(_VALID_INTEGRITY_RE.match(integrity))


def _normalise_src(page_url: str, src: str) -> str:
    """Return a displayable URL, filling in the scheme from the page when needed."""
    if src.startswith("//"):
        scheme = up.urlparse(page_url).scheme or "https"
        return f"{scheme}:{src}"
    return src


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check(page_url: str, html: str) -> List[SriFinding]:
    """
    Scan `html` (the source of `page_url`) for third-party scripts loaded
    without Subresource Integrity.

    Returns a (possibly empty) list of SriFinding.
    """
    findings: List[SriFinding] = []

    parser = _ScriptTagParser()
    try:
        parser.feed(html)
    except Exception:
        pass

    # ---- Case 1: static <script src="..."> without integrity ---------------
    for src, integrity in parser.external_scripts:
        if not _is_cross_origin(page_url, src):
            continue
        if _has_valid_integrity(integrity):
            continue
        display_src = _normalise_src(page_url, src)
        if _already_found(findings, display_src):
            continue
        findings.append(SriFinding(
            url        = page_url,
            issue      = "static_no_integrity",
            script_src = display_src,
            reason     = (
                f"A third-party script is loaded from '{display_src}' without a "
                "Subresource Integrity (integrity=) attribute. An attacker who "
                "compromises that host can inject arbitrary JavaScript into every "
                "visitor's browser."
            ),
            evidence   = f'<script src="{src}"'
                         + (f' integrity="{integrity}"' if integrity else "")
                         + ">",
        ))

    # ---- Case 2: dynamically added cross-origin <script> without integrity -
    for block in parser.inline_blocks:
        for m in _DYN_SRC_RE.finditer(block):
            raw_src = m.group(1)
            if not _is_cross_origin(page_url, raw_src):
                continue
            display_src = _normalise_src(page_url, raw_src)
            if _already_found(findings, display_src):
                continue
            # Check whether .integrity is assigned anywhere in this same block
            if _DYN_INTEGRITY_RE.search(block):
                continue
            snippet = block.strip()[:300]
            findings.append(SriFinding(
                url        = page_url,
                issue      = "dynamic_no_integrity",
                script_src = display_src,
                reason     = (
                    f"A script element is dynamically created and its src is set "
                    f"to the cross-origin URL '{display_src}' without assigning "
                    "a '.integrity' property. The browser cannot enforce SRI on "
                    "dynamically added scripts; the remote host is implicitly "
                    "trusted to serve safe content."
                ),
                evidence   = snippet,
            ))

    return findings


# ---------------------------------------------------------------------------
# Deduplication guard
# ---------------------------------------------------------------------------

def _already_found(findings: List[SriFinding], script_src: str) -> bool:
    return any(f.script_src == script_src for f in findings)
