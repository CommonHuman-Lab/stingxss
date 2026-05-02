# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
StingXSS — engine/vuln_libs.py
Vulnerable JavaScript library detector.

Detection strategy
------------------
Two complementary methods are used so that detection works both for libraries
loaded from a CDN (URL-based) and for locally hosted copies (content-based):

1. **URL signature matching**
   Any <script src="..."> whose URL contains a known library name followed by a
   version number is compared against the known-bad version table.

2. **Inline content fingerprinting**
   For inline <script> blocks (or fetched external scripts), a short
   library-specific fingerprint string present only in that library's source is
   searched for.  When found the version is extracted from the source string and
   compared against the known-bad version table.

Known vulnerable libraries
--------------------------
jQuery 1.x < 1.9.0
  CVE / tracker: https://bugs.jquery.com/ticket/11290
  Vulnerable behaviour: selector parsing executes arbitrary HTML, allowing DOM-
  based XSS via $("<img onerror=... src=x>") passed as a CSS selector.
  Safe versions: 1.9.0+ (patched), or 2.x / 3.x.

The table is intentionally designed to be easy to extend — add one entry per
library to KNOWN_VULNERABLE_LIBS.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Version comparison helper (no external deps)
# ---------------------------------------------------------------------------

def _ver(v: str) -> Tuple[int, ...]:
    """Parse a dotted-version string into a comparable integer tuple."""
    try:
        parts = tuple(int(x) for x in re.split(r"[.\-]", v) if x.isdigit())
        return parts if parts else (0,)
    except Exception:
        return (0,)


# ---------------------------------------------------------------------------
# Known-vulnerable library table
# ---------------------------------------------------------------------------
# Each entry:
#   library_id   : short lowercase key used in findings
#   display_name : human-readable library name
#   url_patterns : list of regex strings matched against script src URLs
#   ver_regex    : regex to extract version from src URL or inline content
#   inline_fp    : short string unique to this library's source (for content scan)
#   vuln_if      : callable(version_tuple) -> bool — True when the version is vulnerable
#   advisory     : URL or short description of the vulnerability

@dataclass(frozen=True)
class _LibSpec:
    library_id:   str
    display_name: str
    url_patterns: Tuple[str, ...]
    ver_regex:    str
    inline_fp:    str
    vuln_if:      object   # Callable[[Tuple[int,...]], bool]
    advisory:     str


KNOWN_VULNERABLE_LIBS: List[_LibSpec] = [
    _LibSpec(
        library_id   = "jquery",
        display_name = "jQuery",
        url_patterns = (
            r"jquery[._\-](\d+\.\d+(?:\.\d+)*)",    # jquery-1.8.1.min.js
            r"jquery/(\d+\.\d+(?:\.\d+)*)/",          # CDN path: /jquery/1.8.1/
        ),
        ver_regex    = r"jquery\s+(?:javascript\s+library\s+)?v?(\d+\.\d+(?:\.\d+)*)",
        inline_fp    = "jQuery JavaScript Library",
        vuln_if      = lambda v: len(v) >= 2 and v[0] == 1 and v[1] < 9,
        advisory     = (
            "jQuery < 1.9.0 is vulnerable to DOM-based XSS via malformed CSS "
            "selectors (https://bugs.jquery.com/ticket/11290). Upgrade to 1.9.0+ "
            "or any 2.x / 3.x release."
        ),
    ),
]

# Pre-compiled per-library URL regexes for performance
_URL_REGEXES: Dict[str, List[re.Pattern]] = {
    spec.library_id: [re.compile(p, re.IGNORECASE) for p in spec.url_patterns]
    for spec in KNOWN_VULNERABLE_LIBS
}

# Pre-compiled version extractor regexes
_VER_REGEXES: Dict[str, re.Pattern] = {
    spec.library_id: re.compile(spec.ver_regex, re.IGNORECASE)
    for spec in KNOWN_VULNERABLE_LIBS
}

# ---------------------------------------------------------------------------
# Finding dataclass (also used by reporter.py)
# ---------------------------------------------------------------------------

@dataclass
class VulnLibFinding:
    url:          str    # page URL where the library was found
    library:      str    # display name, e.g. "jQuery"
    version:      str    # detected version string, e.g. "1.8.1"
    source:       str    # "script_src" | "inline_content"
    evidence:     str    # the src URL or inline snippet that triggered the finding
    advisory:     str    # human-readable advisory / upgrade guidance


# ---------------------------------------------------------------------------
# HTML parser — collects <script src="..."> values
# ---------------------------------------------------------------------------

class _ScriptSrcParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.srcs: List[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() != "script":
            return
        for name, value in attrs:
            if name.lower() == "src" and value:
                self.srcs.append(value.strip())


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check(page_url: str, html: str) -> List[VulnLibFinding]:
    """
    Scan `html` (the source of `page_url`) for vulnerable JavaScript libraries.

    Returns a (possibly empty) list of VulnLibFinding.
    """
    findings: List[VulnLibFinding] = []

    # --- 1. URL-based detection on <script src="..."> tags ------------------
    parser = _ScriptSrcParser()
    try:
        parser.feed(html)
    except Exception:
        pass

    for src in parser.srcs:
        result = _check_src_url(page_url, src)
        if result and not _already_found(findings, result):
            findings.append(result)

    # --- 2. Inline content fingerprinting -----------------------------------
    for spec in KNOWN_VULNERABLE_LIBS:
        if spec.inline_fp in html:
            result = _check_inline_content(page_url, html, spec)
            if result and not _already_found(findings, result):
                findings.append(result)

    return findings


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _check_src_url(page_url: str, src: str) -> Optional[VulnLibFinding]:
    """Try to identify a vulnerable library from a script src URL."""
    for spec in KNOWN_VULNERABLE_LIBS:
        for pattern in _URL_REGEXES[spec.library_id]:
            m = pattern.search(src)
            if m:
                version_str = m.group(1)
                version_tup = _ver(version_str)
                if spec.vuln_if(version_tup):
                    return VulnLibFinding(
                        url      = page_url,
                        library  = spec.display_name,
                        version  = version_str,
                        source   = "script_src",
                        evidence = src[:200],
                        advisory = spec.advisory,
                    )
    return None


def _check_inline_content(
    page_url: str,
    html: str,
    spec: _LibSpec,
) -> Optional[VulnLibFinding]:
    """
    Try to identify a vulnerable library from inline page content using the
    library's unique fingerprint string and version regex.
    """
    ver_re = _VER_REGEXES[spec.library_id]
    m = ver_re.search(html)
    if not m:
        return None
    version_str = m.group(1)
    version_tup = _ver(version_str)
    if not spec.vuln_if(version_tup):
        return None
    # Build a small evidence snippet around the fingerprint
    fp_idx = html.find(spec.inline_fp)
    snippet = html[max(0, fp_idx):fp_idx + 120].strip()
    return VulnLibFinding(
        url      = page_url,
        library  = spec.display_name,
        version  = version_str,
        source   = "inline_content",
        evidence = snippet[:200],
        advisory = spec.advisory,
    )


def _already_found(findings: List[VulnLibFinding], candidate: VulnLibFinding) -> bool:
    """Deduplication guard — skip if same library+version already recorded."""
    return any(
        f.library == candidate.library and f.version == candidate.version
        for f in findings
    )
