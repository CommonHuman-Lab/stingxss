# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Vulnerable JavaScript library detector.

Delegates the library specification to ``commonhuman_payloads.js_vulns`` so
that the database is shared across all CommonHuman-Lab tools.  This module
only handles HTML parsing and the scan entry point.

Detection strategy
------------------
1. **URL signature matching** — ``<script src="...">`` URLs containing a
   known library name + version are compared against the known-bad version table.
2. **Inline content fingerprinting** — inline ``<script>`` blocks (or fetched
   external scripts) are searched for a library-specific unique string; the
   version is extracted and compared.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple

from commonhuman_payloads.js_vulns import KNOWN_VULNERABLE_LIBS, LibSpec, _ver


# ---------------------------------------------------------------------------
# Finding dataclass (compatible with reporter.py VulnLibFinding)
# ---------------------------------------------------------------------------

@dataclass
class VulnLibFinding:
    url:          str    # page URL where the library was found
    library:      str    # display name, e.g. "jQuery"
    version:      str    # detected version string, e.g. "1.8.1"
    source:       str    # "script_src" | "inline_content"
    evidence:     str    # the src URL or inline snippet that triggered the finding
    advisory:     str    # human-readable advisory / upgrade guidance
    cve:          str = ""   # CVE ID(s) from the library spec


# ---------------------------------------------------------------------------
# Pre-compiled regex caches (built once from the shared database)
# ---------------------------------------------------------------------------

_URL_REGEXES: Dict[str, List[re.Pattern]] = {
    spec.library_id: [re.compile(p, re.IGNORECASE) for p in spec.url_patterns]
    for spec in KNOWN_VULNERABLE_LIBS
}

_VER_REGEXES: Dict[str, re.Pattern] = {
    spec.library_id: re.compile(spec.ver_regex, re.IGNORECASE)
    for spec in KNOWN_VULNERABLE_LIBS
}


# ---------------------------------------------------------------------------
# HTML parser — collects <script src="..."> values
# ---------------------------------------------------------------------------

class _ScriptSrcParser(HTMLParser):
    """Collect all <script src="..."> values from an HTML page."""

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
    """Scan *html* (the source of *page_url*) for vulnerable JavaScript libraries.

    Returns a (possibly empty) list of VulnLibFinding.
    """
    findings: List[VulnLibFinding] = []

    parser = _ScriptSrcParser()
    try:
        parser.feed(html)
    except (AssertionError, ValueError):
        pass

    for src in parser.srcs:
        r = _check_src_url(page_url, src)
        if r and not _already_found(findings, r):
            findings.append(r)

    for spec in KNOWN_VULNERABLE_LIBS:
        if spec.inline_fp in html:
            r = _check_inline_content(page_url, html, spec)
            if r and not _already_found(findings, r):
                findings.append(r)

    return findings


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _check_src_url(page_url: str, src: str) -> Optional[VulnLibFinding]:
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
                        cve      = spec.cve,
                    )
    return None


def _check_inline_content(page_url: str, html: str, spec: LibSpec) -> Optional[VulnLibFinding]:
    ver_re = _VER_REGEXES[spec.library_id]
    m = ver_re.search(html)
    if not m:
        return None
    version_str = m.group(1)
    version_tup = _ver(version_str)
    if not spec.vuln_if(version_tup):
        return None
    fp_idx  = html.find(spec.inline_fp)
    snippet = html[max(0, fp_idx): fp_idx + 120].strip()
    return VulnLibFinding(
        url      = page_url,
        library  = spec.display_name,
        version  = version_str,
        source   = "inline_content",
        evidence = snippet[:200],
        advisory = spec.advisory,
        cve      = spec.cve,
    )


def _already_found(findings: List[VulnLibFinding], candidate: VulnLibFinding) -> bool:
    return any(
        f.library == candidate.library and f.version == candidate.version
        for f in findings
    )
