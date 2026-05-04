# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Path-segment injection: appends XSS payloads as extra URL path segments and
checks whether the payload is reflected in the response body.

This catches server-side routes that echo back the URL path (e.g. Flask
``<path:subpath>`` segments, Express ``:param`` segments, 404 error pages
that repeat the requested path, etc.).
"""

from __future__ import annotations

import html
import re
from typing import Any

from ..log import get_logger
from ..analysis.parser import PROBE_MARKER, find_context
from ..analysis.payload_gen import generate, make_confirm_marker
from ..http.injector import Injector
from ..reporter import ReflectedFinding, ScanResult
from .options import ScanOptions

logger = get_logger("stingxss.scanner")

_TAG_OPEN_RE = re.compile(r"<([a-zA-Z][\w:-]*)", re.ASCII)


def _extract_tag(payload: str) -> str:
    m = _TAG_OPEN_RE.search(payload)
    return m.group(0).lower() if m else ""


def _confirm(text: str, marker: str, payload: str) -> tuple[bool, str]:
    unesc = html.unescape(text)
    tag = _extract_tag(payload)
    ok = marker.lower() in unesc.lower() and (not tag or tag in unesc.lower())
    idx = unesc.lower().find(payload[:20].lower())
    snip = unesc[max(0, idx - 30): idx + 80].strip() if idx != -1 else ""
    return ok, snip


def run_path_injection(
    crawled_urls: list[str],
    evasions: list[str],
    opts: ScanOptions,
    injector: Injector,
    result: ScanResult,
) -> None:
    """
    For each crawled URL (no query params, no form), probe whether the path
    itself is injectable by appending a marker as a path segment and checking
    for reflection.  If reflected, generate context-specific payloads.
    """
    tested: set[str] = set()

    for url in crawled_urls:
        # Only test URLs without query params (path-only endpoints)
        if "?" in url:
            continue
        if url in tested:
            continue
        if any(p.search(url) for p in opts.exclude_patterns):
            continue
        tested.add(url)

        # Probe: append marker as path segment
        try:
            resp = injector.inject_path(url, PROBE_MARKER)
        except Exception:
            continue

        from ..analysis.parser import is_reflected
        if not is_reflected(resp.text, marker=PROBE_MARKER):
            continue

        logger.debug("Path injection reflected on: %s", url)
        context = find_context(resp.text, PROBE_MARKER)
        logger.debug("Path context: %s", context)

        for evasion in evasions:
            marker = make_confirm_marker()
            payloads = generate(
                context=context, evasion=evasion, marker=marker,
                custom_payloads=opts.custom_payloads, level=opts.level,
            )
            confirmed_this = False
            for payload in payloads:
                try:
                    r = injector.inject_path(url, payload)
                except Exception:
                    continue
                ok, snip = _confirm(r.text, marker, payload)
                result.append_reflected(ReflectedFinding(
                    url=url + "/" + payload, parameter="[path]",
                    method="GET", context=context,
                    payload=payload, confirmed=ok, evidence=snip,
                ))
                if ok:
                    logger.finding(
                        "PATH XSS CONFIRMED: %s — %s", url, payload[:60],
                    )
                    confirmed_this = True
                    break
            if confirmed_this:
                break
