# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""WebSocket XSS injection scanner stage.

Discovers WebSocket endpoints from crawled page sources, injects XSS payloads
as WebSocket messages, and records any findings where the marker is reflected
in a response frame.

Requires the optional ``websocket-client`` package::

    pip install stingxss[websocket]
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from ..reporter import ScanResult, WebsocketFinding
from .options import ScanOptions

logger = logging.getLogger("stingxss.websocket")


def run_websocket_scan(
    seed_url:     str,
    page_sources: Dict[str, str],
    opts:         ScanOptions,
    injector,
    result:       ScanResult,
    ws_urls:      Optional[List[str]] = None,
) -> None:
    """Discover and test WebSocket endpoints for XSS payload reflection.

    Called from the pipeline after surface building.  If *ws_urls* is
    provided those are tested directly; otherwise WebSocket URLs are
    extracted from *page_sources*.

    Args:
        seed_url:     Primary target URL (used for origin resolution).
        page_sources: Dict of ``{page_url: html_source}`` from the crawler.
        opts:         Current scan options.
        injector:     Injector instance (used only to read cookies/headers).
        result:       ScanResult to append findings to.
        ws_urls:      Explicit WebSocket URLs to test (overrides discovery).
    """
    try:
        from commonhuman_core.ws import WEBSOCKET_AVAILABLE, discover_ws_urls, ws_inject
    except ImportError:
        result.append_error("WebSocket scan: commonhuman-core not importable")
        return

    if not WEBSOCKET_AVAILABLE:
        result.append_error(
            "WebSocket scan requires websocket-client: "
            "pip install stingxss[websocket]"
        )
        return

    # ── 1. Collect WebSocket URLs ──────────────────────────────────────────
    found_ws_urls: List[str] = list(ws_urls or [])

    if not found_ws_urls:
        for page_url, html in page_sources.items():
            for ws_url in discover_ws_urls(html, base_url=page_url):
                if ws_url not in found_ws_urls:
                    found_ws_urls.append(ws_url)

        # Also check the seed URL's own source (may not be in page_sources)
        if seed_url not in page_sources:
            try:
                resp = injector.get(seed_url)
                for ws_url in discover_ws_urls(resp.text, base_url=seed_url):
                    if ws_url not in found_ws_urls:
                        found_ws_urls.append(ws_url)
            except Exception:
                pass

    if not found_ws_urls:
        logger.debug("websocket: no WebSocket endpoints discovered")
        return

    logger.info("websocket: testing %d WebSocket endpoint(s)", len(found_ws_urls))

    # ── 2. Build payloads ──────────────────────────────────────────────────
    from ..analysis.payload_gen import make_confirm_marker
    marker   = make_confirm_marker()
    payloads = _ws_payloads(marker, opts.level)

    # ── 3. Extract cookies/headers from the injector session ───────────────
    cookies = _extract_cookies(injector)

    # ── 4. Test each endpoint ──────────────────────────────────────────────
    for ws_url in found_ws_urls:
        if any(p.search(ws_url) for p in opts.exclude_patterns):
            continue

        logger.info("websocket: probing %s", ws_url)
        ws_results = ws_inject(
            url=ws_url,
            payloads=payloads,
            cookies=cookies,
            timeout=min(opts.timeout, 15),
            marker=marker,
            max_recv=30,  # enough to drain stored-message history before the echo
        )
        for ws_result in ws_results:
            if ws_result.reflected:
                evidence = next(
                    (r for r in ws_result.responses if marker in r),
                    ws_result.responses[0] if ws_result.responses else "",
                )
                finding = WebsocketFinding(
                    url=seed_url,
                    ws_url=ws_url,
                    payload=ws_result.payload,
                    response=evidence[:300],
                    confirmed=True,
                )
                result.append_websocket(finding)
                logger.warning(
                    "WebSocket XSS confirmed: ws_url=%s payload=%s",
                    ws_url, ws_result.payload[:80],
                )
                break  # one confirmed payload per endpoint is enough


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ws_payloads(marker: str, level: int) -> List[str]:
    """Return message payloads for WebSocket injection testing.

    The payloads cover three common WS message formats: plain text, JSON
    object with a 'message'/'msg' key, and JSON with a 'data' key.
    """
    raw = [
        f"<img src=x onerror=alert('{marker}')>",
        f"<svg onload=alert('{marker}')>",
        f"<script>alert('{marker}')</script>",
        f"javascript:alert('{marker}')",
        f"\"><img src=x onerror=alert('{marker}')>",
    ]

    import json as _json
    json_msg  = [_json.dumps({"message": p}) for p in raw[:3]]
    json_data = [_json.dumps({"data":    p}) for p in raw[:3]]
    json_text = [_json.dumps({"text":    p}) for p in raw[:2]]

    if level == 1:
        return raw[:2] + json_msg[:1]
    if level == 2:
        return raw[:3] + json_msg[:2] + json_data[:1]
    return raw + json_msg + json_data + json_text


def _extract_cookies(injector) -> str:
    """Extract the current session cookies from the injector as a header string."""
    try:
        session = getattr(injector, "_session", None)
        if session is None:
            return ""
        jar = session.cookies
        return "; ".join(f"{c.name}={c.value}" for c in jar)
    except Exception:
        return ""
