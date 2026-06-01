# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Translate a GloomProxy ScanContext into StingXSS ScanOptions."""
from __future__ import annotations

from gloomproxy_sdk import ScanContext
from gloomproxy_sdk.auth import extract_auth

from stingxss.engine._scanner.options import ScanOptions


def build_options(ctx: ScanContext) -> ScanOptions:
    """Build StingXSS ScanOptions from a GloomProxy ScanContext."""
    cfg = ctx.config
    auth = extract_auth(cfg)

    base_headers: dict[str, str] = dict(cfg.get("headers", {}))
    merged_headers = auth.merged_headers(base_headers)

    cookie_str = cfg.get("cookies", "")
    if not cookie_str and auth.cookies:
        cookie_str = auth.cookie_header

    return ScanOptions(
        crawl=bool(cfg.get("crawl", False)),
        headers=merged_headers or None,
        cookies=cookie_str,
        proxy=str(cfg.get("proxy", "")),
        timeout=int(cfg.get("timeout", 15)),
        delay=float(cfg.get("delay", 0.0)),
        threads=int(cfg.get("threads", 5)),
        level=int(cfg.get("level", 1)),
        max_pages=int(cfg.get("max_pages", 50)),
        max_depth=int(cfg.get("max_depth", 3)),
        blind_callback=str(cfg.get("blind_callback", "")),
        test_stored=bool(cfg.get("test_stored", False)),
        graphql=bool(cfg.get("graphql", False)),
        websocket=bool(cfg.get("websocket", False)),
    )
