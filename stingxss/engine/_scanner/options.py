# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Scan configuration."""

from __future__ import annotations

from typing import Any


class ScanOptions:
  def __init__(
    self,
    crawl:              bool             = False,
    blind_callback:     str              = "",
    data:               str              = "",
    headers:            dict[str, str] | None = None,
    cookies:            str              = "",
    proxy:              str              = "",
    threads:            int              = 5,
    timeout:            int              = 15,
    level:              int              = 1,
    custom_payloads:    list[str] | None = None,
    max_pages:          int              = 50,
    max_depth:          int              = 3,
    delay:              float            = 0.0,
    exclude_patterns:   list[Any] | None = None,
    inject_headers:     list[str] | None = None,
    test_stored:        bool             = False,
    browser:            bool             = False,
    browser_headless:   bool             = True,
    chromium_path:      str              = "",
    chromedriver_path:  str              = "",
    dom_include_minified: bool           = False,
    probe_filter:       bool             = True,
    poc:                bool             = False,
    evasion_chain:      list[str] | None = None,
    randomize_payloads: bool             = False,
    # ── New options ───────────────────────────────────────────────────────
    graphql:            bool             = False,
    graphql_endpoints:  list[str] | None = None,
    websocket:          bool             = False,
    ws_urls:            list[str] | None = None,
    source_maps:        bool             = False,
    payload_url:        str              = "",
    dork_engine:        str              = "ddg",
    auth_type:          str              = "",
    auth_cred:          str              = "",
  ) -> None:
    self.crawl            = crawl
    self.blind_callback   = blind_callback.strip()
    self.data             = data.strip()
    self.headers          = headers or {}
    self.cookies          = cookies.strip()
    self.proxy            = proxy.strip()
    self.threads          = max(1, min(threads, 20))
    self.timeout          = max(5, min(timeout, 120))
    self.level            = max(1, min(level, 3))
    self.custom_payloads  = custom_payloads or []
    self.max_pages        = max_pages
    self.max_depth        = max_depth
    self.delay            = max(0.0, delay)
    self.exclude_patterns: list[Any] = exclude_patterns or []
    self.inject_headers:   list[str] = inject_headers or []
    self.test_stored:      bool      = test_stored
    self.browser:          bool      = browser
    self.browser_headless: bool      = browser_headless
    self.chromium_path:    str       = chromium_path.strip()
    self.chromedriver_path: str      = chromedriver_path.strip()
    self.dom_include_minified: bool  = dom_include_minified
    self.probe_filter:         bool  = probe_filter
    self.poc:                  bool  = poc
    self.evasion_chain:    list[str] = evasion_chain or []
    self.randomize_payloads: bool    = randomize_payloads
    self.graphql:              bool      = graphql
    self.graphql_endpoints:    list[str] = graphql_endpoints or []
    self.websocket:            bool      = websocket
    self.ws_urls:              list[str] = ws_urls or []
    self.source_maps:      bool      = source_maps
    self.payload_url:      str       = payload_url.strip()
    self.dork_engine:      str       = dork_engine or "ddg"
    self.auth_type:        str       = auth_type.strip().lower()
    self.auth_cred:        str       = auth_cred.strip()
