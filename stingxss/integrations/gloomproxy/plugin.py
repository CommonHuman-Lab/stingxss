# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""GloomProxy plugin wrapper for StingXSS.

Thin adapter only — all offensive logic lives in stingxss.engine.
"""
from __future__ import annotations

import asyncio
import logging

from gloomproxy_sdk import BaseScanner, Finding, ScanContext, Target, ScanOptionDef
from gloomproxy_sdk.capabilities import PluginCapabilities
from gloomproxy_sdk.manifest import PluginManifest, TrustLevel

from .adapter import build_options
from .mapper import map_results
from .metadata import CAPABILITIES

log = logging.getLogger(__name__)


class StingXSSPlugin(BaseScanner):
    name = "stingxss"
    version = "0.1.8"
    description = "Context-aware reflected & DOM XSS scanner with WAF detection and evasion"
    author = "CommonHuman-Lab"
    tags = ["xss", "active", "http"]

    @classmethod
    def capabilities(cls) -> PluginCapabilities:
        return CAPABILITIES

    @classmethod
    def manifest(cls) -> PluginManifest:
        return {
            "trust_level": TrustLevel.CORE,
            "resources": {"max_runtime": 600, "max_findings": 5000},
            "sdk_min_version": "0.1.0",
        }

    @classmethod
    def option_schema(cls) -> list[ScanOptionDef]:
        return [
            {"key": "crawl",       "label": "Crawl",       "type": "bool",   "default": False, "description": "Crawl site to discover pages before scanning"},
            {"key": "level",       "label": "Level",       "type": "select", "default": "1",   "description": "Payload intensity",
             "choices": [{"value": "1", "label": "1 — Fast"}, {"value": "2", "label": "2 — Normal"}, {"value": "3", "label": "3 — Thorough"}]},
            {"key": "test_stored", "label": "Stored XSS",  "type": "bool",   "default": False, "description": "Test for stored cross-site scripting"},
            {"key": "graphql",     "label": "GraphQL",     "type": "bool",   "default": False, "description": "Test GraphQL introspection endpoints"},
            {"key": "websocket",   "label": "WebSocket",   "type": "bool",   "default": False, "description": "Test WebSocket connections for XSS"},
            {"key": "threads",     "label": "Threads",     "type": "int",    "default": 5,     "description": "Concurrent request threads", "min": 1, "max": 20},
        ]

    def initialize(self, context: ScanContext) -> None:
        self._options = build_options(context)

    async def scan(self, target: Target) -> list[Finding]:
        from stingxss.engine.scanner import scan as stingxss_scan

        options = self._options
        url = target.url

        await self.ctx.events.progress("Starting StingXSS scan", 0.0)

        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, stingxss_scan, url, options
            )
        except Exception as exc:
            log.exception("StingXSS engine error for %s", url)
            await self.ctx.events.debug(f"StingXSS engine error: {exc}")
            return []

        findings = map_results(result)

        await self.ctx.events.progress(
            f"StingXSS complete — {len(findings)} finding(s)", 1.0
        )
        log.info("StingXSS: %d finding(s) for %s", len(findings), url)
        return findings
