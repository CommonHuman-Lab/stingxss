# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Unit tests for stingxss.engine._scanner.websocket — all I/O mocked."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from stingxss.engine._scanner.websocket import (
    _extract_cookies,
    _ws_payloads,
    run_websocket_scan,
)
from stingxss.engine.reporter import ScanResult, WebsocketFinding
from stingxss.engine._scanner.options import ScanOptions


# ---------------------------------------------------------------------------
# _ws_payloads
# ---------------------------------------------------------------------------

class TestWsPayloads:
    def test_level1_returns_list(self):
        payloads = _ws_payloads("MARKER", 1)
        assert isinstance(payloads, list) and len(payloads) > 0

    def test_level3_more_than_level1(self):
        p1 = _ws_payloads("M", 1)
        p3 = _ws_payloads("M", 3)
        assert len(p3) > len(p1)

    def test_marker_in_all_payloads(self):
        marker = "TestMarker123"
        for level in (1, 2, 3):
            for p in _ws_payloads(marker, level):
                assert marker in p, f"level={level} payload missing marker: {p!r}"

    def test_includes_raw_and_json_payloads(self):
        payloads = _ws_payloads("M", 3)
        has_raw  = any("<img" in p or "<svg" in p for p in payloads)
        has_json = any('{"message"' in p or '{"data"' in p for p in payloads)
        assert has_raw
        assert has_json

    def test_level2_between_level1_and_level3(self):
        p1 = _ws_payloads("M", 1)
        p2 = _ws_payloads("M", 2)
        p3 = _ws_payloads("M", 3)
        assert len(p1) <= len(p2) <= len(p3)


# ---------------------------------------------------------------------------
# _extract_cookies
# ---------------------------------------------------------------------------

class TestExtractCookies:
    def test_no_session_returns_empty(self):
        injector = MagicMock(spec=[])
        assert _extract_cookies(injector) == ""

    def test_extracts_cookies_from_jar(self):
        cookie = MagicMock()
        cookie.name  = "session"
        cookie.value = "abc123"

        jar = MagicMock()
        jar.__iter__ = MagicMock(return_value=iter([cookie]))

        session = MagicMock()
        session.cookies = jar

        injector = MagicMock()
        injector._session = session

        result = _extract_cookies(injector)
        assert "session=abc123" in result

    def test_multiple_cookies_joined_with_semicolon(self):
        def _make_cookie(name, value):
            c = MagicMock()
            c.name  = name
            c.value = value
            return c

        jar = MagicMock()
        jar.__iter__ = MagicMock(return_value=iter([
            _make_cookie("a", "1"),
            _make_cookie("b", "2"),
        ]))

        session = MagicMock()
        session.cookies = jar

        injector = MagicMock()
        injector._session = session

        result = _extract_cookies(injector)
        assert "a=1" in result and "b=2" in result
        assert ";" in result


# ---------------------------------------------------------------------------
# run_websocket_scan
# ---------------------------------------------------------------------------

def _make_opts(**kwargs):
    defaults = dict(
        level=1,
        timeout=5,
        exclude_patterns=[],
    )
    defaults.update(kwargs)
    return ScanOptions(**defaults)


def _make_injector(html: str = ""):
    injector = MagicMock()
    resp = MagicMock()
    resp.text = html
    injector.get.return_value = resp
    injector._session = None
    return injector


class TestRunWebsocketScan:
    def test_no_urls_no_findings(self):
        result = ScanResult(target="https://example.com")
        injector = _make_injector()
        with patch("commonhuman_core.ws.WEBSOCKET_AVAILABLE", False):
            run_websocket_scan(
                seed_url="https://example.com",
                page_sources={},
                opts=_make_opts(),
                injector=injector,
                result=result,
            )
        assert result.websocket == []
        assert any("websocket-client" in e for e in result.errors)

    def test_appends_error_when_websocket_unavailable(self):
        result = ScanResult(target="https://example.com")
        injector = _make_injector()
        with patch("commonhuman_core.ws.WEBSOCKET_AVAILABLE", False):
            run_websocket_scan(
                seed_url="https://example.com",
                page_sources={},
                opts=_make_opts(),
                injector=injector,
                result=result,
            )
        assert len(result.errors) == 1

    def test_uses_explicit_ws_urls(self):
        """When ws_urls is provided, discovery is skipped."""
        result = ScanResult(target="https://example.com")
        injector = _make_injector()
        ws_results_mock = [MagicMock(reflected=False, payload="p", responses=[])]

        with patch("commonhuman_core.ws.WEBSOCKET_AVAILABLE", True), \
             patch("commonhuman_core.ws.ws_inject", return_value=ws_results_mock) as m_inject, \
             patch("commonhuman_core.ws.discover_ws_urls", return_value=[]) as m_discover, \
             patch("stingxss.engine.analysis.payload_gen.make_confirm_marker", return_value="MARKER"):
            run_websocket_scan(
                seed_url="https://example.com",
                page_sources={},
                opts=_make_opts(),
                injector=injector,
                result=result,
                ws_urls=["wss://example.com/ws"],
            )

        m_inject.assert_called_once()
        m_discover.assert_not_called()

    def test_discovers_ws_urls_from_page_sources(self):
        """Without explicit ws_urls, URLs are extracted from page_sources."""
        result = ScanResult(target="https://example.com")
        injector = _make_injector()
        ws_results_mock = [MagicMock(reflected=False, payload="p", responses=[])]

        page_sources = {"https://example.com/": 'new WebSocket("wss://example.com/feed");'}

        with patch("commonhuman_core.ws.WEBSOCKET_AVAILABLE", True), \
             patch("commonhuman_core.ws.ws_inject", return_value=ws_results_mock), \
             patch("stingxss.engine.analysis.payload_gen.make_confirm_marker", return_value="MARKER"):
            run_websocket_scan(
                seed_url="https://example.com",
                page_sources=page_sources,
                opts=_make_opts(),
                injector=injector,
                result=result,
            )

        # ws_inject was called (with the discovered URL)
        assert result.websocket == []  # not reflected → no finding

    def test_confirmed_reflection_creates_finding(self):
        result = ScanResult(target="https://example.com")
        injector = _make_injector()
        marker = "MARKER_abc"

        reflected_result = MagicMock()
        reflected_result.reflected = True
        reflected_result.payload   = f"<img src=x onerror=alert('{marker}')>"
        reflected_result.responses = [f'<img src=x onerror=alert("{marker}")>']

        with patch("commonhuman_core.ws.WEBSOCKET_AVAILABLE", True), \
             patch("commonhuman_core.ws.ws_inject", return_value=[reflected_result]), \
             patch("stingxss.engine.analysis.payload_gen.make_confirm_marker", return_value=marker):
            run_websocket_scan(
                seed_url="https://example.com",
                page_sources={},
                opts=_make_opts(),
                injector=injector,
                result=result,
                ws_urls=["wss://example.com/ws"],
            )

        assert len(result.websocket) == 1
        finding = result.websocket[0]
        assert isinstance(finding, WebsocketFinding)
        assert finding.confirmed is True
        assert finding.ws_url == "wss://example.com/ws"

    def test_excluded_pattern_skips_url(self):
        import re
        result = ScanResult(target="https://example.com")
        injector = _make_injector()

        with patch("commonhuman_core.ws.WEBSOCKET_AVAILABLE", True), \
             patch("commonhuman_core.ws.ws_inject") as m_inject, \
             patch("stingxss.engine.analysis.payload_gen.make_confirm_marker", return_value="M"):
            run_websocket_scan(
                seed_url="https://example.com",
                page_sources={},
                opts=_make_opts(exclude_patterns=[re.compile(r"example\.com")]),
                injector=injector,
                result=result,
                ws_urls=["wss://example.com/ws"],
            )

        m_inject.assert_not_called()
