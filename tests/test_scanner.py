# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Integration tests for engine/scanner.py — scan pipeline.
Uses mocked Injector responses to avoid real HTTP traffic.
"""

from __future__ import annotations

import re
from unittest.mock import MagicMock, patch

import pytest

from stingxss.engine.scanner import scan, ScanOptions, _test_param
from stingxss.engine.reporter import ReflectedFinding, ReflectionContext, ScanResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(text: str, status: int = 200, content_type: str = "text/html") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    resp.headers = {"content-type": content_type}
    return resp


# ---------------------------------------------------------------------------
# _test_param unit tests
# ---------------------------------------------------------------------------

class TestTestParam:
    def setup_method(self):
        self.result = ScanResult(target="https://example.com/")

    def _log(self, msg: str) -> None:
        pass

    def test_no_reflection_returns_early(self):
        injector = MagicMock()
        # probe_reflection returns False → nothing should be appended
        injector.probe_reflection.return_value = (False, _make_response("no marker"))
        surface = {
            "url": "https://example.com/?q=x",
            "method": "GET",
            "params": {"q": ""},
            "single_param": "q",
        }
        opts = ScanOptions()
        _test_param(surface, ["none"], opts, injector, self.result, self._log)
        assert self.result.reflected == []

    def test_json_response_skips_payloads(self):
        injector = MagicMock()
        injector.probe_reflection.return_value = (
            True,
            _make_response('{"q":"MARKER"}', content_type="application/json"),
        )
        surface = {
            "url": "https://example.com/api?q=x",
            "method": "GET",
            "params": {"q": ""},
            "single_param": "q",
        }
        opts = ScanOptions()
        _test_param(surface, ["none"], opts, injector, self.result, self._log)
        assert self.result.reflected == []

    def test_confirmed_xss_appended(self):
        marker_holder: list[str] = []

        def probe_side_effect(url, param, marker, method="GET", base_data=None):
            # Reflect the marker back so context = HTML_BODY
            return True, _make_response(f"<p>{marker}</p>")

        def get_side_effect(url, **kwargs):
            # Return a response containing both a tag literal and the marker
            # We must simulate what inject_get does
            return _make_response(f"<img src=x onerror=alert('vXSS_EXEC_xxxxxx')>")

        injector = MagicMock()
        injector.probe_reflection.side_effect = probe_side_effect
        injector.inject_get.side_effect = lambda url, param, payload: _make_response(
            payload  # echo the payload back verbatim → confirmed
        )

        surface = {
            "url": "https://example.com/?q=x",
            "method": "GET",
            "params": {"q": ""},
            "single_param": "q",
        }
        opts = ScanOptions(level=1)
        _test_param(surface, ["none"], opts, injector, self.result, self._log)
        assert len(self.result.reflected) > 0

    def test_exclude_pattern_skips_url(self):
        injector = MagicMock()
        injector.probe_reflection.return_value = (True, _make_response("<p>MARKER</p>"))

        surface = {
            "url": "https://example.com/logout",
            "method": "GET",
            "params": {"token": ""},
            "single_param": "token",
        }
        opts = ScanOptions(exclude_patterns=[re.compile(r"/logout")])
        _test_param(surface, ["none"], opts, injector, self.result, self._log)
        # Should skip — probe_reflection never called
        injector.probe_reflection.assert_not_called()
        assert self.result.reflected == []


# ---------------------------------------------------------------------------
# scan() integration (full pipeline with mocked Injector)
# ---------------------------------------------------------------------------

class TestScanIntegration:
    @patch("stingxss.engine.scanner.waf_detect")
    @patch("stingxss.engine.scanner.Injector")
    def test_scan_returns_result(self, MockInjector, mock_waf):
        mock_waf.detect.return_value = MagicMock(
            detected=False, evasions=["none"], name=None, confidence=None
        )
        injector_inst = MagicMock()
        injector_inst.request_count = 2
        injector_inst.get_params.return_value = ["q"]
        injector_inst.probe_reflection.return_value = (False, _make_response("no"))
        injector_inst.get.return_value = _make_response("<html><body>hi</body></html>")
        MockInjector.return_value = injector_inst

        result = scan("https://example.com/?q=test", ScanOptions())
        assert result.target == "https://example.com/?q=test"
        assert result.duration_s >= 0

    @patch("stingxss.engine.scanner.waf_detect")
    @patch("stingxss.engine.scanner.Injector")
    def test_scan_waf_detected_stored(self, MockInjector, mock_waf):
        mock_waf.detect.return_value = MagicMock(
            detected=True, evasions=["case_mixing"], confidence="high"
        )
        mock_waf.detect.return_value.name = "Cloudflare"
        injector_inst = MagicMock()
        injector_inst.request_count = 0
        injector_inst.get_params.return_value = []
        injector_inst.get.return_value = _make_response("<html></html>")
        MockInjector.return_value = injector_inst

        result = scan("https://cf-protected.example.com/", ScanOptions())
        assert result.waf_detected == "Cloudflare"

    @patch("stingxss.engine.scanner.waf_detect")
    @patch("stingxss.engine.scanner.Injector")
    def test_scan_post_data_surface(self, MockInjector, mock_waf):
        mock_waf.detect.return_value = MagicMock(
            detected=False, evasions=["none"], name=None, confidence=None
        )
        injector_inst = MagicMock()
        injector_inst.request_count = 0
        injector_inst.get_params.return_value = []
        injector_inst.probe_reflection.return_value = (False, _make_response("no"))
        injector_inst.get.return_value = _make_response("<html></html>")
        MockInjector.return_value = injector_inst

        opts = ScanOptions(data="user=alice&pass=secret")
        result = scan("https://example.com/login", opts)
        # Two POST params → probe_reflection called twice
        assert injector_inst.probe_reflection.call_count == 2
