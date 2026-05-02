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
        _test_param(surface, ["none"], opts, injector, self.result)
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
        _test_param(surface, ["none"], opts, injector, self.result)
        assert self.result.reflected == []

    def test_confirmed_xss_appended(self):
        marker_holder: list[str] = []

        def probe_side_effect(url, param, marker, method="GET", base_data=None):
            # Reflect the marker back so context = HTML_BODY
            return True, _make_response(f"<p>{marker}</p>")

        def get_side_effect(url, **kwargs):
            # Return a response containing both a tag literal and the marker
            # We must simulate what inject_get does
            return _make_response(f"<img src=x onerror=alert('StingXSS_xxxxxx')>")

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
        _test_param(surface, ["none"], opts, injector, self.result)
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
        _test_param(surface, ["none"], opts, injector, self.result)
        # Should skip — probe_reflection never called
        injector.probe_reflection.assert_not_called()
        assert self.result.reflected == []


# ---------------------------------------------------------------------------
# scan() integration (full pipeline with mocked Injector)
# ---------------------------------------------------------------------------

class TestScanIntegration:
    @patch("stingxss.engine._scanner.pipeline.waf_detect")
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

    @patch("stingxss.engine._scanner.pipeline.waf_detect")
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

    @patch("stingxss.engine._scanner.pipeline.waf_detect")
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


# ---------------------------------------------------------------------------
# Angular SSTI extra-context injection tests
# ---------------------------------------------------------------------------

class TestAngularSSTI:
    """
    Verify that _test_param fires extra Angular SSTI payloads when the probed
    page is detected as an Angular app (contains ng-app).
    """

    def setup_method(self):
        self.result = ScanResult(target="https://example.com/")
        self.logs: list[str] = []

    def _log(self, msg: str) -> None:
        self.logs.append(msg)

    def _make_injector(self, probe_html: str, inject_echo: bool = False) -> MagicMock:
        injector = MagicMock()
        injector.probe_reflection.return_value = (True, _make_response(probe_html))
        if inject_echo:
            # Echo payload back verbatim → marker present → confirmed
            injector.inject_get.side_effect = lambda url, param, payload: _make_response(payload)
        else:
            injector.inject_get.return_value = _make_response("no marker")
        return injector

    def test_angular_page_triggers_extra_contexts(self):
        """Extra Angular contexts are tried when ng-app is present in the probe response."""
        # Probe response: marker in HTML body on an ng-app page
        probe_html = '<html ng-app><body>MARKER</body></html>'
        injector = self._make_injector(probe_html)

        surface = {
            "url": "https://example.com/?q=x",
            "method": "GET",
            "params": {"q": ""},
            "single_param": "q",
        }
        opts = ScanOptions(level=1)
        _test_param(surface, ["none"], opts, injector, self.result)

        # inject_get should have been called at least once for the extra Angular payloads
        # (even if they are not confirmed, the attempt must be made)
        assert injector.inject_get.call_count > 0

        # Verify at least one Angular SSTI payload was attempted
        all_payloads = [call.args[2] for call in injector.inject_get.call_args_list]
        # After format(), {{ → { and }} → }, so check for "constructor" as a marker
        # of Angular expression payloads.
        angular_payloads = [p for p in all_payloads if "constructor" in p or "$eval" in p]
        assert len(angular_payloads) > 0, "No Angular SSTI payloads were injected"

    def test_angular_ssti_confirmed_when_marker_echoed(self):
        """Confirmed Angular SSTI finding stored when marker is echoed in response."""
        probe_html = '<html ng-app><body>MARKER</body></html>'
        injector = self._make_injector(probe_html, inject_echo=True)

        surface = {
            "url": "https://example.com/?q=x",
            "method": "GET",
            "params": {"q": ""},
            "single_param": "q",
        }
        opts = ScanOptions(level=1)
        _test_param(surface, ["none"], opts, injector, self.result)

        from stingxss.engine.reporter import ReflectionContext
        confirmed = [
            f for f in self.result.reflected
            if f.confirmed and f.context in (
                ReflectionContext.ANGULAR_TEMPLATE,
                ReflectionContext.ANGULAR_TEMPLATE_ALT,
            )
        ]
        assert len(confirmed) > 0, "Expected at least one confirmed Angular SSTI finding"

    def test_non_angular_page_no_extra_payloads(self):
        """Extra Angular contexts must NOT be tried on a non-Angular page."""
        # Probe response: plain HTML — no ng-app
        probe_html = '<html><body>MARKER</body></html>'
        injector = self._make_injector(probe_html)

        surface = {
            "url": "https://example.com/?q=x",
            "method": "GET",
            "params": {"q": ""},
            "single_param": "q",
        }
        opts = ScanOptions(level=1)
        _test_param(surface, ["none"], opts, injector, self.result)

        all_payloads = [call.args[2] for call in injector.inject_get.call_args_list]
        # Angular SSTI payloads don't contain HTML tags, so check for "constructor"
        angular_payloads = [p for p in all_payloads if "constructor" in p or "$eval" in p]
        assert angular_payloads == [], "Angular payloads must not be sent to non-Angular pages"
