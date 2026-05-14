# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Smoke tests for engine/waf_detect.py — confirms the stingxss adapter
correctly wraps commonhuman_payloads.waf.detect() via injector.get.
"""

from unittest.mock import MagicMock

from stingxss.engine.http.waf_detect import WafResult, EVASION_NONE, detect


def _make_injector(status: int, headers: dict | None = None, body: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.headers = headers or {}
    resp.text = body
    injector = MagicMock()
    injector.get.return_value = resp
    return injector


class TestWafDetectAdapter:
    """Stingxss wraps detect() with injector.get, XSS probe, check_reflection=True."""

    URL = "https://example.com/search?q=test"

    def test_xss_probe_reflected_returns_no_waf(self):
        """check_reflection=True: probe reflected in body → no WAF immediately."""
        injector = _make_injector(200, body="<script>alert(1)</script> found in page")
        result = detect(injector, self.URL)
        assert isinstance(result, WafResult)
        assert result.detected is False
        assert result.evasions == [EVASION_NONE]

    def test_cloudflare_detected_through_adapter(self):
        injector = _make_injector(
            403,
            headers={"cf-ray": "abc123", "server": "cloudflare"},
            body="Attention Required | Cloudflare",
        )
        result = detect(injector, self.URL)
        assert result.detected is True
        assert result.name == "Cloudflare"

    def test_exception_returns_no_waf(self):
        injector = MagicMock()
        injector.get.side_effect = Exception("connection refused")
        result = detect(injector, self.URL)
        assert result.detected is False
