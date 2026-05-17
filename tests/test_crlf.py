# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for engine/checks/crlf.py — CRLF / HTTP Response Splitting detector."""

import pytest
from unittest.mock import MagicMock

from stingxss.engine.checks.crlf import (
    check_params,
    check_headers,
    _header_injected,
    _INJECTED_HEADER,
    _INJECTED_VALUE,
)
from stingxss.engine.reporter import CRLFFinding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_resp(status=200, headers=None, text=""):
    resp = MagicMock()
    resp.status_code = status
    resp.headers = headers or {}
    resp.text = text
    return resp


def _make_injector(get_resp=None, header_resp=None):
    inj = MagicMock()
    inj.inject_get.return_value = get_resp or _make_resp()
    # Both check_params and check_headers call injector.get(); wire whichever was given
    inj.get.return_value = header_resp or get_resp or _make_resp()
    return inj


# ---------------------------------------------------------------------------
# _header_injected
# ---------------------------------------------------------------------------

class TestHeaderInjected:
    def test_detects_injected_header_exact_case(self):
        resp = _make_resp(headers={_INJECTED_HEADER: _INJECTED_VALUE})
        assert _header_injected(resp) is True

    def test_detects_injected_header_different_case(self):
        resp = _make_resp(headers={_INJECTED_HEADER.lower(): _INJECTED_VALUE})
        assert _header_injected(resp) is True

    def test_no_injected_header(self):
        resp = _make_resp(headers={"Content-Type": "text/html"})
        assert _header_injected(resp) is False

    def test_empty_headers(self):
        resp = _make_resp(headers={})
        assert _header_injected(resp) is False


# ---------------------------------------------------------------------------
# check_params
# ---------------------------------------------------------------------------

class TestCheckParams:
    def test_no_finding_when_header_not_injected(self):
        inj = _make_injector(get_resp=_make_resp(headers={"Content-Type": "text/html"}))
        findings = check_params("http://example.com/?q=test", "q", "GET", inj)
        assert findings == []

    def test_finding_when_crlf_header_reflected(self):
        # Simulate the server reflecting the injected header in the response
        vuln_resp = _make_resp(headers={_INJECTED_HEADER: _INJECTED_VALUE})
        inj = _make_injector(get_resp=vuln_resp)
        findings = check_params("http://example.com/?q=test", "q", "GET", inj)
        assert len(findings) == 1
        f = findings[0]
        assert isinstance(f, CRLFFinding)
        assert f.url == "http://example.com/?q=test"
        assert f.parameter == "q"
        assert f.method == "GET"
        assert f.vector == "param"
        assert _INJECTED_HEADER in f.injected_header

    def test_only_one_finding_per_param(self):
        # All sequences hit — should still be deduplicated to one finding
        vuln_resp = _make_resp(headers={_INJECTED_HEADER: _INJECTED_VALUE})
        inj = _make_injector(get_resp=vuln_resp)
        findings = check_params("http://example.com/?q=test", "q", "GET", inj)
        assert len(findings) == 1

    def test_exception_in_inject_skips_gracefully(self):
        inj = MagicMock()
        inj.inject_get.side_effect = Exception("network error")
        findings = check_params("http://example.com/?q=test", "q", "GET", inj)
        assert findings == []

    def test_finding_reason_mentions_param(self):
        vuln_resp = _make_resp(headers={_INJECTED_HEADER: _INJECTED_VALUE})
        inj = _make_injector(get_resp=vuln_resp)
        findings = check_params("http://example.com/?q=test", "q", "GET", inj)
        assert "q" in findings[0].reason


# ---------------------------------------------------------------------------
# check_headers
# ---------------------------------------------------------------------------

class TestCheckHeaders:
    def test_no_finding_when_headers_clean(self):
        inj = _make_injector(header_resp=_make_resp(headers={"Content-Type": "text/html"}))
        findings = check_headers("http://example.com/", inj)
        assert findings == []

    def test_finding_when_header_crlf_reflected(self):
        vuln_resp = _make_resp(headers={_INJECTED_HEADER: _INJECTED_VALUE})
        inj = _make_injector(header_resp=vuln_resp)
        findings = check_headers("http://example.com/", inj)
        assert len(findings) >= 1
        f = findings[0]
        assert isinstance(f, CRLFFinding)
        assert f.vector == "header"
        assert f.method == "GET"

    def test_exception_in_get_skips_gracefully(self):
        inj = MagicMock()
        inj.get.side_effect = Exception("timeout")
        findings = check_headers("http://example.com/", inj)
        assert findings == []

    def test_finding_reason_mentions_header_name(self):
        vuln_resp = _make_resp(headers={_INJECTED_HEADER: _INJECTED_VALUE})
        inj = _make_injector(header_resp=vuln_resp)
        findings = check_headers("http://example.com/", inj)
        # At least one finding should mention a test header name
        assert any(f.parameter in f.reason for f in findings)
