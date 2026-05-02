# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Tests for engine/clickjacking.py — framing-protection header analyser.

Covers the two Google Firing Range /clickjacking/ cases:
  1. X-Frame-Options: ALLOWALL
  2. CSP present but without frame-ancestors
Plus related edge cases.
"""

import pytest

from stingxss.engine.checks.clickjacking import check, _get_header, _csp_has_frame_ancestors
from stingxss.engine.reporter import ClickjackingFinding

URL = "https://example.com/page"


# ---------------------------------------------------------------------------
# Unit tests for helper functions
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_get_header_case_insensitive(self):
        hdrs = {"X-Frame-Options": "DENY", "Content-Type": "text/html"}
        assert _get_header(hdrs, "x-frame-options") == "DENY"
        assert _get_header(hdrs, "X-FRAME-OPTIONS") == "DENY"

    def test_get_header_missing_returns_none(self):
        assert _get_header({}, "x-frame-options") is None

    def test_csp_has_frame_ancestors_true(self):
        csp = "default-src 'self'; frame-ancestors 'none'"
        assert _csp_has_frame_ancestors(csp) is True

    def test_csp_has_frame_ancestors_false(self):
        csp = "default-src 'self'; script-src 'nonce-abc'"
        assert _csp_has_frame_ancestors(csp) is False

    def test_csp_has_frame_ancestors_none(self):
        assert _csp_has_frame_ancestors(None) is False

    def test_csp_has_frame_ancestors_empty(self):
        assert _csp_has_frame_ancestors("") is False


# ---------------------------------------------------------------------------
# Firing Range case 1: X-Frame-Options ALLOWALL
# ---------------------------------------------------------------------------

class TestXFOAllowAll:
    """
    /clickjacking/clickjacking_xfo_allowall
    X-Frame-Options: ALLOWALL — non-standard, browsers ignore it.
    """

    def test_xfo_allowall_is_flagged(self):
        hdrs = {"X-Frame-Options": "ALLOWALL"}
        finding = check(URL, hdrs)
        assert isinstance(finding, ClickjackingFinding)

    def test_xfo_allowall_reason_mentions_allowall(self):
        hdrs = {"X-Frame-Options": "ALLOWALL"}
        finding = check(URL, hdrs)
        assert "ALLOWALL" in finding.reason

    def test_xfo_allowall_header_captured(self):
        hdrs = {"X-Frame-Options": "ALLOWALL"}
        finding = check(URL, hdrs)
        assert finding.xfo_header == "ALLOWALL"

    def test_xfo_allowall_url_captured(self):
        hdrs = {"X-Frame-Options": "ALLOWALL"}
        finding = check(URL, hdrs)
        assert finding.url == URL

    def test_xfo_allowall_case_insensitive(self):
        # The header value should be matched case-insensitively
        hdrs = {"x-frame-options": "allowall"}
        finding = check(URL, hdrs)
        assert isinstance(finding, ClickjackingFinding)


# ---------------------------------------------------------------------------
# Firing Range case 2: CSP present but no frame-ancestors
# ---------------------------------------------------------------------------

class TestCSPNoFrameAncestors:
    """
    /clickjacking/clickjacking_csp_no_frame_ancestors
    CSP is present but does not contain frame-ancestors.
    """

    def test_csp_without_frame_ancestors_flagged(self):
        hdrs = {"Content-Security-Policy": "default-src 'self'; script-src 'nonce-abc'"}
        finding = check(URL, hdrs)
        assert isinstance(finding, ClickjackingFinding)

    def test_csp_without_frame_ancestors_reason(self):
        hdrs = {"Content-Security-Policy": "default-src 'self'"}
        finding = check(URL, hdrs)
        assert "frame-ancestors" in finding.reason

    def test_csp_without_frame_ancestors_header_captured(self):
        csp_val = "default-src 'self'"
        hdrs = {"Content-Security-Policy": csp_val}
        finding = check(URL, hdrs)
        assert finding.csp_header == csp_val

    def test_csp_with_frame_ancestors_not_flagged(self):
        hdrs = {"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"}
        finding = check(URL, hdrs)
        assert finding is None

    def test_csp_frame_ancestors_self_not_flagged(self):
        hdrs = {"Content-Security-Policy": "frame-ancestors 'self'"}
        finding = check(URL, hdrs)
        assert finding is None


# ---------------------------------------------------------------------------
# X-Frame-Options: properly protected values
# ---------------------------------------------------------------------------

class TestXFOProtected:
    def test_xfo_deny_not_flagged(self):
        hdrs = {"X-Frame-Options": "DENY"}
        assert check(URL, hdrs) is None

    def test_xfo_sameorigin_not_flagged(self):
        hdrs = {"X-Frame-Options": "SAMEORIGIN"}
        assert check(URL, hdrs) is None

    def test_xfo_deny_case_insensitive(self):
        hdrs = {"X-Frame-Options": "deny"}
        assert check(URL, hdrs) is None

    def test_xfo_sameorigin_case_insensitive(self):
        hdrs = {"X-Frame-Options": "sameorigin"}
        assert check(URL, hdrs) is None


# ---------------------------------------------------------------------------
# No framing protection at all
# ---------------------------------------------------------------------------

class TestNoProtection:
    def test_no_headers_flagged(self):
        finding = check(URL, {})
        assert isinstance(finding, ClickjackingFinding)

    def test_no_headers_reason_mentions_neither(self):
        finding = check(URL, {})
        assert "X-Frame-Options" in finding.reason or "frame-ancestors" in finding.reason

    def test_no_headers_empty_xfo_and_csp(self):
        finding = check(URL, {"Content-Type": "text/html"})
        assert finding.xfo_header == ""
        assert finding.csp_header == ""


# ---------------------------------------------------------------------------
# XFO ALLOW-FROM (deprecated) without CSP frame-ancestors
# ---------------------------------------------------------------------------

class TestXFOAllowFrom:
    def test_allow_from_without_csp_flagged(self):
        hdrs = {"X-Frame-Options": "ALLOW-FROM https://trusted.example.com"}
        finding = check(URL, hdrs)
        assert isinstance(finding, ClickjackingFinding)

    def test_allow_from_with_csp_frame_ancestors_not_flagged(self):
        hdrs = {
            "X-Frame-Options": "ALLOW-FROM https://trusted.example.com",
            "Content-Security-Policy": "frame-ancestors https://trusted.example.com",
        }
        finding = check(URL, hdrs)
        assert finding is None
