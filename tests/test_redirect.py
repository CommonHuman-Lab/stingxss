# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Tests for engine/redirect.py — open redirect and javascript-redirect detector.

Covers all three Firing Range /redirect/ cases:
  /redirect/parameter              → 302 Location: <url>, unfiltered
  /redirect/parameter/NOSTARTSWITHJS → 302 Location: <url>, blocks javascript:
  /redirect/meta                   → <meta http-equiv=refresh content="0;<url>">
"""

import pytest
from unittest.mock import MagicMock, patch

from stingxss.engine.checks.redirect import (
    check_url,
    _is_js_location,
    _extract_meta_refresh_url,
    OpenRedirectFinding,
    _CANARY_MARKER,
    _OPEN_REDIR_URL,
)


# ---------------------------------------------------------------------------
# Helper — fake session/injector
# ---------------------------------------------------------------------------

class _FakeResp:
    """Minimal response stub."""
    def __init__(self, status_code=302, location="", body=""):
        self.status_code = status_code
        self.headers = {}
        if location:
            self.headers["Location"] = location
        self.text = body


class _FakeSession:
    def __init__(self, responses: dict):
        """Map: payload_substring → _FakeResp"""
        self._responses = responses
        self._default = _FakeResp(200)

    def get(self, url, timeout=None, allow_redirects=False):
        for key, resp in self._responses.items():
            if key in url:
                return resp
        return self._default


class _FakeInjector:
    def __init__(self, session):
        self._session = session
        self.timeout = 10

    def get(self, url, **kwargs):
        return self._session.get(url, timeout=self.timeout, **kwargs)


# ---------------------------------------------------------------------------
# _is_js_location
# ---------------------------------------------------------------------------

class TestIsJsLocation:
    def test_plain_javascript_uri(self):
        assert _is_js_location("javascript:alert(1)")

    def test_uppercase_javascript(self):
        assert _is_js_location("JAVASCRIPT:alert(1)")

    def test_mixed_case(self):
        assert _is_js_location("Javascript:alert(1)")

    def test_leading_whitespace(self):
        assert _is_js_location("  javascript:alert(1)")

    def test_leading_null_byte(self):
        assert _is_js_location("\x00javascript:alert(1)")

    def test_https_not_js(self):
        assert not _is_js_location("https://evil.com")

    def test_protocol_relative_not_js(self):
        assert not _is_js_location("//evil.com")

    def test_empty_string(self):
        assert not _is_js_location("")

    def test_relative_path(self):
        assert not _is_js_location("/some/path")


# ---------------------------------------------------------------------------
# _extract_meta_refresh_url
# ---------------------------------------------------------------------------

class TestExtractMetaRefreshUrl:
    def test_basic_meta_refresh(self):
        html = '<meta http-equiv="refresh" content="0;javascript:alert(1)">'
        assert _extract_meta_refresh_url(html) == "javascript:alert(1)"

    def test_meta_refresh_with_url_keyword(self):
        html = '<meta http-equiv="refresh" content="0;url=https://evil.com">'
        result = _extract_meta_refresh_url(html)
        assert result is not None
        assert "evil.com" in result

    def test_meta_refresh_delay_5(self):
        html = '<meta http-equiv=refresh content="5;javascript:alert(1)">'
        assert _extract_meta_refresh_url(html) == "javascript:alert(1)"

    def test_no_meta_refresh(self):
        html = "<html><body><p>nothing</p></body></html>"
        assert _extract_meta_refresh_url(html) is None

    def test_canary_in_meta(self):
        html = f'<meta http-equiv="refresh" content="0;//{_CANARY_MARKER}.example.com">'
        result = _extract_meta_refresh_url(html)
        assert result is not None
        assert _CANARY_MARKER in result


# ---------------------------------------------------------------------------
# check_url — case 1: javascript redirect (unfiltered)
# Mirrors /redirect/parameter
# ---------------------------------------------------------------------------

class TestJavascriptRedirectUnfiltered:
    def _make_injector(self, payload_kw, location):
        session = _FakeSession({payload_kw: _FakeResp(302, location=location)})
        return _FakeInjector(session)

    def test_plain_javascript_redirect_detected(self):
        injector = self._make_injector("javascript%3Aalert", "javascript:alert(1)")
        findings = check_url(
            "https://example.com/redirect?url=/",
            param="url",
            method="GET",
            injector=injector,
        )
        js_findings = [f for f in findings if f.issue == "javascript_redirect"]
        assert len(js_findings) >= 1
        assert js_findings[0].parameter == "url"
        assert "javascript:" in js_findings[0].location.lower()

    def test_open_redirect_detected(self):
        """Canary URL reflected verbatim in Location header."""
        session = _FakeSession({
            _CANARY_MARKER: _FakeResp(302, location=_OPEN_REDIR_URL),
        })
        injector = _FakeInjector(session)
        findings = check_url(
            "https://example.com/redirect?url=/",
            param="url",
            method="GET",
            injector=injector,
        )
        open_findings = [f for f in findings if f.issue == "open_redirect"]
        assert len(open_findings) == 1
        assert _CANARY_MARKER in open_findings[0].location

    def test_no_redirect_no_finding(self):
        """200 response with no Location — not a redirect."""
        session = _FakeSession({})
        injector = _FakeInjector(session)
        findings = check_url(
            "https://example.com/page?q=x",
            param="q",
            method="GET",
            injector=injector,
        )
        assert findings == []


# ---------------------------------------------------------------------------
# check_url — case 2: javascript: blocked (NOSTARTSWITHJS)
# Open redirect still possible via //evil.com
# ---------------------------------------------------------------------------

class TestFilteredJavascriptRedirect:
    def test_protocol_relative_open_redirect(self):
        """//evil.com canary reflected — open redirect regardless of JS filter."""
        session = _FakeSession({
            _CANARY_MARKER: _FakeResp(302, location=_OPEN_REDIR_URL),
            "javascript%3A": _FakeResp(400),  # server blocks javascript:
        })
        injector = _FakeInjector(session)
        findings = check_url(
            "https://example.com/redirect/NOSTARTSWITHJS?url=/",
            param="url",
            method="GET",
            injector=injector,
        )
        open_findings = [f for f in findings if f.issue == "open_redirect"]
        assert len(open_findings) == 1

    def test_capital_j_bypass(self):
        """Javascript: (capital J) bypasses naive starts-with check."""
        session = _FakeSession({
            "Javascript%3A": _FakeResp(302, location="Javascript:alert(1)"),
            _CANARY_MARKER:  _FakeResp(200),
        })
        injector = _FakeInjector(session)
        findings = check_url(
            "https://example.com/redirect/NOSTARTSWITHJS?url=/",
            param="url",
            method="GET",
            injector=injector,
        )
        js_findings = [f for f in findings if f.issue == "javascript_redirect"]
        assert len(js_findings) >= 1


# ---------------------------------------------------------------------------
# check_url — case 3: meta-refresh redirect
# Mirrors /redirect/meta
# ---------------------------------------------------------------------------

class TestMetaRefreshRedirect:
    def test_javascript_in_meta_refresh_detected(self):
        body = '<meta http-equiv="refresh" content="0;javascript:alert(1)">'
        session = _FakeSession({
            "javascript%3Aalert": _FakeResp(200, body=body),
        })
        injector = _FakeInjector(session)
        findings = check_url(
            "https://example.com/redirect/meta?q=/",
            param="q",
            method="GET",
            injector=injector,
        )
        meta_findings = [f for f in findings if f.issue == "meta_redirect"]
        assert len(meta_findings) >= 1
        assert "javascript:" in meta_findings[0].location.lower()

    def test_open_redirect_in_meta_refresh(self):
        body = f'<meta http-equiv="refresh" content="0;//{_CANARY_MARKER}.example.com">'
        session = _FakeSession({
            _CANARY_MARKER: _FakeResp(200, body=body),
        })
        injector = _FakeInjector(session)
        findings = check_url(
            "https://example.com/redirect/meta?q=/",
            param="q",
            method="GET",
            injector=injector,
        )
        meta_open = [f for f in findings if f.issue == "meta_redirect_open"]
        assert len(meta_open) >= 1
        assert _CANARY_MARKER in meta_open[0].location

    def test_clean_meta_refresh_no_finding(self):
        body = '<meta http-equiv="refresh" content="0;/">'
        session = _FakeSession({"": _FakeResp(200, body=body)})
        injector = _FakeInjector(session)
        findings = check_url(
            "https://example.com/page?q=/",
            param="q",
            method="GET",
            injector=injector,
        )
        assert findings == []


# ---------------------------------------------------------------------------
# OpenRedirectFinding fields
# ---------------------------------------------------------------------------

class TestOpenRedirectFindingFields:
    def test_all_fields(self):
        f = OpenRedirectFinding(
            url="https://example.com/redirect?url=/",
            parameter="url",
            method="GET",
            issue="javascript_redirect",
            payload="javascript:alert(1)",
            location="javascript:alert(1)",
            reason="Unfiltered redirect to javascript: URI.",
        )
        assert f.issue == "javascript_redirect"
        assert f.method == "GET"
        assert f.location == "javascript:alert(1)"


# ---------------------------------------------------------------------------
# Exception safety
# ---------------------------------------------------------------------------

class TestRedirectExceptionSafety:
    def test_network_error_does_not_crash(self):
        class _ErrorSession:
            def get(self, url, **kwargs):
                raise ConnectionError("timeout")

        injector = _FakeInjector(_ErrorSession())
        # Should return empty list, not raise
        findings = check_url(
            "https://example.com/redir?url=/",
            param="url",
            method="GET",
            injector=injector,
        )
        assert findings == []
