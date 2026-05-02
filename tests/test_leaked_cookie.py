# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Tests for engine/leaked_cookie.py — httpOnly cookie leak detector.

Covers both firing-range cases:
  /leakedcookie/leakedcookie        → value leaked in HTML body
  /leakedcookie/leakedinresource    → value leaked in a referenced JS file
"""

import pytest
from stingxss.engine.checks.leaked_cookie import (
    check,
    _parse_httponly_cookies,
    _extract_resource_urls,
    LeakedCookieFinding,
)


# ---------------------------------------------------------------------------
# Helpers / stubs
# ---------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code


class _FakeInjector:
    """Stub injector that returns pre-canned responses per URL."""
    def __init__(self, url_map: dict):
        self._map = url_map

    def get(self, url: str, **kwargs) -> _FakeResponse:
        text = self._map.get(url, "")
        return _FakeResponse(text)


# ---------------------------------------------------------------------------
# _parse_httponly_cookies
# ---------------------------------------------------------------------------

class TestParseHttponlyCookies:
    def test_single_httponly_cookie(self):
        headers = {"Set-Cookie": "session=abc123; Path=/; HttpOnly"}
        result = _parse_httponly_cookies(headers)
        assert result == {"session": "abc123"}

    def test_non_httponly_cookie_ignored(self):
        headers = {"Set-Cookie": "tracker=xyz; Path=/"}
        result = _parse_httponly_cookies(headers)
        assert result == {}

    def test_multiple_set_cookie_headers_as_list(self):
        headers = {"set-cookie": [
            "session=abc123; HttpOnly",
            "analytics=track99",         # no HttpOnly
            "csrf=tok456; HttpOnly; Secure",
        ]}
        result = _parse_httponly_cookies(headers)
        assert "session" in result
        assert result["session"] == "abc123"
        assert "analytics" not in result
        assert "csrf" in result
        assert result["csrf"] == "tok456"

    def test_httponly_case_insensitive(self):
        headers = {"Set-Cookie": "auth=secret99; httponly; Secure"}
        result = _parse_httponly_cookies(headers)
        assert result == {"auth": "secret99"}

    def test_empty_value_skipped(self):
        headers = {"Set-Cookie": "empty=; HttpOnly"}
        result = _parse_httponly_cookies(headers)
        assert result == {}

    def test_no_set_cookie_header(self):
        headers = {"Content-Type": "text/html"}
        result = _parse_httponly_cookies(headers)
        assert result == {}

    def test_header_key_case_insensitive(self):
        headers = {"SET-COOKIE": "token=val12345; HttpOnly"}
        result = _parse_httponly_cookies(headers)
        assert result == {"token": "val12345"}


# ---------------------------------------------------------------------------
# _extract_resource_urls
# ---------------------------------------------------------------------------

class TestExtractResourceUrls:
    def test_extracts_script_src(self):
        body = '<script src="/js/app.js"></script>'
        urls = _extract_resource_urls(body, "https://example.com/page")
        assert "https://example.com/js/app.js" in urls

    def test_relative_url_resolved(self):
        body = '<script src="leakedcookie.js"></script>'
        urls = _extract_resource_urls(body, "https://example.com/leakedcookie/leakedinresource")
        assert "https://example.com/leakedcookie/leakedcookie.js" in urls

    def test_absolute_url_kept(self):
        body = '<script src="https://cdn.example.com/lib.js"></script>'
        urls = _extract_resource_urls(body, "https://example.com/page")
        assert "https://cdn.example.com/lib.js" in urls

    def test_data_uri_skipped(self):
        body = '<script src="data:text/javascript,alert(1)"></script>'
        urls = _extract_resource_urls(body, "https://example.com/page")
        assert urls == []

    def test_no_scripts(self):
        body = "<html><body><p>hello</p></body></html>"
        urls = _extract_resource_urls(body, "https://example.com/page")
        assert urls == []


# ---------------------------------------------------------------------------
# check() — case 1: leaked in body
# ---------------------------------------------------------------------------

class TestLeakedCookieInBody:
    def test_httponly_value_in_body_detected(self):
        """Mirrors /leakedcookie/leakedcookie — value echoed in HTML body."""
        cookie_value = "JSpf5typfOY"
        headers = {"Set-Cookie": f"secret={cookie_value}; HttpOnly; Path=/"}
        body = f"<html><body>Cookie value: {cookie_value}</body></html>"
        findings = check("https://example.com/page", headers, body)
        assert len(findings) == 1
        f = findings[0]
        assert f.leak_type == "leaked_in_body"
        assert f.cookie_name == "secret"
        assert cookie_value[:30] == f.cookie_value
        assert cookie_value in f.evidence
        assert "HttpOnly" in f.reason or "httpOnly" in f.reason.lower() or "httponly" in f.reason.lower()

    def test_non_httponly_cookie_not_reported(self):
        """Non-HttpOnly cookie value in body is not a security issue."""
        headers = {"Set-Cookie": "session=abc12345; Path=/"}
        body = "<html><body>abc12345</body></html>"
        findings = check("https://example.com/page", headers, body)
        assert findings == []

    def test_short_cookie_value_skipped(self):
        """Values shorter than 4 chars are skipped (too many false positives)."""
        headers = {"Set-Cookie": "flag=yes; HttpOnly"}
        body = "<html><body>yes</body></html>"
        findings = check("https://example.com/page", headers, body)
        assert findings == []

    def test_cookie_not_in_body(self):
        headers = {"Set-Cookie": "token=supersecret999; HttpOnly"}
        body = "<html><body><p>nothing here</p></body></html>"
        findings = check("https://example.com/page", headers, body)
        assert findings == []

    def test_multiple_httponly_cookies_only_leaked_reported(self):
        headers = {"set-cookie": [
            "leaked=LeakedValue123; HttpOnly",
            "safe=SafeValue456; HttpOnly",
        ]}
        body = "<html><body>LeakedValue123</body></html>"
        findings = check("https://example.com/page", headers, body)
        assert len(findings) == 1
        assert findings[0].cookie_name == "leaked"

    def test_no_injector_skips_resource_check(self):
        """Without an injector, only body check runs — no error raised."""
        headers = {"Set-Cookie": "tok=ResourceSecret12; HttpOnly"}
        body = '<script src="/secret.js"></script>'
        # No injector — resource check is skipped
        findings = check("https://example.com/page", headers, body, injector=None)
        assert findings == []


# ---------------------------------------------------------------------------
# check() — case 2: leaked in resource
# ---------------------------------------------------------------------------

class TestLeakedCookieInResource:
    def test_httponly_value_in_js_resource_detected(self):
        """Mirrors /leakedcookie/leakedinresource — value in a JS file."""
        cookie_value = "JSpf5typfOY"
        page_url = "https://example.com/leakedcookie/leakedinresource"
        headers = {"Set-Cookie": f"secret={cookie_value}; HttpOnly; Path=/"}
        body = '<script src="leakedcookie.js"></script><p>Nothing here</p>'
        resource_url = "https://example.com/leakedcookie/leakedcookie.js"
        resource_body = f"var cookie = '{cookie_value}';"

        injector = _FakeInjector({resource_url: resource_body})
        findings = check(page_url, headers, body, injector=injector)

        assert len(findings) == 1
        f = findings[0]
        assert f.leak_type == "leaked_in_resource"
        assert f.resource_url == resource_url
        assert f.cookie_name == "secret"
        assert cookie_value in f.evidence

    def test_resource_not_containing_cookie_clean(self):
        cookie_value = "SomeTokenABCD"
        page_url = "https://example.com/page"
        headers = {"Set-Cookie": f"tok={cookie_value}; HttpOnly"}
        body = '<script src="/app.js"></script>'
        resource_body = "var x = 'nothing important';"

        injector = _FakeInjector({"https://example.com/app.js": resource_body})
        findings = check(page_url, headers, body, injector=injector)
        assert findings == []

    def test_resource_fetch_failure_does_not_crash(self):
        class _ErrorInjector:
            def get(self, url, **kwargs):
                raise ConnectionError("timeout")

        cookie_value = "SomeTokenABCD"
        headers = {"Set-Cookie": f"tok={cookie_value}; HttpOnly"}
        body = '<script src="/app.js"></script>'
        findings = check("https://example.com/page", headers, body, injector=_ErrorInjector())
        assert findings == []

    def test_both_body_and_resource_leaked(self):
        """Value in both body AND resource — two separate findings."""
        cookie_value = "BothLeakedXYZ"
        page_url = "https://example.com/page"
        headers = {"Set-Cookie": f"tok={cookie_value}; HttpOnly"}
        body = f'<p>{cookie_value}</p><script src="/res.js"></script>'
        resource_body = f"console.log('{cookie_value}');"

        injector = _FakeInjector({"https://example.com/res.js": resource_body})
        findings = check(page_url, headers, body, injector=injector)

        leak_types = {f.leak_type for f in findings}
        assert "leaked_in_body" in leak_types
        assert "leaked_in_resource" in leak_types


# ---------------------------------------------------------------------------
# LeakedCookieFinding serialisation sanity
# ---------------------------------------------------------------------------

class TestLeakedCookieFindingFields:
    def test_all_fields_present(self):
        f = LeakedCookieFinding(
            url="https://example.com/page",
            cookie_name="session",
            cookie_value="abc123",
            leak_type="leaked_in_body",
            resource_url="",
            evidence="...abc123...",
            reason="HttpOnly cookie 'session' value echoed in body.",
        )
        assert f.url == "https://example.com/page"
        assert f.cookie_name == "session"
        assert f.leak_type == "leaked_in_body"
        assert f.resource_url == ""
