# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Tests for engine/injector.py — HTTP engine, parameter injection, cookie parsing.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from stingxss.engine.http.injector import Injector, _parse_cookie_string, parse_post_data


# ---------------------------------------------------------------------------
# _parse_cookie_string
# ---------------------------------------------------------------------------

class TestParseCookieString:
    def test_standard_semicolon_format(self):
        result = _parse_cookie_string("session=abc; user=bob")
        assert result == {"session": "abc", "user": "bob"}

    def test_json_format(self):
        result = _parse_cookie_string('{"session": "xyz", "role": "admin"}')
        assert result == {"session": "xyz", "role": "admin"}

    def test_empty_string(self):
        assert _parse_cookie_string("") == {}

    def test_no_equals_part_skipped(self):
        result = _parse_cookie_string("validcookie=1; noequals; another=2")
        assert "validcookie" in result
        assert "another" in result
        assert "noequals" not in result

    def test_value_with_equals(self):
        # value may contain = (e.g. base64)
        result = _parse_cookie_string("token=abc=def")
        assert result["token"] == "abc=def"


# ---------------------------------------------------------------------------
# parse_post_data
# ---------------------------------------------------------------------------

class TestParsePostData:
    def test_urlencoded(self):
        result = parse_post_data("user=alice&pass=secret")
        assert result == {"user": "alice", "pass": "secret"}

    def test_json(self):
        result = parse_post_data('{"key": "value", "num": 42}')
        assert result["key"] == "value"
        assert result["num"] == "42"

    def test_empty_string(self):
        assert parse_post_data("") == {}

    def test_malformed_returns_something(self):
        # Should not crash
        result = parse_post_data("not&valid&at===all")
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Injector — parameter utilities
# ---------------------------------------------------------------------------

class TestInjectorParams:
    def test_get_params_parses_query(self):
        params = Injector.get_params("https://example.com/search?q=test&page=2")
        assert "q" in params
        assert "page" in params

    def test_get_params_empty_url(self):
        assert Injector.get_params("https://example.com/no-query") == []

    def test_same_origin_true(self):
        assert Injector.same_origin(
            "https://example.com/a", "https://example.com/b"
        )

    def test_same_origin_false_different_host(self):
        assert not Injector.same_origin(
            "https://example.com/a", "https://evil.com/b"
        )

    def test_same_origin_false_different_scheme(self):
        assert not Injector.same_origin(
            "http://example.com/a", "https://example.com/a"
        )

    def test_get_base_url(self):
        assert Injector.get_base_url("https://example.com/path?q=1") == "https://example.com"


# ---------------------------------------------------------------------------
# Injector — inject helpers (mocked session)
# ---------------------------------------------------------------------------

class TestInjectorInject:
    def setup_method(self):
        self.injector = Injector(timeout=5)

    def teardown_method(self):
        self.injector.close()

    def _mock_get(self, text="<html>ok</html>", status=200):
        resp = MagicMock()
        resp.status_code = status
        resp.text = text
        resp.headers = {}
        return resp

    def test_inject_get_replaces_param(self):
        with patch.object(self.injector._session, "get") as mock_get:
            mock_get.return_value = self._mock_get()
            self.injector.inject_get("https://example.com/?q=old", "q", "<script>")
            called_url = mock_get.call_args[0][0]
            assert "%3Cscript%3E" in called_url or "<script>" in called_url

    def test_inject_post_sends_payload(self):
        with patch.object(self.injector._session, "post") as mock_post:
            mock_post.return_value = self._mock_get()
            self.injector.inject_post("https://example.com/", "field", "PAYLOAD")
            data_arg = mock_post.call_args[1].get("data") or mock_post.call_args[0][1]
            assert data_arg.get("field") == "PAYLOAD"

    def test_request_count_incremented(self):
        with patch.object(self.injector._session, "get") as mock_get:
            mock_get.return_value = self._mock_get()
            self.injector.get("https://example.com/")
            self.injector.get("https://example.com/")
            assert self.injector.request_count == 2

    def test_probe_reflection_detected(self):
        marker = "vXSS_PROBE"
        resp_text = f"<html><body>Search: {marker}</body></html>"
        with patch.object(self.injector._session, "get") as mock_get:
            mock_get.return_value = self._mock_get(text=resp_text)
            reflected, resp = self.injector.probe_reflection(
                "https://example.com/?q=test", "q", marker
            )
            assert reflected is True

    def test_probe_reflection_not_reflected(self):
        with patch.object(self.injector._session, "get") as mock_get:
            mock_get.return_value = self._mock_get(text="<html>nothing here</html>")
            reflected, _ = self.injector.probe_reflection(
                "https://example.com/?q=test", "q", "MISSING_MARKER_XYZ"
            )
            assert reflected is False

    def test_probe_reflection_tag_wrapping_fallback(self):
        """
        When the plain probe returns 400 (tag-restricted endpoint), the injector
        should try tag-wrapped probes and return True once one succeeds.
        This simulates the Firing Range /tags/* behaviour.
        """
        marker = "vXSStagprobe"
        call_count = [0]

        def side_effect(url, **kwargs):
            resp = MagicMock()
            resp.headers = {}
            # First call (plain marker) → 400 with no reflection
            if call_count[0] == 0:
                resp.status_code = 400
                resp.text = "Bad Request"
            else:
                # Subsequent calls: simulate server reflecting the marker inside
                # an img src attribute (i.e. tag-wrapped probe succeeded)
                resp.status_code = 200
                resp.text = f'<img src="{marker}">'
            call_count[0] += 1
            return resp

        with patch.object(self.injector._session, "get", side_effect=side_effect):
            reflected, resp = self.injector.probe_reflection(
                "https://example.com/?q=test", "q", marker
            )
        assert reflected is True
        # Must have made more than one request (fallback tried)
        assert call_count[0] > 1

    def test_probe_reflection_tag_wrapping_all_fail(self):
        """
        If ALL probes (plain + tag-wrapped) fail to reflect the marker,
        probe_reflection must return False.
        """
        marker = "vXSSneverreflected"

        def side_effect(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 400
            resp.text = "Bad Request"
            resp.headers = {}
            return resp

        with patch.object(self.injector._session, "get", side_effect=side_effect):
            reflected, _ = self.injector.probe_reflection(
                "https://example.com/?q=test", "q", marker
            )
        assert reflected is False

    def test_header_injection(self):
        with patch.object(self.injector._session, "get") as mock_get:
            mock_get.return_value = self._mock_get()
            self.injector.inject_header("https://example.com/", "Referer", "<script>")
            headers_sent = mock_get.call_args[1].get("headers", {})
            assert headers_sent.get("Referer") == "<script>"
