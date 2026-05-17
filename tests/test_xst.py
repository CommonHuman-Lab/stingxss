# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for engine/checks/xst.py — Cross-Site Tracing detector."""

import pytest
from unittest.mock import MagicMock, patch

from stingxss.engine.checks.xst import check, _origin
from stingxss.engine.reporter import XSTFinding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_resp(status=200, content_type="", body=""):
    resp = MagicMock()
    resp.status_code = status
    resp.headers = {"Content-Type": content_type} if content_type else {}
    resp.text = body
    return resp


def _make_injector(resp=None, raises=None):
    inj = MagicMock()
    inj.timeout = 10
    session = MagicMock()
    if raises:
        session.request.side_effect = raises
    else:
        session.request.return_value = resp or _make_resp()
    inj._session = session
    return inj


# ---------------------------------------------------------------------------
# _origin
# ---------------------------------------------------------------------------

class TestOrigin:
    def test_strips_path(self):
        assert _origin("http://example.com/some/path?q=1") == "http://example.com/"

    def test_preserves_port(self):
        assert _origin("https://example.com:8443/app") == "https://example.com:8443/"

    def test_root_url_unchanged(self):
        assert _origin("http://example.com/") == "http://example.com/"


# ---------------------------------------------------------------------------
# check()
# ---------------------------------------------------------------------------

class TestCheck:
    def test_returns_none_when_trace_disabled(self):
        resp = _make_resp(status=405)
        inj = _make_injector(resp=resp)
        assert check("http://example.com/", inj) is None

    def test_returns_none_when_200_but_wrong_content_type(self):
        resp = _make_resp(status=200, content_type="text/html", body="some body")
        inj = _make_injector(resp=resp)
        assert check("http://example.com/", inj) is None

    def test_finding_when_200_and_message_http_content_type(self):
        resp = _make_resp(status=200, content_type="message/http", body="TRACE / HTTP/1.1")
        inj = _make_injector(resp=resp)
        result = check("http://example.com/path", inj)
        assert isinstance(result, XSTFinding)
        assert result.url == "http://example.com/"
        assert result.method == "TRACE"
        assert "TRACE" in result.reason

    def test_finding_when_200_and_trace_echoed_in_body(self):
        resp = _make_resp(status=200, content_type="text/plain", body="TRACE / HTTP/1.1\r\nHost: example.com")
        inj = _make_injector(resp=resp)
        result = check("http://example.com/", inj)
        assert isinstance(result, XSTFinding)

    def test_returns_none_on_exception(self):
        inj = _make_injector(raises=Exception("connection refused"))
        assert check("http://example.com/", inj) is None

    def test_sends_trace_method(self):
        resp = _make_resp(status=405)
        inj = _make_injector(resp=resp)
        check("http://example.com/", inj)
        inj._session.request.assert_called_once()
        call_args = inj._session.request.call_args
        assert call_args[0][0] == "TRACE"

    def test_targets_origin_not_full_path(self):
        resp = _make_resp(status=405)
        inj = _make_injector(resp=resp)
        check("http://example.com/deep/path?q=1", inj)
        call_args = inj._session.request.call_args
        assert call_args[0][1] == "http://example.com/"

    def test_finding_reason_is_non_empty(self):
        resp = _make_resp(status=200, content_type="message/http")
        inj = _make_injector(resp=resp)
        result = check("http://example.com/", inj)
        assert result is not None
        assert len(result.reason) > 20
