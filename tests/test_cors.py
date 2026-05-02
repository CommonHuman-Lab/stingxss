# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Tests for engine/cors.py — CORS misconfiguration detector.

Covers all 7 Google Firing Range /cors/alloworigin/ cases:
  1. dynamicAllowOrigin         → ISSUE_DYNAMIC_REFLECT
  2. allowOriginStartsWith      → ISSUE_STARTS_WITH_BYPASS
  3. allowOriginEndsWith        → ISSUE_ENDS_WITH_BYPASS
  4. allowOriginRegexDot        → ISSUE_REGEX_DOT_BYPASS
  5. allowOriginProtocolDowngrade → ISSUE_PROTOCOL_DOWNGRADE
  6. allowNullOrigin            → ISSUE_NULL_ORIGIN
  7. allowInsecureScheme        → ISSUE_INSECURE_SCHEME
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from stingxss.engine.checks.cors import (
  check,
  _origin_allowed,
  ISSUE_DYNAMIC_REFLECT,
  ISSUE_STARTS_WITH_BYPASS,
  ISSUE_ENDS_WITH_BYPASS,
  ISSUE_REGEX_DOT_BYPASS,
  ISSUE_PROTOCOL_DOWNGRADE,
  ISSUE_NULL_ORIGIN,
  ISSUE_INSECURE_SCHEME,
)
from stingxss.engine.reporter import CORSFinding

BASE_URL = "https://example.com/api/data"


# ---------------------------------------------------------------------------
# Helper — build a mock injector whose get() returns specific headers
# ---------------------------------------------------------------------------

def _injector_factory(response_map: dict):
  """
  Returns a mock injector whose get(url, headers=...) inspects the Origin
  header sent and returns the matching ACAO/ACAC response headers.

  response_map: { origin_value: (acao_value, acac_value) }
  A special key '*' means "match any origin".
  """
  def _get(url, params=None, **kwargs):
    origin = (kwargs.get("headers") or {}).get("Origin", "")
    resp = MagicMock()
    # Look up exact match first, then wildcard
    if origin in response_map:
      acao, acac = response_map[origin]
    elif "*" in response_map:
      acao, acac = response_map["*"]
    else:
      acao, acac = "", ""
    resp.headers = {
      "Access-Control-Allow-Origin":      acao,
      "Access-Control-Allow-Credentials": acac,
      "Content-Type": "application/json",
    }
    return resp

  inj = MagicMock()
  inj.get.side_effect = _get
  return inj


def _no_cors_injector():
  """Injector that never sets CORS headers."""
  return _injector_factory({})


# ---------------------------------------------------------------------------
# Unit — _origin_allowed helper
# ---------------------------------------------------------------------------

class TestOriginAllowed:
  def test_exact_match(self):
    assert _origin_allowed("https://evil.com", "https://evil.com")

  def test_wildcard(self):
    assert _origin_allowed("*", "https://anything.com")

  def test_no_match(self):
    assert not _origin_allowed("https://safe.com", "https://evil.com")

  def test_case_insensitive(self):
    assert _origin_allowed("HTTPS://EVIL.COM", "https://evil.com")

  def test_empty_acao(self):
    assert not _origin_allowed("", "https://evil.com")


# ---------------------------------------------------------------------------
# Case 1: dynamicAllowOrigin — blindly reflects any Origin
# ---------------------------------------------------------------------------

class TestDynamicReflect:
  def test_detects_dynamic_reflect(self):
    # Server reflects whatever Origin is sent
    inj = _injector_factory({"*": ("__ORIGIN__", "true")})

    # Patch: server echoes the Origin value
    def _echo_get(url, params=None, **kwargs):
      origin = (kwargs.get("headers") or {}).get("Origin", "")
      resp = MagicMock()
      resp.headers = {
        "Access-Control-Allow-Origin":      origin,
        "Access-Control-Allow-Credentials": "true",
      }
      return resp

    inj.get.side_effect = _echo_get
    findings = check(BASE_URL, inj)
    issues = [f.issue for f in findings]
    assert ISSUE_DYNAMIC_REFLECT in issues

  def test_dynamic_reflect_credentials_flag(self):
    def _echo_get(url, params=None, **kwargs):
      origin = (kwargs.get("headers") or {}).get("Origin", "")
      resp = MagicMock()
      resp.headers = {
        "Access-Control-Allow-Origin":      origin,
        "Access-Control-Allow-Credentials": "true",
      }
      return resp

    inj = MagicMock()
    inj.get.side_effect = _echo_get
    findings = check(BASE_URL, inj)
    dr = next(f for f in findings if f.issue == ISSUE_DYNAMIC_REFLECT)
    assert dr.credentials is True

  def test_no_finding_when_acao_absent(self):
    inj = _no_cors_injector()
    findings = check(BASE_URL, inj)
    assert not any(f.issue == ISSUE_DYNAMIC_REFLECT for f in findings)

  def test_no_finding_when_acao_same_origin_only(self):
    # ACAO only set for same-origin requests, not for the evil probe origin
    inj = _injector_factory({"https://example.com": ("https://example.com", "true")})
    findings = check(BASE_URL, inj)
    assert not any(f.issue == ISSUE_DYNAMIC_REFLECT for f in findings)


# ---------------------------------------------------------------------------
# Case 2: allowOriginStartsWith — startsWith bypass
# ---------------------------------------------------------------------------

class TestStartsWithBypass:
  def test_detects_startswith_bypass(self):
    # Server accepts any origin starting with "example.com"
    def _startswith_get(url, params=None, **kwargs):
      origin = (kwargs.get("headers") or {}).get("Origin", "")
      resp = MagicMock()
      if "example.com" in origin:
        resp.headers = {
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Credentials": "true",
        }
      else:
        resp.headers = {}
      return resp

    inj = MagicMock()
    inj.get.side_effect = _startswith_get
    findings = check(BASE_URL, inj)
    assert any(f.issue == ISSUE_STARTS_WITH_BYPASS for f in findings)

  def test_no_finding_when_bypass_origin_rejected(self):
    inj = _no_cors_injector()
    findings = check(BASE_URL, inj)
    assert not any(f.issue == ISSUE_STARTS_WITH_BYPASS for f in findings)


# ---------------------------------------------------------------------------
# Case 3: allowOriginEndsWith — endsWith bypass
# ---------------------------------------------------------------------------

class TestEndsWithBypass:
  def test_detects_endswith_bypass(self):
    def _endswith_get(url, params=None, **kwargs):
      origin = (kwargs.get("headers") or {}).get("Origin", "")
      resp = MagicMock()
      # Accept if origin ends with ".com" (overly broad)
      if origin.endswith(".com"):
        resp.headers = {
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Credentials": "false",
        }
      else:
        resp.headers = {}
      return resp

    inj = MagicMock()
    inj.get.side_effect = _endswith_get
    findings = check(BASE_URL, inj)
    assert any(f.issue == ISSUE_ENDS_WITH_BYPASS for f in findings)

  def test_no_finding_when_bypass_origin_rejected(self):
    inj = _no_cors_injector()
    findings = check(BASE_URL, inj)
    assert not any(f.issue == ISSUE_ENDS_WITH_BYPASS for f in findings)


# ---------------------------------------------------------------------------
# Case 4: allowOriginRegexDot — unescaped dot bypass
# ---------------------------------------------------------------------------

class TestRegexDotBypass:
  def test_detects_regex_dot_bypass(self):
    import re as _re
    # Simulates: origin.match("www.example.com") — dot matches any char
    pattern = _re.compile(r"https://wwwXexample\.com")  # NOT what the server does
    # Server uses unescaped dot: www.example.com → accepts wwwXexample.com
    def _regex_get(url, params=None, **kwargs):
      origin = (kwargs.get("headers") or {}).get("Origin", "")
      resp = MagicMock()
      # Simulate buggy server: treats '.' as any char
      if _re.search(r"https://www.example.com", origin):
        resp.headers = {
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Credentials": "true",
        }
      else:
        resp.headers = {}
      return resp

    inj = MagicMock()
    inj.get.side_effect = _regex_get
    findings = check("https://www.example.com/api", inj)
    assert any(f.issue == ISSUE_REGEX_DOT_BYPASS for f in findings)

  def test_no_finding_when_bypass_rejected(self):
    inj = _no_cors_injector()
    findings = check(BASE_URL, inj)
    assert not any(f.issue == ISSUE_REGEX_DOT_BYPASS for f in findings)


# ---------------------------------------------------------------------------
# Case 5: allowOriginProtocolDowngrade — http:// accepted for https:// target
# ---------------------------------------------------------------------------

class TestProtocolDowngrade:
  def test_detects_protocol_downgrade(self):
    def _downgrade_get(url, params=None, **kwargs):
      origin = (kwargs.get("headers") or {}).get("Origin", "")
      resp = MagicMock()
      # Server only checks hostname, not scheme
      if "example.com" in origin:
        resp.headers = {
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Credentials": "true",
        }
      else:
        resp.headers = {}
      return resp

    inj = MagicMock()
    inj.get.side_effect = _downgrade_get
    findings = check(BASE_URL, inj)  # BASE_URL is https://
    assert any(f.issue == ISSUE_PROTOCOL_DOWNGRADE for f in findings)

  def test_no_probe_for_http_target(self):
    """Protocol downgrade is only relevant for https:// targets."""
    inj = _no_cors_injector()
    findings = check("http://example.com/api", inj)
    assert not any(f.issue == ISSUE_PROTOCOL_DOWNGRADE for f in findings)

  def test_no_finding_when_http_origin_rejected(self):
    inj = _no_cors_injector()
    findings = check(BASE_URL, inj)
    assert not any(f.issue == ISSUE_PROTOCOL_DOWNGRADE for f in findings)


# ---------------------------------------------------------------------------
# Case 6: allowNullOrigin — ACAO: null
# ---------------------------------------------------------------------------

class TestNullOrigin:
  def test_detects_null_origin(self):
    inj = _injector_factory({"null": ("null", "true")})
    findings = check(BASE_URL, inj)
    assert any(f.issue == ISSUE_NULL_ORIGIN for f in findings)

  def test_null_finding_has_correct_acao(self):
    inj = _injector_factory({"null": ("null", "false")})
    findings = check(BASE_URL, inj)
    nf = next(f for f in findings if f.issue == ISSUE_NULL_ORIGIN)
    assert nf.acao_received == "null"
    assert nf.origin_sent == "null"

  def test_no_finding_when_null_rejected(self):
    inj = _no_cors_injector()
    findings = check(BASE_URL, inj)
    assert not any(f.issue == ISSUE_NULL_ORIGIN for f in findings)

  def test_no_finding_when_acao_is_not_null(self):
    # ACAO returns a normal origin, not "null"
    inj = _injector_factory({"null": ("https://example.com", "false")})
    findings = check(BASE_URL, inj)
    assert not any(f.issue == ISSUE_NULL_ORIGIN for f in findings)


# ---------------------------------------------------------------------------
# Case 7: allowInsecureScheme — http:// origin accepted for https:// resource
# ---------------------------------------------------------------------------

class TestInsecureScheme:
  def test_detects_insecure_scheme(self):
    def _http_get(url, params=None, **kwargs):
      origin = (kwargs.get("headers") or {}).get("Origin", "")
      resp = MagicMock()
      if origin.startswith("http://"):
        resp.headers = {
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Credentials": "true",
        }
      else:
        resp.headers = {}
      return resp

    inj = MagicMock()
    inj.get.side_effect = _http_get
    findings = check(BASE_URL, inj)  # BASE_URL is https://
    assert any(f.issue == ISSUE_INSECURE_SCHEME for f in findings)

  def test_no_probe_for_http_target(self):
    """Insecure scheme probe is only sent when target is https://."""
    inj = _no_cors_injector()
    findings = check("http://example.com/api", inj)
    assert not any(f.issue == ISSUE_INSECURE_SCHEME for f in findings)

  def test_no_finding_when_http_attacker_rejected(self):
    inj = _no_cors_injector()
    findings = check(BASE_URL, inj)
    assert not any(f.issue == ISSUE_INSECURE_SCHEME for f in findings)


# ---------------------------------------------------------------------------
# CORSFinding dataclass fields
# ---------------------------------------------------------------------------

class TestCORSFindingFields:
  def test_finding_url_captured(self):
    inj = _injector_factory({"null": ("null", "false")})
    findings = check(BASE_URL, inj)
    nf = next(f for f in findings if f.issue == ISSUE_NULL_ORIGIN)
    assert nf.url == BASE_URL

  def test_finding_reason_nonempty(self):
    inj = _injector_factory({"null": ("null", "false")})
    findings = check(BASE_URL, inj)
    nf = next(f for f in findings if f.issue == ISSUE_NULL_ORIGIN)
    assert len(nf.reason) > 20

  def test_empty_result_when_no_cors_headers(self):
    inj = _no_cors_injector()
    findings = check(BASE_URL, inj)
    assert findings == []

  def test_network_error_does_not_raise(self):
    """Exceptions from the injector must be swallowed, not propagated."""
    inj = MagicMock()
    inj.get.side_effect = Exception("network error")
    findings = check(BASE_URL, inj)
    assert findings == []
