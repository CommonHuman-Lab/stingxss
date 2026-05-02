# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Tests for engine/hsts.py — HSTS header analyser.

Covers all five Google Firing Range /stricttransportsecurity/ cases:
  1. hsts_missing                  — header absent
  2. hsts_max_age_too_low          — max-age=1337
  3. hsts_max_age_missing          — includeSubDomains; preload (no max-age)
  4. hsts_includesubdomains_missing — max-age=63072000; preload
  5. hsts_preload_missing           — max-age=63072000; includeSubDomains
Plus good-header and edge-case coverage.
"""

import pytest

from stingxss.engine.checks.hsts import check, _get_header, HstsFinding

HTTPS_URL = "https://example.com/page"
HTTP_URL  = "http://example.com/page"

# Exact header values observed from the Firing Range
FR_MAX_AGE_TOO_LOW           = "max-age=1337; includeSubDomains; preload"
FR_MAX_AGE_MISSING           = "includeSubDomains; preload"
FR_INCLUDESUBDOMAINS_MISSING = "max-age=63072000; preload"
FR_PRELOAD_MISSING           = "max-age=63072000; includeSubDomains"
GOOD_HEADER                  = "max-age=63072000; includeSubDomains; preload"


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def issues(findings):
    return [f.issue for f in findings]


# ---------------------------------------------------------------------------
# Unit test: _get_header helper
# ---------------------------------------------------------------------------

class TestGetHeader:
    def test_case_insensitive_lookup(self):
        hdrs = {"Strict-Transport-Security": "max-age=31536000"}
        assert _get_header(hdrs, "strict-transport-security") == "max-age=31536000"

    def test_uppercase_key_found(self):
        hdrs = {"STRICT-TRANSPORT-SECURITY": "max-age=31536000"}
        assert _get_header(hdrs, "strict-transport-security") == "max-age=31536000"

    def test_missing_returns_none(self):
        assert _get_header({}, "strict-transport-security") is None


# ---------------------------------------------------------------------------
# Case 1: hsts_missing
# ---------------------------------------------------------------------------

class TestHstsMissing:
    """Firing Range: /stricttransportsecurity/hsts_missing"""

    def test_absent_header_flagged(self):
        findings = check(HTTPS_URL, {})
        assert "hsts_missing" in issues(findings)

    def test_only_one_finding_when_missing(self):
        # When the header is absent there is nothing else to analyse
        findings = check(HTTPS_URL, {})
        assert len(findings) == 1

    def test_url_captured(self):
        findings = check(HTTPS_URL, {})
        assert findings[0].url == HTTPS_URL

    def test_header_value_empty_string(self):
        findings = check(HTTPS_URL, {})
        assert findings[0].header_value == ""

    def test_reason_mentions_hsts(self):
        findings = check(HTTPS_URL, {})
        assert "HSTS" in findings[0].reason or "Strict-Transport-Security" in findings[0].reason

    def test_http_url_skipped(self):
        # HSTS is irrelevant for plain HTTP — should return no findings
        findings = check(HTTP_URL, {})
        assert findings == []


# ---------------------------------------------------------------------------
# Case 2: hsts_max_age_too_low
# ---------------------------------------------------------------------------

class TestHstsMaxAgeTooLow:
    """Firing Range: /stricttransportsecurity/hsts_max_age_too_low
    Header: max-age=1337; includeSubDomains; preload
    """

    def test_low_max_age_flagged(self):
        hdrs = {"Strict-Transport-Security": FR_MAX_AGE_TOO_LOW}
        findings = check(HTTPS_URL, hdrs)
        assert "hsts_max_age_too_low" in issues(findings)

    def test_no_other_flags_missing(self):
        # includeSubDomains and preload ARE present — only max-age should fire
        hdrs = {"Strict-Transport-Security": FR_MAX_AGE_TOO_LOW}
        findings = check(HTTPS_URL, hdrs)
        assert "hsts_includesubdomains_missing" not in issues(findings)
        assert "hsts_preload_missing" not in issues(findings)

    def test_header_value_captured(self):
        hdrs = {"Strict-Transport-Security": FR_MAX_AGE_TOO_LOW}
        findings = check(HTTPS_URL, hdrs)
        f = next(f for f in findings if f.issue == "hsts_max_age_too_low")
        assert f.header_value == FR_MAX_AGE_TOO_LOW

    def test_reason_mentions_max_age_value(self):
        hdrs = {"Strict-Transport-Security": FR_MAX_AGE_TOO_LOW}
        findings = check(HTTPS_URL, hdrs)
        f = next(f for f in findings if f.issue == "hsts_max_age_too_low")
        assert "1337" in f.reason

    def test_boundary_exactly_18_weeks_not_flagged(self):
        # 10886400 seconds = 18 weeks — right on the warn threshold (not below it)
        hdrs = {"Strict-Transport-Security": "max-age=10886400; includeSubDomains; preload"}
        findings = check(HTTPS_URL, hdrs)
        assert "hsts_max_age_too_low" not in issues(findings)

    def test_boundary_one_below_18_weeks_flagged(self):
        hdrs = {"Strict-Transport-Security": "max-age=10886399; includeSubDomains; preload"}
        findings = check(HTTPS_URL, hdrs)
        assert "hsts_max_age_too_low" in issues(findings)

    def test_zero_max_age_flagged(self):
        hdrs = {"Strict-Transport-Security": "max-age=0; includeSubDomains; preload"}
        findings = check(HTTPS_URL, hdrs)
        assert "hsts_max_age_too_low" in issues(findings)


# ---------------------------------------------------------------------------
# Case 3: hsts_max_age_missing
# ---------------------------------------------------------------------------

class TestHstsMaxAgeMissing:
    """Firing Range: /stricttransportsecurity/hsts_max_age_missing
    Header: includeSubDomains; preload
    """

    def test_no_max_age_flagged(self):
        hdrs = {"Strict-Transport-Security": FR_MAX_AGE_MISSING}
        findings = check(HTTPS_URL, hdrs)
        assert "hsts_max_age_missing" in issues(findings)

    def test_includesubdomains_and_preload_present(self):
        # Those flags ARE present so they must not fire
        hdrs = {"Strict-Transport-Security": FR_MAX_AGE_MISSING}
        findings = check(HTTPS_URL, hdrs)
        assert "hsts_includesubdomains_missing" not in issues(findings)
        assert "hsts_preload_missing" not in issues(findings)

    def test_header_value_captured(self):
        hdrs = {"Strict-Transport-Security": FR_MAX_AGE_MISSING}
        findings = check(HTTPS_URL, hdrs)
        f = next(f for f in findings if f.issue == "hsts_max_age_missing")
        assert f.header_value == FR_MAX_AGE_MISSING

    def test_reason_mentions_max_age(self):
        hdrs = {"Strict-Transport-Security": FR_MAX_AGE_MISSING}
        findings = check(HTTPS_URL, hdrs)
        f = next(f for f in findings if f.issue == "hsts_max_age_missing")
        assert "max-age" in f.reason


# ---------------------------------------------------------------------------
# Case 4: hsts_includesubdomains_missing
# ---------------------------------------------------------------------------

class TestHstsIncludeSubdomainsMissing:
    """Firing Range: /stricttransportsecurity/hsts_includesubdomains_missing
    Header: max-age=63072000; preload
    """

    def test_missing_includesubdomains_flagged(self):
        hdrs = {"Strict-Transport-Security": FR_INCLUDESUBDOMAINS_MISSING}
        findings = check(HTTPS_URL, hdrs)
        assert "hsts_includesubdomains_missing" in issues(findings)

    def test_max_age_and_preload_present(self):
        hdrs = {"Strict-Transport-Security": FR_INCLUDESUBDOMAINS_MISSING}
        findings = check(HTTPS_URL, hdrs)
        assert "hsts_max_age_missing" not in issues(findings)
        assert "hsts_max_age_too_low" not in issues(findings)
        assert "hsts_preload_missing" not in issues(findings)

    def test_header_value_captured(self):
        hdrs = {"Strict-Transport-Security": FR_INCLUDESUBDOMAINS_MISSING}
        findings = check(HTTPS_URL, hdrs)
        f = next(f for f in findings if f.issue == "hsts_includesubdomains_missing")
        assert f.header_value == FR_INCLUDESUBDOMAINS_MISSING

    def test_reason_mentions_includesubdomains(self):
        hdrs = {"Strict-Transport-Security": FR_INCLUDESUBDOMAINS_MISSING}
        findings = check(HTTPS_URL, hdrs)
        f = next(f for f in findings if f.issue == "hsts_includesubdomains_missing")
        assert "includeSubDomains" in f.reason or "subdomain" in f.reason.lower()


# ---------------------------------------------------------------------------
# Case 5: hsts_preload_missing
# ---------------------------------------------------------------------------

class TestHstsPreloadMissing:
    """Firing Range: /stricttransportsecurity/hsts_preload_missing
    Header: max-age=63072000; includeSubDomains
    """

    def test_missing_preload_flagged(self):
        hdrs = {"Strict-Transport-Security": FR_PRELOAD_MISSING}
        findings = check(HTTPS_URL, hdrs)
        assert "hsts_preload_missing" in issues(findings)

    def test_max_age_and_includesubdomains_present(self):
        hdrs = {"Strict-Transport-Security": FR_PRELOAD_MISSING}
        findings = check(HTTPS_URL, hdrs)
        assert "hsts_max_age_missing" not in issues(findings)
        assert "hsts_max_age_too_low" not in issues(findings)
        assert "hsts_includesubdomains_missing" not in issues(findings)

    def test_header_value_captured(self):
        hdrs = {"Strict-Transport-Security": FR_PRELOAD_MISSING}
        findings = check(HTTPS_URL, hdrs)
        f = next(f for f in findings if f.issue == "hsts_preload_missing")
        assert f.header_value == FR_PRELOAD_MISSING

    def test_reason_mentions_preload(self):
        hdrs = {"Strict-Transport-Security": FR_PRELOAD_MISSING}
        findings = check(HTTPS_URL, hdrs)
        f = next(f for f in findings if f.issue == "hsts_preload_missing")
        assert "preload" in f.reason.lower()


# ---------------------------------------------------------------------------
# Good header — no findings expected
# ---------------------------------------------------------------------------

class TestGoodHeader:
    def test_perfect_header_no_findings(self):
        hdrs = {"Strict-Transport-Security": GOOD_HEADER}
        findings = check(HTTPS_URL, hdrs)
        assert findings == []

    def test_one_year_exact_no_low_max_age(self):
        hdrs = {"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"}
        findings = check(HTTPS_URL, hdrs)
        assert findings == []

    def test_header_name_case_insensitive(self):
        hdrs = {"strict-transport-security": GOOD_HEADER}
        findings = check(HTTPS_URL, hdrs)
        assert findings == []

    def test_directives_order_independent(self):
        hdrs = {"Strict-Transport-Security": "preload; max-age=63072000; includeSubDomains"}
        findings = check(HTTPS_URL, hdrs)
        assert findings == []


# ---------------------------------------------------------------------------
# Multi-issue: header present with multiple problems simultaneously
# ---------------------------------------------------------------------------

class TestMultipleIssues:
    def test_low_max_age_and_no_includesubdomains_and_no_preload(self):
        hdrs = {"Strict-Transport-Security": "max-age=100"}
        findings = check(HTTPS_URL, hdrs)
        found = issues(findings)
        assert "hsts_max_age_too_low" in found
        assert "hsts_includesubdomains_missing" in found
        assert "hsts_preload_missing" in found

    def test_no_max_age_and_no_includesubdomains_and_no_preload(self):
        hdrs = {"Strict-Transport-Security": ""}
        findings = check(HTTPS_URL, hdrs)
        found = issues(findings)
        assert "hsts_max_age_missing" in found
        assert "hsts_includesubdomains_missing" in found
        assert "hsts_preload_missing" in found

    def test_finding_type_is_hsts_finding(self):
        hdrs = {"Strict-Transport-Security": "max-age=100"}
        findings = check(HTTPS_URL, hdrs)
        for f in findings:
            assert isinstance(f, HstsFinding)
