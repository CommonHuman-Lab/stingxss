# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Tests for engine/sri.py — SRI / insecure third-party script detector.

Covers both Google Firing Range /insecurethirdpartyscripts/ cases:
  1. third_party_scripts_without_subresource_integrity
     Static <script src="//nonexistent.google"> with no integrity attribute.
  2. third_party_scripts_without_subresource_integrity_dynamically_added
     Inline JS that creates a <script> element and assigns a cross-origin URL
     to .src without setting .integrity.
Plus safe-variant and edge-case coverage.
"""

import pytest

from stingxss.engine.checks.sri import (
    check,
    _is_cross_origin,
    _has_valid_integrity,
    _normalise_src,
    SriFinding,
)

PAGE_HTTPS = "https://example.com/page"
PAGE_HTTP  = "http://example.com/page"

# ---------------------------------------------------------------------------
# Exact Firing Range HTML
# ---------------------------------------------------------------------------

FR_STATIC = """<!DOCTYPE html>
<html>
  <body>
    <script src="//nonexistent.google"></script>
  </body>
</html>"""

FR_DYNAMIC = """<!DOCTYPE html>
<html>
  <body>
    <script>
      var script = document.createElement('script');
      script.src = '//nonexistent.google';
      document.body.append(script);
    </script>
  </body>
</html>"""


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def issues(findings):
    return [f.issue for f in findings]


# ---------------------------------------------------------------------------
# Unit tests: helpers
# ---------------------------------------------------------------------------

class TestIssCrossOrigin:
    def test_protocol_relative_different_host(self):
        assert _is_cross_origin("https://example.com/", "//cdn.example.net/lib.js") is True

    def test_absolute_https_different_host(self):
        assert _is_cross_origin("https://example.com/", "https://cdn.jquery.com/lib.js") is True

    def test_absolute_http_different_host(self):
        assert _is_cross_origin("https://example.com/", "http://cdn.other.com/lib.js") is True

    def test_same_host_protocol_relative(self):
        assert _is_cross_origin("https://example.com/", "//example.com/static/lib.js") is False

    def test_same_host_absolute(self):
        assert _is_cross_origin("https://example.com/page", "https://example.com/js/lib.js") is False

    def test_relative_path_not_cross_origin(self):
        assert _is_cross_origin("https://example.com/page", "/js/lib.js") is False

    def test_relative_no_slash_not_cross_origin(self):
        assert _is_cross_origin("https://example.com/page", "lib.js") is False

    def test_empty_src(self):
        assert _is_cross_origin("https://example.com/", "") is False


class TestHasValidIntegrity:
    def test_sha256(self):
        assert _has_valid_integrity("sha256-abc123==") is True

    def test_sha384(self):
        assert _has_valid_integrity("sha384-xyz==") is True

    def test_sha512(self):
        assert _has_valid_integrity("sha512-longvalue==") is True

    def test_empty_string(self):
        assert _has_valid_integrity("") is False

    def test_wrong_prefix(self):
        assert _has_valid_integrity("md5-abc123") is False

    def test_case_insensitive(self):
        assert _has_valid_integrity("SHA256-abc==") is True


class TestNormaliseSrc:
    def test_protocol_relative_gets_https_scheme(self):
        result = _normalise_src("https://example.com/", "//cdn.test/lib.js")
        assert result == "https://cdn.test/lib.js"

    def test_protocol_relative_gets_http_scheme(self):
        result = _normalise_src("http://example.com/", "//cdn.test/lib.js")
        assert result == "http://cdn.test/lib.js"

    def test_absolute_url_unchanged(self):
        result = _normalise_src("https://example.com/", "https://cdn.test/lib.js")
        assert result == "https://cdn.test/lib.js"


# ---------------------------------------------------------------------------
# Case 1: static <script src> without integrity (Firing Range exact HTML)
# ---------------------------------------------------------------------------

class TestStaticNoIntegrity:
    """Firing Range: third_party_scripts_without_subresource_integrity"""

    def test_firing_range_detected(self):
        findings = check(PAGE_HTTPS, FR_STATIC)
        assert any(f.issue == "static_no_integrity" for f in findings)

    def test_exactly_one_finding(self):
        findings = check(PAGE_HTTPS, FR_STATIC)
        assert len(findings) == 1

    def test_script_src_captured(self):
        findings = check(PAGE_HTTPS, FR_STATIC)
        f = findings[0]
        assert "nonexistent.google" in f.script_src

    def test_url_captured(self):
        findings = check(PAGE_HTTPS, FR_STATIC)
        assert findings[0].url == PAGE_HTTPS

    def test_reason_mentions_integrity(self):
        findings = check(PAGE_HTTPS, FR_STATIC)
        assert "integrity" in findings[0].reason.lower()

    def test_evidence_contains_script_tag(self):
        findings = check(PAGE_HTTPS, FR_STATIC)
        assert "script" in findings[0].evidence.lower()

    def test_finding_is_sri_finding_instance(self):
        findings = check(PAGE_HTTPS, FR_STATIC)
        assert isinstance(findings[0], SriFinding)

    def test_https_absolute_url_no_integrity(self):
        html = '<html><head><script src="https://cdn.external.com/lib.js"></script></head></html>'
        findings = check(PAGE_HTTPS, html)
        assert any(f.issue == "static_no_integrity" for f in findings)

    def test_http_absolute_url_no_integrity(self):
        html = '<html><head><script src="http://cdn.external.com/lib.js"></script></head></html>'
        findings = check(PAGE_HTTPS, html)
        assert any(f.issue == "static_no_integrity" for f in findings)


# ---------------------------------------------------------------------------
# Static script with valid integrity — must NOT be flagged
# ---------------------------------------------------------------------------

class TestStaticWithIntegrity:
    def test_sha256_integrity_not_flagged(self):
        html = (
            '<script src="https://cdn.external.com/lib.js" '
            'integrity="sha256-abc123=="></script>'
        )
        findings = check(PAGE_HTTPS, html)
        assert not any(f.issue == "static_no_integrity" for f in findings)

    def test_sha384_integrity_not_flagged(self):
        html = (
            '<script src="https://cdn.external.com/lib.js" '
            'integrity="sha384-xyz=="></script>'
        )
        findings = check(PAGE_HTTPS, html)
        assert not any(f.issue == "static_no_integrity" for f in findings)

    def test_sha512_integrity_not_flagged(self):
        html = (
            '<script src="https://cdn.external.com/lib.js" '
            'integrity="sha512-longvalue=="></script>'
        )
        findings = check(PAGE_HTTPS, html)
        assert not any(f.issue == "static_no_integrity" for f in findings)

    def test_same_origin_script_not_flagged(self):
        html = '<script src="/static/js/app.js"></script>'
        findings = check(PAGE_HTTPS, html)
        assert findings == []

    def test_same_origin_absolute_not_flagged(self):
        html = '<script src="https://example.com/js/app.js"></script>'
        findings = check(PAGE_HTTPS, html)
        assert findings == []


# ---------------------------------------------------------------------------
# Case 2: dynamically added script without integrity (Firing Range exact HTML)
# ---------------------------------------------------------------------------

class TestDynamicNoIntegrity:
    """Firing Range: third_party_scripts_without_subresource_integrity_dynamically_added"""

    def test_firing_range_detected(self):
        findings = check(PAGE_HTTPS, FR_DYNAMIC)
        assert any(f.issue == "dynamic_no_integrity" for f in findings)

    def test_exactly_one_finding(self):
        findings = check(PAGE_HTTPS, FR_DYNAMIC)
        assert len(findings) == 1

    def test_script_src_captured(self):
        findings = check(PAGE_HTTPS, FR_DYNAMIC)
        f = next(f for f in findings if f.issue == "dynamic_no_integrity")
        assert "nonexistent.google" in f.script_src

    def test_reason_mentions_integrity(self):
        findings = check(PAGE_HTTPS, FR_DYNAMIC)
        f = next(f for f in findings if f.issue == "dynamic_no_integrity")
        assert "integrity" in f.reason.lower()

    def test_evidence_is_truncated_snippet(self):
        findings = check(PAGE_HTTPS, FR_DYNAMIC)
        f = next(f for f in findings if f.issue == "dynamic_no_integrity")
        assert len(f.evidence) <= 300

    def test_https_absolute_dynamic_src(self):
        html = """<script>
        var s = document.createElement('script');
        s.src = 'https://cdn.attacker.com/evil.js';
        document.head.appendChild(s);
        </script>"""
        findings = check(PAGE_HTTPS, html)
        assert any(f.issue == "dynamic_no_integrity" for f in findings)

    def test_double_quoted_src_detected(self):
        html = """<script>
        var s = document.createElement('script');
        s.src = "//cdn.external.com/lib.js";
        document.body.append(s);
        </script>"""
        findings = check(PAGE_HTTPS, html)
        assert any(f.issue == "dynamic_no_integrity" for f in findings)


# ---------------------------------------------------------------------------
# Dynamic script with .integrity set — must NOT be flagged
# ---------------------------------------------------------------------------

class TestDynamicWithIntegrity:
    def test_integrity_assigned_not_flagged(self):
        html = """<script>
        var s = document.createElement('script');
        s.src = '//cdn.external.com/lib.js';
        s.integrity = 'sha256-abc123==';
        document.body.append(s);
        </script>"""
        findings = check(PAGE_HTTPS, html)
        assert not any(f.issue == "dynamic_no_integrity" for f in findings)

    def test_integrity_sha384_not_flagged(self):
        html = """<script>
        var s = document.createElement('script');
        s.integrity = 'sha384-xyz==';
        s.src = '//cdn.external.com/lib.js';
        document.body.append(s);
        </script>"""
        findings = check(PAGE_HTTPS, html)
        assert not any(f.issue == "dynamic_no_integrity" for f in findings)

    def test_same_origin_dynamic_src_not_flagged(self):
        html = """<script>
        var s = document.createElement('script');
        s.src = '/static/lib.js';
        document.body.append(s);
        </script>"""
        findings = check(PAGE_HTTPS, html)
        assert findings == []


# ---------------------------------------------------------------------------
# No scripts — no findings
# ---------------------------------------------------------------------------

class TestNoScripts:
    def test_empty_html(self):
        assert check(PAGE_HTTPS, "") == []

    def test_no_script_tags(self):
        html = "<html><body><p>Hello</p></body></html>"
        assert check(PAGE_HTTPS, html) == []

    def test_inline_script_no_src_assignment(self):
        html = "<script>var x = 1 + 2;</script>"
        assert check(PAGE_HTTPS, html) == []


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

class TestDeduplication:
    def test_same_src_twice_static_reported_once(self):
        html = (
            '<script src="//cdn.external.com/lib.js"></script>'
            '<script src="//cdn.external.com/lib.js"></script>'
        )
        findings = check(PAGE_HTTPS, html)
        srcs = [f.script_src for f in findings]
        assert len(srcs) == len(set(srcs))

    def test_two_different_external_scripts_both_reported(self):
        html = (
            '<script src="//cdn.a.com/a.js"></script>'
            '<script src="//cdn.b.com/b.js"></script>'
        )
        findings = check(PAGE_HTTPS, html)
        assert len(findings) == 2


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_malformed_html_does_not_crash(self):
        findings = check(PAGE_HTTPS, "<<<<script src='//evil.com/x.js'")
        assert isinstance(findings, list)

    def test_all_finding_fields_populated(self):
        findings = check(PAGE_HTTPS, FR_STATIC)
        f = findings[0]
        assert f.url
        assert f.issue
        assert f.script_src
        assert f.reason
        assert f.evidence

    def test_both_cases_in_same_page(self):
        combined = """<html><body>
        <script src="//cdn.external.com/lib.js"></script>
        <script>
          var s = document.createElement('script');
          s.src = '//cdn2.other.com/lib2.js';
          document.body.append(s);
        </script>
        </body></html>"""
        findings = check(PAGE_HTTPS, combined)
        found_issues = issues(findings)
        assert "static_no_integrity" in found_issues
        assert "dynamic_no_integrity" in found_issues
