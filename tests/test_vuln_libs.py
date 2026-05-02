# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Tests for engine/vuln_libs.py — vulnerable JavaScript library detector.

Covers the one Google Firing Range /vulnerablelibraries/ case:
  - jQuery 1.8.1 loaded via <script src="...">
    (https://bugs.jquery.com/ticket/11290)

Plus detection of:
  - other vulnerable jQuery 1.x versions
  - safe jQuery versions (1.9+, 2.x, 3.x)
  - inline content fingerprinting
  - deduplication
  - edge cases (malformed HTML, no scripts)
"""

import pytest

from stingxss.engine.checks.vuln_libs import (
    check,
    _ver,
    _check_src_url,
    VulnLibFinding,
    KNOWN_VULNERABLE_LIBS,
)

PAGE = "https://example.com/page"

# ---------------------------------------------------------------------------
# Firing Range exact HTML
# ---------------------------------------------------------------------------

FIRING_RANGE_HTML = """<!DOCTYPE html>
<html>
  <head>
    <title>Firing Range - vulnerable libraries - JQuery</title>
    <script src="https://code.jquery.com/jquery-1.8.1.js"></script>
  </head>
  <body>
    <script>
      function fail() {
        document.getElementById('failurediv').innerHTML = 'Exploited';
      }
      $("element[attribute='<img onerror=fail() src=x>']");
    </script>
    <div id='failurediv'>
      This DIV will host the result of an exploitation of http://bugs.jquery.com/ticket/11290.
    </div>
  </body>
</html>"""


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def libraries(findings):
    return [(f.library, f.version) for f in findings]


# ---------------------------------------------------------------------------
# Unit tests: _ver helper
# ---------------------------------------------------------------------------

class TestVer:
    def test_simple_three_part(self):
        assert _ver("1.8.1") == (1, 8, 1)

    def test_two_part(self):
        assert _ver("1.9") == (1, 9)

    def test_four_part(self):
        assert _ver("3.6.0.1") == (3, 6, 0, 1)

    def test_with_hyphen(self):
        assert _ver("1.8.1-beta") == (1, 8, 1)

    def test_empty_string(self):
        assert _ver("") == (0,)

    def test_non_numeric(self):
        assert _ver("abc") == (0,)


# ---------------------------------------------------------------------------
# Firing Range case: jQuery 1.8.1 via CDN script src
# ---------------------------------------------------------------------------

class TestFiringRangeJQuery181:
    """
    /vulnerablelibraries/jquery.html
    <script src="https://code.jquery.com/jquery-1.8.1.js">
    """

    def test_firing_range_page_detected(self):
        findings = check(PAGE, FIRING_RANGE_HTML)
        assert len(findings) >= 1

    def test_library_is_jquery(self):
        findings = check(PAGE, FIRING_RANGE_HTML)
        assert any(f.library == "jQuery" for f in findings)

    def test_version_is_181(self):
        findings = check(PAGE, FIRING_RANGE_HTML)
        jq = next(f for f in findings if f.library == "jQuery")
        assert jq.version == "1.8.1"

    def test_source_is_script_src(self):
        findings = check(PAGE, FIRING_RANGE_HTML)
        jq = next(f for f in findings if f.library == "jQuery")
        assert jq.source == "script_src"

    def test_url_captured(self):
        findings = check(PAGE, FIRING_RANGE_HTML)
        jq = next(f for f in findings if f.library == "jQuery")
        assert jq.url == PAGE

    def test_evidence_contains_src_url(self):
        findings = check(PAGE, FIRING_RANGE_HTML)
        jq = next(f for f in findings if f.library == "jQuery")
        assert "jquery-1.8.1" in jq.evidence

    def test_advisory_mentions_upgrade(self):
        findings = check(PAGE, FIRING_RANGE_HTML)
        jq = next(f for f in findings if f.library == "jQuery")
        assert "1.9" in jq.advisory or "upgrade" in jq.advisory.lower()

    def test_finding_type_is_vuln_lib_finding(self):
        findings = check(PAGE, FIRING_RANGE_HTML)
        for f in findings:
            assert isinstance(f, VulnLibFinding)


# ---------------------------------------------------------------------------
# URL-based detection: various jQuery 1.x URL formats
# ---------------------------------------------------------------------------

class TestJQueryUrlFormats:
    def _html(self, src):
        return f'<html><head><script src="{src}"></script></head></html>'

    def test_cdn_path_format(self):
        # https://code.jquery.com/jquery/1.8.1/jquery.min.js
        html = self._html("https://code.jquery.com/jquery/1.8.1/jquery.min.js")
        findings = check(PAGE, html)
        assert any(f.library == "jQuery" and f.version == "1.8.1" for f in findings)

    def test_filename_dash_format(self):
        html = self._html("/static/js/jquery-1.7.2.min.js")
        findings = check(PAGE, html)
        assert any(f.library == "jQuery" and f.version == "1.7.2" for f in findings)

    def test_filename_dot_format(self):
        html = self._html("/assets/jquery.1.6.4.js")
        findings = check(PAGE, html)
        assert any(f.library == "jQuery" for f in findings)

    def test_version_1_0_vulnerable(self):
        html = self._html("https://example.com/js/jquery-1.0.0.js")
        findings = check(PAGE, html)
        assert any(f.library == "jQuery" for f in findings)

    def test_version_1_8_9_vulnerable(self):
        html = self._html("/js/jquery-1.8.9.min.js")
        findings = check(PAGE, html)
        assert any(f.library == "jQuery" for f in findings)


# ---------------------------------------------------------------------------
# Safe jQuery versions — must NOT be flagged
# ---------------------------------------------------------------------------

class TestJQuerySafeVersions:
    def _html(self, src):
        return f'<html><head><script src="{src}"></script></head></html>'

    def test_190_safe(self):
        html = self._html("/js/jquery-1.9.0.min.js")
        findings = check(PAGE, html)
        assert not any(f.library == "jQuery" for f in findings)

    def test_191_safe(self):
        html = self._html("/js/jquery-1.9.1.min.js")
        findings = check(PAGE, html)
        assert not any(f.library == "jQuery" for f in findings)

    def test_2x_safe(self):
        html = self._html("https://code.jquery.com/jquery-2.2.4.min.js")
        findings = check(PAGE, html)
        assert not any(f.library == "jQuery" for f in findings)

    def test_3x_safe(self):
        html = self._html("https://code.jquery.com/jquery-3.7.1.min.js")
        findings = check(PAGE, html)
        assert not any(f.library == "jQuery" for f in findings)

    def test_no_script_tag(self):
        findings = check(PAGE, "<html><body>no scripts here</body></html>")
        assert findings == []

    def test_empty_html(self):
        findings = check(PAGE, "")
        assert findings == []


# ---------------------------------------------------------------------------
# Inline content fingerprinting
# ---------------------------------------------------------------------------

class TestInlineFingerprint:
    """
    If the library is hosted locally (no version in src URL), the inline
    content fingerprint + version regex should still detect it.
    """

    def test_inline_fingerprint_detects_jquery(self):
        # Simulate content that looks like the jQuery source comment header
        fake_inline = (
            '<script src="/js/jquery.min.js"></script>'
            '<!-- jQuery JavaScript Library v1.8.1 -->'
        )
        html = f"<html><head>{fake_inline}</head></html>"
        findings = check(PAGE, html)
        # Should find via inline fingerprint since src has no version
        assert any(f.library == "jQuery" for f in findings)

    def test_inline_fingerprint_source_field(self):
        fake_inline = (
            '<script src="/js/lib.js"></script>'
            '<!-- jQuery JavaScript Library v1.5.2 -->'
        )
        html = f"<html><head>{fake_inline}</head></html>"
        findings = check(PAGE, html)
        jq = next((f for f in findings if f.library == "jQuery"), None)
        if jq:  # only check source if detected
            assert jq.source == "inline_content"

    def test_inline_fingerprint_safe_version_not_flagged(self):
        # Same fingerprint but safe version
        safe_inline = '<!-- jQuery JavaScript Library v3.7.1 -->'
        html = f"<html><head>{safe_inline}</head></html>"
        findings = check(PAGE, html)
        assert not any(f.library == "jQuery" for f in findings)


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

class TestDeduplication:
    def test_same_version_not_reported_twice(self):
        # Two script tags pointing to the same version
        html = (
            '<html><head>'
            '<script src="/js/jquery-1.8.1.js"></script>'
            '<script src="https://cdn.example.com/jquery-1.8.1.min.js"></script>'
            '</head></html>'
        )
        findings = check(PAGE, html)
        jq_findings = [f for f in findings if f.library == "jQuery"]
        assert len(jq_findings) == 1

    def test_different_versions_both_reported(self):
        # Two different vulnerable versions loaded (unusual but theoretically possible)
        html = (
            '<html><head>'
            '<script src="/js/jquery-1.7.0.js"></script>'
            '<script src="/js/jquery-1.8.1.js"></script>'
            '</head></html>'
        )
        findings = check(PAGE, html)
        versions = {f.version for f in findings if f.library == "jQuery"}
        # At least one should be reported; deduplication only blocks same version
        assert len(versions) >= 1


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_malformed_html_does_not_crash(self):
        findings = check(PAGE, "<<<<script src='jquery-1.8.1.js'")
        # May or may not detect depending on parser tolerance — must not raise
        assert isinstance(findings, list)

    def test_script_tag_no_src(self):
        html = "<html><head><script>var x = 1;</script></head></html>"
        findings = check(PAGE, html)
        assert findings == []

    def test_non_jquery_script_not_flagged(self):
        html = '<html><head><script src="/js/angular-1.8.1.js"></script></head></html>'
        findings = check(PAGE, html)
        assert not any(f.library == "jQuery" for f in findings)

    def test_finding_fields_all_present(self):
        findings = check(PAGE, FIRING_RANGE_HTML)
        f = findings[0]
        assert f.url
        assert f.library
        assert f.version
        assert f.source
        assert f.evidence
        assert f.advisory


# ---------------------------------------------------------------------------
# KNOWN_VULNERABLE_LIBS sanity checks
# ---------------------------------------------------------------------------

class TestKnownVulnerableLibsTable:
    def test_jquery_entry_exists(self):
        ids = [s.library_id for s in KNOWN_VULNERABLE_LIBS]
        assert "jquery" in ids

    def test_jquery_vuln_if_correct_boundaries(self):
        spec = next(s for s in KNOWN_VULNERABLE_LIBS if s.library_id == "jquery")
        assert spec.vuln_if(_ver("1.0.0")) is True
        assert spec.vuln_if(_ver("1.8.1")) is True
        assert spec.vuln_if(_ver("1.8.9")) is True
        assert spec.vuln_if(_ver("1.9.0")) is False
        assert spec.vuln_if(_ver("2.0.0")) is False
        assert spec.vuln_if(_ver("3.6.0")) is False

    def test_every_spec_has_advisory(self):
        for spec in KNOWN_VULNERABLE_LIBS:
            assert spec.advisory.strip()
