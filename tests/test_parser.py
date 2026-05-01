"""
Tests for engine/parser.py — context detection logic.
"""

import pytest

from stingxss.engine.parser import find_context, is_reflected, PROBE_MARKER
from stingxss.engine.reporter import ReflectionContext


# ---------------------------------------------------------------------------
# is_reflected
# ---------------------------------------------------------------------------

class TestIsReflected:
    def test_marker_present(self):
        assert is_reflected(f"hello {PROBE_MARKER} world")

    def test_marker_absent(self):
        assert not is_reflected("hello world")

    def test_marker_html_encoded(self):
        # Server HTML-encodes the value — is_reflected must still find it
        # after html.unescape
        encoded = PROBE_MARKER.replace("v", "&#118;")
        assert is_reflected(encoded)

    def test_case_insensitive(self):
        assert is_reflected(PROBE_MARKER.lower())
        assert is_reflected(PROBE_MARKER.upper())


# ---------------------------------------------------------------------------
# find_context
# ---------------------------------------------------------------------------

class TestFindContext:
    def _body(self, template: str, marker: str = PROBE_MARKER) -> str:
        return template.replace("MARKER", marker)

    def test_html_body(self):
        html = self._body("<p>MARKER</p>")
        assert find_context(html) == ReflectionContext.HTML_BODY

    def test_attr_double_quote(self):
        html = self._body('<input value="MARKER">')
        assert find_context(html) == ReflectionContext.ATTR_DOUBLE

    def test_attr_single_quote(self):
        html = self._body("<input value='MARKER'>")
        assert find_context(html) == ReflectionContext.ATTR_SINGLE

    def test_attr_unquoted(self):
        html = self._body("<input value=MARKER>")
        assert find_context(html) == ReflectionContext.ATTR_UNQUOTED

    def test_script_string_double(self):
        html = self._body('<script>var x = "MARKER";</script>')
        assert find_context(html) == ReflectionContext.SCRIPT_STRING_D

    def test_script_string_single(self):
        html = self._body("<script>var x = 'MARKER';</script>")
        assert find_context(html) == ReflectionContext.SCRIPT_STRING_S

    def test_script_bare(self):
        html = self._body("<script>var x = MARKER;</script>")
        assert find_context(html) == ReflectionContext.SCRIPT_BARE

    def test_html_comment(self):
        html = self._body("<!-- MARKER -->")
        assert find_context(html) == ReflectionContext.COMMENT

    def test_style_block(self):
        html = self._body("<style>body { color: MARKER; }</style>")
        assert find_context(html) == ReflectionContext.CSS

    def test_event_handler(self):
        html = self._body('<a onclick="alert(MARKER)">click</a>')
        assert find_context(html) == ReflectionContext.EVENT_HANDLER

    def test_url_attribute(self):
        html = self._body('<a href="MARKER">link</a>')
        assert find_context(html) == ReflectionContext.URL_ATTR

    def test_marker_not_found_returns_unknown(self):
        assert find_context("<p>nothing here</p>") == ReflectionContext.UNKNOWN

    def test_marker_after_closed_script(self):
        """Marker in body after a closed script tag should be HTML_BODY."""
        html = self._body("<script>var x = 1;</script><p>MARKER</p>")
        assert find_context(html) == ReflectionContext.HTML_BODY

    def test_template_literal_treated_as_script_bare(self):
        """Marker inside a template literal — classified as SCRIPT_BARE
        (template literals are not split into a separate context yet)."""
        html = self._body("<script>let s = `hello MARKER`;</script>")
        result = find_context(html)
        # Acceptable: bare or any script context, but NOT html_body
        assert result in (
            ReflectionContext.SCRIPT_BARE,
            ReflectionContext.SCRIPT_STRING_D,
            ReflectionContext.SCRIPT_STRING_S,
        )
