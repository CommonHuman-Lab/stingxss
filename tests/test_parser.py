# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Tests for engine/parser.py — context detection logic.
"""

import pytest

from stingxss.engine.analysis.parser import find_context, is_reflected, PROBE_MARKER
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

    def test_style_block_bare(self):
        """Marker as entire CSS content (no property colon before it) → CSS."""
        html = self._body("<style>MARKER</style>")
        assert find_context(html) == ReflectionContext.CSS

    def test_style_block_value(self):
        """Marker inside a CSS property value → CSS_VALUE."""
        html = self._body("<style>body { color: MARKER; }</style>")
        assert find_context(html) == ReflectionContext.CSS_VALUE

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

    def test_template_literal_context(self):
        """Marker inside a template literal is correctly classified as SCRIPT_TEMPLATE."""
        html = self._body("<script>let s = `hello MARKER`;</script>")
        result = find_context(html)
        assert result == ReflectionContext.SCRIPT_TEMPLATE


# ---------------------------------------------------------------------------
# Firing Range /badscriptimport/ — SCRIPT_SRC context detection
# ---------------------------------------------------------------------------

class TestScriptSrcContext:
    """
    Google Firing Range /remoteinclude/parameter/script cases.
    The q parameter is reflected into <script src="MARKER">.
    """

    def _body(self, marker: str = PROBE_MARKER) -> str:
        return (
            f'<html><head><title>Remote include</title></head>'
            f'<body><script src="{marker}"></script></body></html>'
        )

    def test_script_src_classified_as_script_src(self):
        """Marker in <script src="..."> → SCRIPT_SRC context."""
        assert find_context(self._body()) == ReflectionContext.SCRIPT_SRC

    def test_localhost_url_still_script_src(self):
        """Marker reflecting a localhost URL in script src."""
        html = f'<script src="http://127.0.0.2/{PROBE_MARKER}.js"></script>'
        assert find_context(html) == ReflectionContext.SCRIPT_SRC

    def test_private_ip_url_script_src(self):
        """Marker reflecting a private IP URL in script src."""
        html = f'<script src="http://192.168.1.2/{PROBE_MARKER}.js"></script>'
        assert find_context(html) == ReflectionContext.SCRIPT_SRC

    def test_typosquatting_url_script_src(self):
        """Marker reflecting a typosquatting domain in script src."""
        html = f'<script src="http://g00gle.com/{PROBE_MARKER}.js"></script>'
        assert find_context(html) == ReflectionContext.SCRIPT_SRC

    def test_img_src_is_url_attr_not_script_src(self):
        """src in a non-script tag must remain URL_ATTR."""
        html = f'<img src="{PROBE_MARKER}">'
        assert find_context(html) == ReflectionContext.URL_ATTR

    def test_script_src_double_quoted(self):
        """src in script tag with double quotes → SCRIPT_SRC."""
        html = f'<SCRIPT SRC="{PROBE_MARKER}"></SCRIPT>'
        assert find_context(html) == ReflectionContext.SCRIPT_SRC


# ---------------------------------------------------------------------------
# Firing Range /escape/ — new context detection tests
# ---------------------------------------------------------------------------

class TestFiringRangeEscapeContexts:
    """
    Parser context detection for all new contexts introduced by the /escape/ page.
    Each test mirrors the exact HTML structure returned by a specific endpoint.
    """

    def _body(self, template: str) -> str:
        return template.replace("MARKER", PROBE_MARKER)

    # ---- HTML contexts -------------------------------------------------------

    def test_body_html_escaped(self):
        html = self._body("<html><body>\nMARKER\n</body></html>")
        assert find_context(html) == ReflectionContext.HTML_BODY

    def test_body_url_escaped(self):
        html = self._body("<html><body>\nMARKER\n</body></html>")
        assert find_context(html) == ReflectionContext.HTML_BODY

    def test_head_html_escaped(self):
        html = self._body("<html><head>\nMARKER\n</head><body></body></html>")
        assert find_context(html) == ReflectionContext.HTML_BODY

    def test_body_comment_html_escaped(self):
        html = self._body("<html><body><!-- MARKER --></body></html>")
        assert find_context(html) == ReflectionContext.COMMENT

    def test_body_comment_url_escaped(self):
        html = self._body("<html><body><!-- MARKER --></body></html>")
        assert find_context(html) == ReflectionContext.COMMENT

    def test_textarea_html_escaped(self):
        html = self._body("<html><body><textarea>\nMARKER\n</textarea></body></html>")
        assert find_context(html) == ReflectionContext.TEXTAREA

    def test_textarea_url_escaped(self):
        html = self._body("<html><body><textarea>\nMARKER\n</textarea></body></html>")
        assert find_context(html) == ReflectionContext.TEXTAREA

    def test_tagname_html_escaped(self):
        html = self._body("<html><body><MARKER></body></html>")
        assert find_context(html) == ReflectionContext.TAG_NAME

    def test_tagname_url_escaped(self):
        html = self._body("<html><body><MARKER></body></html>")
        assert find_context(html) == ReflectionContext.TAG_NAME

    def test_attribute_unquoted_html_escaped(self):
        html = self._body("<html><body><tag attribute=MARKER></body></html>")
        assert find_context(html) == ReflectionContext.ATTR_UNQUOTED

    def test_attribute_singlequoted_html_escaped(self):
        html = self._body("<html><body><tag attribute='MARKER'></body></html>")
        assert find_context(html) == ReflectionContext.ATTR_SINGLE

    def test_attribute_quoted_html_escaped(self):
        html = self._body('<html><body><tag attribute="MARKER"></body></html>')
        assert find_context(html) == ReflectionContext.ATTR_DOUBLE

    def test_attribute_name_html_escaped(self):
        html = self._body('<html><body><tag MARKER=""/></body></html>')
        assert find_context(html) == ReflectionContext.ATTR_NAME

    def test_attribute_name_url_escaped(self):
        html = self._body('<html><body><tag MARKER=""/></body></html>')
        assert find_context(html) == ReflectionContext.ATTR_NAME

    # ---- CSS contexts --------------------------------------------------------

    def test_css_style_html_escaped(self):
        html = self._body("<html><head><style>MARKER</style></head></html>")
        assert find_context(html) == ReflectionContext.CSS

    def test_css_style_value_html_escaped(self):
        html = self._body(
            "<html><head><style>\nbody { color: MARKER; }\n</style></head></html>"
        )
        assert find_context(html) == ReflectionContext.CSS_VALUE

    def test_css_style_value_url_escaped(self):
        html = self._body(
            "<html><head><style>\nbody { color: MARKER; }\n</style></head></html>"
        )
        assert find_context(html) == ReflectionContext.CSS_VALUE

    def test_css_style_font_value_html_escaped(self):
        html = self._body(
            "<html><head><style>\nbody { font-name: MARKER; }\n</style></head></html>"
        )
        assert find_context(html) == ReflectionContext.CSS_VALUE

    def test_css_style_font_value_url_escaped(self):
        html = self._body(
            "<html><head><style>\nbody { font-name: MARKER; }\n</style></head></html>"
        )
        assert find_context(html) == ReflectionContext.CSS_VALUE

    # ---- JS contexts ---------------------------------------------------------

    def test_js_assignment_html_escaped(self):
        html = self._body("<html><body><script>var foo=MARKER;</script></body></html>")
        assert find_context(html) == ReflectionContext.SCRIPT_BARE

    def test_js_eval_html_escaped(self):
        html = self._body("<html><body><script>MARKER;</script></body></html>")
        assert find_context(html) == ReflectionContext.SCRIPT_BARE

    def test_js_quoted_string_html_escaped(self):
        html = self._body('<html><body><script>var foo="MARKER";</script></body></html>')
        assert find_context(html) == ReflectionContext.SCRIPT_STRING_D

    def test_js_quoted_string_url_escaped(self):
        html = self._body('<html><body><script>var foo="MARKER";</script></body></html>')
        assert find_context(html) == ReflectionContext.SCRIPT_STRING_D

    def test_js_singlequoted_string_html_escaped(self):
        html = self._body("<html><body><script>var foo='MARKER';</script></body></html>")
        assert find_context(html) == ReflectionContext.SCRIPT_STRING_S

    def test_js_slashquoted_string_html_escaped(self):
        html = self._body("<html><body><script>var foo=/MARKER/;</script></body></html>")
        assert find_context(html) == ReflectionContext.SCRIPT_REGEX

    def test_js_slashquoted_string_url_escaped(self):
        html = self._body("<html><body><script>var foo=/MARKER/;</script></body></html>")
        assert find_context(html) == ReflectionContext.SCRIPT_REGEX

    def test_js_comment_html_escaped(self):
        html = self._body('<html><body><script>var foo=1; /* "MARKER" */</script></body></html>')
        assert find_context(html) == ReflectionContext.SCRIPT_COMMENT

    def test_js_comment_url_escaped(self):
        html = self._body('<html><body><script>var foo=1; /* "MARKER" */</script></body></html>')
        assert find_context(html) == ReflectionContext.SCRIPT_COMMENT

    # ---- URL contexts --------------------------------------------------------

    def test_attribute_script_html_escaped(self):
        html = self._body(
            '<html><body><script src="http://irrelevant.google.com?MARKER"/></body></html>'
        )
        assert find_context(html) == ReflectionContext.SCRIPT_SRC

    def test_css_import_html_escaped(self):
        html = self._body(
            '<html><head><link rel="stylesheet" href="MARKER" /></head></html>'
        )
        assert find_context(html) == ReflectionContext.URL_ATTR

    # ---- JS eval with client-side encode wrappers ----------------------------

    def test_js_eval_escape_wrapper(self):
        html = self._body(
            "<html><body><script>\neval(escape('MARKER'));\n</script></body></html>"
        )
        assert find_context(html) == ReflectionContext.SCRIPT_STRING_S

    def test_js_eval_encodeuricomponent_wrapper(self):
        html = self._body(
            "<html><body><script>\neval(encodeURIComponent('MARKER'));\n</script></body></html>"
        )
        assert find_context(html) == ReflectionContext.SCRIPT_STRING_S

    def test_js_eval_html_escape_wrapper(self):
        html = self._body(
            "<html><body><script>eval('MARKER'.replace(/</g, '&lt;'));\n</script></body></html>"
        )
        assert find_context(html) == ReflectionContext.SCRIPT_STRING_S


class TestFiringRangeEscapePayloads:
    """Verify payload sets for each new context."""

    def test_textarea_payloads_break_out(self):
        from stingxss.engine.analysis.payload_gen import generate
        payloads = generate(ReflectionContext.TEXTAREA, level=3)
        assert any("</textarea>" in p for p in payloads)

    def test_tag_name_payloads_valid(self):
        from stingxss.engine.analysis.payload_gen import generate
        payloads = generate(ReflectionContext.TAG_NAME, level=3)
        assert len(payloads) > 0
        assert any("onerror" in p or "onload" in p for p in payloads)

    def test_attr_name_payloads_event_handler(self):
        from stingxss.engine.analysis.payload_gen import generate
        payloads = generate(ReflectionContext.ATTR_NAME, level=3)
        assert any(p.startswith("on") for p in payloads)

    def test_css_value_payloads_break_out(self):
        from stingxss.engine.analysis.payload_gen import generate
        payloads = generate(ReflectionContext.CSS_VALUE, level=3)
        assert any("}" in p for p in payloads)

    def test_script_regex_payloads_escape_slash(self):
        from stingxss.engine.analysis.payload_gen import generate
        payloads = generate(ReflectionContext.SCRIPT_REGEX, level=3)
        assert any(p.startswith("/") for p in payloads)

    def test_script_comment_payloads_escape_comment(self):
        from stingxss.engine.analysis.payload_gen import generate
        payloads = generate(ReflectionContext.SCRIPT_COMMENT, level=3)
        assert any(p.startswith("*/") for p in payloads)


# ---------------------------------------------------------------------------
# New context detection tests: TITLE, IFRAME_SRCDOC, NOSCRIPT, OBJECT_DATA
# ---------------------------------------------------------------------------

class TestNewContextDetection:
    def _body(self, template: str, marker: str = PROBE_MARKER) -> str:
        return template.replace("MARKER", marker)

    # --- TITLE ---------------------------------------------------------------

    def test_title_context(self):
        html = self._body("<html><head><title>MARKER</title></head><body></body></html>")
        assert find_context(html) == ReflectionContext.TITLE

    def test_title_context_not_html_body(self):
        # Must NOT be classified as HTML_BODY
        html = self._body("<title>MARKER</title>")
        ctx = find_context(html)
        assert ctx == ReflectionContext.TITLE

    # --- IFRAME_SRCDOC -------------------------------------------------------

    def test_iframe_srcdoc_double_quoted(self):
        html = self._body('<iframe srcdoc="MARKER"></iframe>')
        assert find_context(html) == ReflectionContext.IFRAME_SRCDOC

    def test_iframe_srcdoc_single_quoted(self):
        html = self._body("<iframe srcdoc='MARKER'></iframe>")
        assert find_context(html) == ReflectionContext.IFRAME_SRCDOC

    # --- NOSCRIPT ------------------------------------------------------------

    def test_noscript_context(self):
        html = self._body("<noscript>MARKER</noscript>")
        assert find_context(html) == ReflectionContext.NOSCRIPT

    def test_noscript_in_head(self):
        html = self._body("<html><head><noscript>MARKER</noscript></head><body></body></html>")
        assert find_context(html) == ReflectionContext.NOSCRIPT

    # --- OBJECT_DATA ---------------------------------------------------------

    def test_object_data_attr(self):
        html = self._body('<object data="MARKER"></object>')
        assert find_context(html) == ReflectionContext.OBJECT_DATA

    def test_param_value_attr(self):
        html = self._body('<object><param value="MARKER"></object>')
        assert find_context(html) == ReflectionContext.OBJECT_DATA


class TestNewContextPayloads:
    def test_title_payloads_break_out(self):
        from stingxss.engine.analysis.payload_gen import generate
        payloads = generate(ReflectionContext.TITLE, level=3)
        assert any("</title>" in p for p in payloads)

    def test_iframe_srcdoc_payloads(self):
        from stingxss.engine.analysis.payload_gen import generate
        payloads = generate(ReflectionContext.IFRAME_SRCDOC, level=3)
        assert len(payloads) > 0
        # At least one payload should inject a script or img
        assert any("<script>" in p or "onerror" in p for p in payloads)

    def test_noscript_payloads_break_out(self):
        from stingxss.engine.analysis.payload_gen import generate
        payloads = generate(ReflectionContext.NOSCRIPT, level=3)
        assert any("</noscript>" in p for p in payloads)

    def test_object_data_payloads(self):
        from stingxss.engine.analysis.payload_gen import generate
        payloads = generate(ReflectionContext.OBJECT_DATA, level=3)
        assert len(payloads) > 0
        assert any("javascript:" in p or "attacker" in p for p in payloads)
