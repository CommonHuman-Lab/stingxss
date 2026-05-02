# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Tests for engine/payload_gen.py — payload generation and evasion transforms.
"""

import pytest

from stingxss.engine.analysis.payload_gen import (
    generate,
    make_confirm_marker,
    blind_payloads,
    file_upload_payloads,
    restricted_char_payloads,
    polyglot_payloads,
    waf_bypass_payloads,
    prototype_pollution_payloads,
    classic_legacy_payloads,
    encoding_payloads,
    content_type_payloads,
    css_transition_payloads,
    extra_no_interaction_payloads,
    CONFIRM_MARKER_PREFIX,
)
from stingxss.engine.reporter import ReflectionContext
from stingxss.engine.http.waf_detect import (
    EVASION_NONE,
    EVASION_CASE_MIXING,
    EVASION_HTML_ENCODE,
    EVASION_UNICODE,
    EVASION_DOUBLE_ENCODE,
    EVASION_CHUNKED_TAGS,
    EVASION_NULL_BYTE,
    EVASION_NEWLINE,
    EVASION_COMMENT_BREAK,
    EVASION_BACKTICK,
    EVASION_CSS_EXPR,
)


class TestMakeConfirmMarker:
    def test_has_prefix(self):
        m = make_confirm_marker()
        assert m.startswith(CONFIRM_MARKER_PREFIX)

    def test_unique(self):
        markers = {make_confirm_marker() for _ in range(50)}
        assert len(markers) == 50


class TestGenerate:
    def test_returns_list(self):
        payloads = generate(ReflectionContext.HTML_BODY)
        assert isinstance(payloads, list)
        assert len(payloads) > 0

    def test_level_limits_payloads(self):
        p1 = generate(ReflectionContext.HTML_BODY, level=1)
        p2 = generate(ReflectionContext.HTML_BODY, level=2)
        p3 = generate(ReflectionContext.HTML_BODY, level=3)
        assert len(p1) <= len(p2) <= len(p3)
        assert len(p1) <= 3

    def test_marker_embedded(self):
        marker = "TESTMARKER123"
        payloads = generate(ReflectionContext.HTML_BODY, marker=marker, level=3)
        for p in payloads:
            assert marker in p

    def test_no_duplicates(self):
        payloads = generate(ReflectionContext.HTML_BODY, level=3)
        assert len(payloads) == len(set(payloads))

    def test_custom_payloads_appended(self):
        custom = ["<custom>payload</custom>"]
        payloads = generate(ReflectionContext.HTML_BODY, custom_payloads=custom)
        assert "<custom>payload</custom>" in payloads

    @pytest.mark.parametrize("ctx", list(ReflectionContext))
    def test_all_contexts_return_payloads(self, ctx):
        payloads = generate(ctx)
        assert len(payloads) > 0

    def test_evasion_produces_more_payloads(self):
        base = generate(ReflectionContext.HTML_BODY, evasion=EVASION_NONE, level=3)
        evaded = generate(ReflectionContext.HTML_BODY, evasion=EVASION_CASE_MIXING, level=3)
        # Evasion adds a transformed variant alongside original
        assert len(evaded) >= len(base)

    def test_script_context_payloads_do_not_start_with_angle_bracket(self):
        """Script-context payloads should break out of strings, not inject tags."""
        payloads = generate(ReflectionContext.SCRIPT_STRING_D, level=1)
        # At least one payload starts with a quote character (breakout)
        assert any(p.startswith('"') or p.startswith("'") for p in payloads)


class TestBlindPayloads:
    def test_returns_list(self):
        result = blind_payloads("https://callback.example.com")
        assert isinstance(result, list)
        assert len(result) >= 4

    def test_callback_url_in_payload(self):
        cb = "https://callback.example.com"
        for p in blind_payloads(cb):
            assert cb in p

    def test_trailing_slash_stripped(self):
        cb = "https://callback.example.com/"
        cb_clean = "https://callback.example.com"
        for p in blind_payloads(cb):
            assert cb_clean in p


class TestEvasionTransforms:
    """Smoke-test each evasion strategy via generate()."""

    @pytest.mark.parametrize("evasion", [
        EVASION_CASE_MIXING,
        EVASION_HTML_ENCODE,
        EVASION_UNICODE,
        EVASION_DOUBLE_ENCODE,
        EVASION_CHUNKED_TAGS,
        EVASION_NULL_BYTE,
        EVASION_NEWLINE,
        EVASION_COMMENT_BREAK,
        EVASION_BACKTICK,
        EVASION_CSS_EXPR,
    ])
    def test_evasion_does_not_crash(self, evasion):
        payloads = generate(ReflectionContext.HTML_BODY, evasion=evasion, level=2)
        assert isinstance(payloads, list)
        assert len(payloads) > 0


class TestFiringRangePayloads:
    """
    Verify that the payload lists contain the vectors needed to detect each
    class of injection from https://public-firing-range.appspot.com/tags/
    """

    def test_html_body_contains_meta_redirect(self):
        """META tag endpoint: only <meta> tags accepted."""
        payloads = generate(ReflectionContext.HTML_BODY, level=3)
        assert any("<meta" in p and "javascript" in p for p in payloads)

    def test_html_body_contains_div_event_handler(self):
        """DIV tag endpoint: only <div> tags accepted."""
        payloads = generate(ReflectionContext.HTML_BODY, level=3)
        assert any("<div" in p and "on" in p for p in payloads)

    def test_html_body_contains_body_child_payload(self):
        """BODY/ONLOAD endpoint: strips onload but passes inner content."""
        payloads = generate(ReflectionContext.HTML_BODY, level=3)
        assert any("<body>" in p and "<img" in p for p in payloads)

    def test_html_body_contains_multiline_payload(self):
        """Multiline endpoint: single-line regex bypassed with newline prefix."""
        payloads = generate(ReflectionContext.HTML_BODY, level=3)
        assert any(p.startswith("\n") for p in payloads)

    def test_url_attr_contains_javascript_proto(self):
        """HREF-A endpoint: <a href=...> must accept javascript: protocol."""
        payloads = generate(ReflectionContext.URL_ATTR, level=3)
        assert any("javascript:alert" in p for p in payloads)

    def test_url_attr_contains_attacker_url(self):
        """SCRIPT-SRC endpoint: javascript: doesn't work for script src."""
        payloads = generate(ReflectionContext.URL_ATTR, level=3)
        assert any("attacker.example" in p or "//" in p for p in payloads)

    def test_attr_double_contains_expression(self):
        """DIV-STYLE / HREF-STYLE endpoints: only style= attr accepted, IE expression."""
        payloads = generate(ReflectionContext.ATTR_DOUBLE, level=3)
        assert any("expression(" in p for p in payloads)

    def test_css_payloads_contain_expression(self):
        """STYLE tag endpoint: expression() works in IE CSS context."""
        payloads = generate(ReflectionContext.CSS, level=3)
        assert any("expression(" in p for p in payloads)

    def test_css_expression_evasion_breaks_keyword(self):
        """Expression endpoint: filters 'expression', needs ex/**/pression variant."""
        payloads = generate(ReflectionContext.CSS, evasion=EVASION_CSS_EXPR, level=3)
        assert any("ex/**/pression" in p for p in payloads)

    def test_css_expression_evasion_does_not_crash(self):
        payloads = generate(ReflectionContext.CSS, evasion=EVASION_CSS_EXPR, level=3)
        assert len(payloads) > 0


# ---------------------------------------------------------------------------
# Firing Range /badscriptimport/ — SCRIPT_SRC payloads
# ---------------------------------------------------------------------------

class TestScriptSrcPayloads:
    """
    Google Firing Range /remoteinclude/parameter/script cases.
    The scanner must generate payloads that either:
    (a) supply an attacker-controlled URL to load as script, or
    (b) break out of the src attribute and inject inline script.
    """

    def test_script_src_payloads_generated(self):
        payloads = generate(ReflectionContext.SCRIPT_SRC, level=3)
        assert len(payloads) > 0

    def test_script_src_contains_attacker_url(self):
        """At least one payload must be a URL pointing to an attacker host."""
        payloads = generate(ReflectionContext.SCRIPT_SRC, level=3)
        assert any("attacker.example" in p or "//" in p for p in payloads)

    def test_script_src_contains_breakout_payload(self):
        """At least one payload must break out of the src attribute."""
        payloads = generate(ReflectionContext.SCRIPT_SRC, level=3)
        assert any("<script>" in p.lower() for p in payloads)

    def test_script_src_marker_embedded(self):
        """Every payload must contain the confirmation marker."""
        marker = make_confirm_marker()
        payloads = generate(ReflectionContext.SCRIPT_SRC, marker=marker, level=3)
        for p in payloads:
            assert marker in p, f"Marker missing from payload: {p}"

    def test_script_src_level1_returns_payloads(self):
        payloads = generate(ReflectionContext.SCRIPT_SRC, level=1)
        assert len(payloads) >= 1


# ---------------------------------------------------------------------------
# New payloads from PortSwigger XSS cheat sheet
# ---------------------------------------------------------------------------

class TestNewNoInteractionPayloads:
    """
    Verify the new no-interaction vectors added from the PortSwigger cheat sheet
    are present in the HTML_BODY and ATTR context payload lists.
    """

    def test_html_body_contains_svg_animate_onbegin(self):
        payloads = generate(ReflectionContext.HTML_BODY, level=3)
        assert any("onbegin" in p and "<animate" in p for p in payloads)

    def test_html_body_contains_svg_animate_onend(self):
        payloads = generate(ReflectionContext.HTML_BODY, level=3)
        assert any("onend" in p and "<animate" in p for p in payloads)

    def test_html_body_contains_svg_animate_onrepeat(self):
        payloads = generate(ReflectionContext.HTML_BODY, level=3)
        assert any("onrepeat" in p for p in payloads)

    def test_html_body_contains_css_animation_onanimationend(self):
        payloads = generate(ReflectionContext.HTML_BODY, level=3)
        assert any("onanimationend" in p for p in payloads)

    def test_html_body_contains_css_animation_onanimationstart(self):
        payloads = generate(ReflectionContext.HTML_BODY, level=3)
        assert any("onanimationstart" in p for p in payloads)

    def test_html_body_contains_content_visibility_auto(self):
        payloads = generate(ReflectionContext.HTML_BODY, level=3)
        assert any("oncontentvisibilityautostatechange" in p for p in payloads)

    def test_html_body_contains_hidden_input_content_visibility(self):
        payloads = generate(ReflectionContext.HTML_BODY, level=3)
        assert any(
            "oncontentvisibilityautostatechange" in p and "input" in p
            for p in payloads
        )

    def test_html_body_contains_autofocus_onfocus(self):
        payloads = generate(ReflectionContext.HTML_BODY, level=3)
        assert any("autofocus" in p and "onfocus" in p for p in payloads)

    def test_html_body_contains_onpageshow(self):
        payloads = generate(ReflectionContext.HTML_BODY, level=3)
        assert any("onpageshow" in p for p in payloads)

    def test_html_body_contains_audio_onerror(self):
        payloads = generate(ReflectionContext.HTML_BODY, level=3)
        assert any("<audio" in p and "onerror" in p for p in payloads)

    def test_html_body_contains_video_onloadstart(self):
        payloads = generate(ReflectionContext.HTML_BODY, level=3)
        assert any("<video" in p and "onloadstart" in p for p in payloads)

    # ATTR_DOUBLE
    def test_attr_double_contains_svg_animate(self):
        payloads = generate(ReflectionContext.ATTR_DOUBLE, level=3)
        assert any("onbegin" in p and "animate" in p for p in payloads)

    def test_attr_double_contains_css_animation(self):
        payloads = generate(ReflectionContext.ATTR_DOUBLE, level=3)
        assert any("onanimationend" in p for p in payloads)

    def test_attr_double_contains_content_visibility(self):
        payloads = generate(ReflectionContext.ATTR_DOUBLE, level=3)
        assert any("oncontentvisibilityautostatechange" in p for p in payloads)

    def test_attr_double_contains_autofocus_onfocus(self):
        payloads = generate(ReflectionContext.ATTR_DOUBLE, level=3)
        assert any("autofocus" in p and "onfocus" in p for p in payloads)

    # ATTR_SINGLE
    def test_attr_single_contains_svg_animate(self):
        payloads = generate(ReflectionContext.ATTR_SINGLE, level=3)
        assert any("onbegin" in p and "animate" in p for p in payloads)

    def test_attr_single_contains_content_visibility(self):
        payloads = generate(ReflectionContext.ATTR_SINGLE, level=3)
        assert any("oncontentvisibilityautostatechange" in p for p in payloads)

    def test_attr_single_contains_autofocus_onfocus(self):
        payloads = generate(ReflectionContext.ATTR_SINGLE, level=3)
        assert any("autofocus" in p and "onfocus" in p for p in payloads)

    # ATTR_UNQUOTED
    def test_attr_unquoted_contains_svg_animate(self):
        payloads = generate(ReflectionContext.ATTR_UNQUOTED, level=3)
        assert any("onbegin" in p and "animate" in p for p in payloads)

    def test_attr_unquoted_contains_content_visibility(self):
        payloads = generate(ReflectionContext.ATTR_UNQUOTED, level=3)
        assert any("oncontentvisibilityautostatechange" in p for p in payloads)


class TestNewBlindPayloads:
    """Verify new blind payload vectors phone home and cover new event types."""

    CB = "https://callback.example.com"

    def test_blind_payloads_count_increased(self):
        assert len(blind_payloads(self.CB)) >= 10

    def test_blind_contains_svg_animate_onend(self):
        payloads = blind_payloads(self.CB)
        assert any("onend" in p and "animate" in p for p in payloads)

    def test_blind_contains_content_visibility(self):
        payloads = blind_payloads(self.CB)
        assert any("oncontentvisibilityautostatechange" in p for p in payloads)

    def test_blind_contains_css_animation(self):
        payloads = blind_payloads(self.CB)
        assert any("onanimationend" in p for p in payloads)

    def test_blind_contains_autofocus_onfocus(self):
        payloads = blind_payloads(self.CB)
        assert any("autofocus" in p and "onfocus" in p for p in payloads)

    def test_all_new_blind_payloads_contain_callback_url(self):
        cb = "https://myhost.example"
        for p in blind_payloads(cb):
            assert cb in p


# ---------------------------------------------------------------------------
# #1 — CSS transition & webkit animation events
# ---------------------------------------------------------------------------

class TestCssTransitionPayloads:
    def test_returns_list(self):
        result = css_transition_payloads()
        assert isinstance(result, list)
        assert len(result) > 0

    def test_marker_embedded(self):
        marker = "CSSTEST"
        for p in css_transition_payloads(marker=marker):
            assert marker in p

    def test_contains_ontransitionend(self):
        payloads = css_transition_payloads()
        assert any("ontransitionend" in p for p in payloads)

    def test_contains_ontransitionrun(self):
        payloads = css_transition_payloads()
        assert any("ontransitionrun" in p for p in payloads)

    def test_contains_ontransitionstart(self):
        payloads = css_transition_payloads()
        assert any("ontransitionstart" in p for p in payloads)

    def test_contains_onwebkitanimationend(self):
        payloads = css_transition_payloads()
        assert any("onwebkitanimationend" in p for p in payloads)

    def test_contains_onwebkitanimationstart(self):
        payloads = css_transition_payloads()
        assert any("onwebkitanimationstart" in p for p in payloads)

    def test_contains_onwebkitanimationiteration(self):
        payloads = css_transition_payloads()
        assert any("onwebkitanimationiteration" in p for p in payloads)

    def test_contains_onanimationiteration(self):
        payloads = css_transition_payloads()
        assert any("onanimationiteration" in p for p in payloads)

    def test_contains_onanimationcancel(self):
        payloads = css_transition_payloads()
        assert any("onanimationcancel" in p for p in payloads)

    def test_contains_onwebkittransitionend(self):
        payloads = css_transition_payloads()
        assert any("onwebkittransitionend" in p for p in payloads)

    def test_no_duplicates(self):
        payloads = css_transition_payloads()
        assert len(payloads) == len(set(payloads))


# ---------------------------------------------------------------------------
# #2 — Additional no-interaction events
# ---------------------------------------------------------------------------

class TestExtraNoInteractionPayloads:
    def test_returns_list(self):
        result = extra_no_interaction_payloads()
        assert isinstance(result, list)
        assert len(result) > 0

    def test_marker_embedded(self):
        marker = "NOINTER"
        for p in extra_no_interaction_payloads(marker=marker):
            assert marker in p

    def test_contains_onbeforematch(self):
        payloads = extra_no_interaction_payloads()
        assert any("onbeforematch" in p for p in payloads)

    def test_contains_onscrollend(self):
        payloads = extra_no_interaction_payloads()
        assert any("onscrollend" in p for p in payloads)

    def test_contains_onscrollsnapchange(self):
        payloads = extra_no_interaction_payloads()
        assert any("onscrollsnapchange" in p for p in payloads)

    def test_contains_ontimeupdate(self):
        payloads = extra_no_interaction_payloads()
        assert any("ontimeupdate" in p for p in payloads)

    def test_contains_onwaiting(self):
        payloads = extra_no_interaction_payloads()
        assert any("onwaiting" in p for p in payloads)

    def test_contains_onsuspend(self):
        payloads = extra_no_interaction_payloads()
        assert any("onsuspend" in p for p in payloads)

    def test_contains_onunhandledrejection(self):
        payloads = extra_no_interaction_payloads()
        assert any("onunhandledrejection" in p for p in payloads)

    def test_contains_onsecuritypolicyviolation(self):
        payloads = extra_no_interaction_payloads()
        assert any("onsecuritypolicyviolation" in p for p in payloads)

    def test_contains_onpagereveal(self):
        payloads = extra_no_interaction_payloads()
        assert any("onpagereveal" in p for p in payloads)

    def test_contains_onslotchange(self):
        payloads = extra_no_interaction_payloads()
        assert any("onslotchange" in p for p in payloads)


# ---------------------------------------------------------------------------
# #3 — JS hoisting / window.name context
# ---------------------------------------------------------------------------

class TestJsHoistingContext:
    def test_generate_returns_payloads(self):
        payloads = generate(ReflectionContext.JS_HOISTING, level=3)
        assert len(payloads) > 0

    def test_marker_embedded(self):
        marker = "HOIST42"
        payloads = generate(ReflectionContext.JS_HOISTING, marker=marker, level=3)
        for p in payloads:
            assert marker in p

    def test_contains_alert(self):
        payloads = generate(ReflectionContext.JS_HOISTING, level=3)
        assert any("alert" in p for p in payloads)

    def test_contains_constructor_chain(self):
        payloads = generate(ReflectionContext.JS_HOISTING, level=3)
        assert any("constructor" in p for p in payloads)


# ---------------------------------------------------------------------------
# #4 — File upload payloads
# ---------------------------------------------------------------------------

class TestFileUploadPayloads:
    def test_returns_list(self):
        result = file_upload_payloads()
        assert isinstance(result, list)
        assert len(result) > 0

    def test_marker_embedded(self):
        marker = "UPLOAD1"
        for p in file_upload_payloads(marker=marker):
            assert marker in p

    def test_contains_svg_onload(self):
        payloads = file_upload_payloads()
        assert any("<svg" in p and "onload" in p for p in payloads)

    def test_contains_svg_script(self):
        payloads = file_upload_payloads()
        assert any("<svg" in p and "<script>" in p for p in payloads)

    def test_contains_svg_animate_onbegin(self):
        payloads = file_upload_payloads()
        assert any("onbegin" in p for p in payloads)

    def test_contains_html_script(self):
        payloads = file_upload_payloads()
        assert any("<script>" in p and "svg" not in p for p in payloads)

    def test_contains_xhtml_polyglot(self):
        payloads = file_upload_payloads()
        assert any("xhtml" in p.lower() for p in payloads)


# ---------------------------------------------------------------------------
# #5 — Restricted characters bypass
# ---------------------------------------------------------------------------

class TestRestrictedCharPayloads:
    def test_returns_list(self):
        result = restricted_char_payloads()
        assert isinstance(result, list)
        assert len(result) > 0

    def test_marker_embedded(self):
        marker = "RESTR1"
        for p in restricted_char_payloads(marker=marker):
            assert marker in p

    def test_contains_backtick_call(self):
        payloads = restricted_char_payloads()
        assert any("alert`" in p for p in payloads)

    def test_contains_throw_trick(self):
        payloads = restricted_char_payloads()
        assert any("throw" in p for p in payloads)

    def test_contains_onerror_assignment(self):
        payloads = restricted_char_payloads()
        assert any("onerror=alert" in p for p in payloads)

    def test_contains_no_space_svg_slash(self):
        payloads = restricted_char_payloads()
        assert any("<svg/" in p for p in payloads)

    def test_contains_tab_separator(self):
        payloads = restricted_char_payloads()
        assert any("\t" in p for p in payloads)

    def test_contains_html_entity_encoded_parens(self):
        payloads = restricted_char_payloads()
        assert any("&#x" in p for p in payloads)


# ---------------------------------------------------------------------------
# #6 — VueJS CSTI
# ---------------------------------------------------------------------------

class TestVueTemplateContext:
    def test_generate_returns_payloads(self):
        payloads = generate(ReflectionContext.VUE_TEMPLATE, level=3)
        assert len(payloads) > 0

    def test_marker_embedded(self):
        marker = "VUE123"
        payloads = generate(ReflectionContext.VUE_TEMPLATE, marker=marker, level=3)
        for p in payloads:
            assert marker in p

    def test_contains_constructor_chain(self):
        payloads = generate(ReflectionContext.VUE_TEMPLATE, level=3)
        assert any("constructor" in p for p in payloads)

    def test_contains_vue2_c_shorthand(self):
        payloads = generate(ReflectionContext.VUE_TEMPLATE, level=3)
        assert any("_c" in p for p in payloads)

    def test_contains_vue3_nexttick(self):
        payloads = generate(ReflectionContext.VUE_TEMPLATE, level=3)
        assert any("$nextTick" in p for p in payloads)

    def test_contains_double_braces(self):
        payloads = generate(ReflectionContext.VUE_TEMPLATE, level=3)
        assert any("{{" in p for p in payloads)


# ---------------------------------------------------------------------------
# #7 — Dangling markup / scriptless attacks
# ---------------------------------------------------------------------------

class TestDanglingMarkupContext:
    def test_generate_returns_payloads(self):
        payloads = generate(ReflectionContext.DANGLING_MARKUP, level=3)
        assert len(payloads) > 0

    def test_contains_open_img_src(self):
        payloads = generate(ReflectionContext.DANGLING_MARKUP, level=3)
        assert any("<img src=" in p and "attacker" in p for p in payloads)

    def test_contains_open_form_action(self):
        payloads = generate(ReflectionContext.DANGLING_MARKUP, level=3)
        assert any("<form" in p and "action" in p for p in payloads)

    def test_contains_base_tag_hijack(self):
        payloads = generate(ReflectionContext.DANGLING_MARKUP, level=3)
        assert any("<base" in p for p in payloads)

    def test_contains_meta_refresh(self):
        payloads = generate(ReflectionContext.DANGLING_MARKUP, level=3)
        assert any("<meta" in p and "refresh" in p for p in payloads)


# ---------------------------------------------------------------------------
# #8 — Polyglots
# ---------------------------------------------------------------------------

class TestPolyglotPayloads:
    def test_returns_list(self):
        result = polyglot_payloads()
        assert isinstance(result, list)
        assert len(result) > 0

    def test_marker_embedded(self):
        marker = "POLY99"
        for p in polyglot_payloads(marker=marker):
            assert marker in p

    def test_contains_portswigger_classic(self):
        payloads = polyglot_payloads()
        assert any("jaVasCript" in p for p in payloads)

    def test_contains_attr_html_polyglot(self):
        payloads = polyglot_payloads()
        assert any('"><img' in p for p in payloads)

    def test_contains_backtick_polyglot(self):
        payloads = polyglot_payloads()
        assert any("`" in p and "svg" in p for p in payloads)

    def test_no_duplicates(self):
        payloads = polyglot_payloads()
        assert len(payloads) == len(set(payloads))


# ---------------------------------------------------------------------------
# #9 — WAF bypass global object obfuscation
# ---------------------------------------------------------------------------

class TestWafBypassGlobalPayloads:
    def test_returns_list(self):
        result = waf_bypass_payloads()
        assert isinstance(result, list)
        assert len(result) > 0

    def test_marker_embedded(self):
        # Most WAF bypass payloads embed the marker; the static atob payload does not.
        marker = "WAF42"
        payloads = waf_bypass_payloads(marker=marker)
        assert any(marker in p for p in payloads)

    def test_contains_self_concat(self):
        payloads = waf_bypass_payloads()
        assert any("self[" in p and "ale" in p for p in payloads)

    def test_contains_top_regex(self):
        payloads = waf_bypass_payloads()
        assert any("top[" in p and ".source" in p for p in payloads)

    def test_contains_globalthis_hex(self):
        payloads = waf_bypass_payloads()
        assert any("globalThis" in p and "\\x" in p for p in payloads)

    def test_contains_frames_octal(self):
        payloads = waf_bypass_payloads()
        assert any("frames[" in p and "\\1" in p for p in payloads)

    def test_contains_fromcharcode(self):
        payloads = waf_bypass_payloads()
        assert any("fromCharCode" in p for p in payloads)

    def test_contains_constructor_chain(self):
        payloads = waf_bypass_payloads()
        assert any("constructor" in p for p in payloads)


# ---------------------------------------------------------------------------
# #10 — Prototype pollution gadgets
# ---------------------------------------------------------------------------

class TestPrototypePollutionPayloads:
    def test_returns_list(self):
        result = prototype_pollution_payloads()
        assert isinstance(result, list)
        assert len(result) > 0

    def test_marker_embedded(self):
        # Most prototype pollution payloads embed the marker; key-path gadgets do not.
        marker = "PP123"
        payloads = prototype_pollution_payloads(marker=marker)
        assert any(marker in p for p in payloads)

    def test_contains_proto_html(self):
        payloads = prototype_pollution_payloads()
        assert any("__proto__" in p and "html" in p for p in payloads)

    def test_contains_lodash_gadget(self):
        payloads = prototype_pollution_payloads()
        assert any("sourceURL" in p for p in payloads)

    def test_contains_sanitize_html_gadget(self):
        payloads = prototype_pollution_payloads()
        assert any("innerText" in p for p in payloads)

    def test_contains_dompurify_gadget(self):
        payloads = prototype_pollution_payloads()
        assert any("ALLOWED_TAGS" in p for p in payloads)

    def test_contains_knockout_gadget(self):
        payloads = prototype_pollution_payloads()
        assert any("template" in p for p in payloads)


# ---------------------------------------------------------------------------
# #11 — Classic / legacy vectors
# ---------------------------------------------------------------------------

class TestClassicLegacyPayloads:
    def test_returns_list(self):
        result = classic_legacy_payloads()
        assert isinstance(result, list)
        assert len(result) > 0

    def test_marker_embedded(self):
        marker = "LEGCY1"
        for p in classic_legacy_payloads(marker=marker):
            assert marker in p

    def test_contains_marquee_onstart(self):
        payloads = classic_legacy_payloads()
        assert any("<marquee" in p and "onstart" in p for p in payloads)

    def test_contains_marquee_onfinish(self):
        payloads = classic_legacy_payloads()
        assert any("<marquee" in p and "onfinish" in p for p in payloads)

    def test_contains_marquee_onbounce(self):
        payloads = classic_legacy_payloads()
        assert any("<marquee" in p and "onbounce" in p for p in payloads)

    def test_contains_svg_discard(self):
        payloads = classic_legacy_payloads()
        assert any("<discard" in p and "onbegin" in p for p in payloads)

    def test_contains_svg_use_href(self):
        payloads = classic_legacy_payloads()
        assert any("<use" in p and "href" in p for p in payloads)

    def test_contains_vbscript(self):
        payloads = classic_legacy_payloads()
        assert any("vbscript" in p for p in payloads)

    def test_contains_null_byte_href(self):
        payloads = classic_legacy_payloads()
        assert any("&#0000" in p for p in payloads)

    def test_contains_webkit_playback(self):
        payloads = classic_legacy_payloads()
        assert any("onwebkitplaybacktargetavailabilitychanged" in p for p in payloads)


# ---------------------------------------------------------------------------
# #12 — Encoding variants
# ---------------------------------------------------------------------------

class TestEncodingPayloads:
    def test_returns_list(self):
        result = encoding_payloads()
        assert isinstance(result, list)
        assert len(result) > 0

    def test_marker_embedded(self):
        marker = "ENC123"
        for p in encoding_payloads(marker=marker):
            assert marker in p

    def test_contains_svg_html_entity_parens(self):
        payloads = encoding_payloads()
        assert any("<svg>" in p and "&lpar;" in p for p in payloads)

    def test_contains_decimal_entities_javascript(self):
        payloads = encoding_payloads()
        assert any("&#106;" in p or "&#x6A;" in p for p in payloads)

    def test_contains_unicode_escape(self):
        payloads = encoding_payloads()
        assert any("\\u00" in p for p in payloads)

    def test_contains_double_url_encode(self):
        payloads = encoding_payloads()
        assert any("%253C" in p for p in payloads)

    def test_contains_utf7(self):
        payloads = encoding_payloads()
        assert any("+ADw-" in p for p in payloads)

    def test_contains_html_entity_angle_brackets(self):
        payloads = encoding_payloads()
        assert any("&lt;script&gt;" in p for p in payloads)


# ---------------------------------------------------------------------------
# #13 — Content-type / response header vectors
# ---------------------------------------------------------------------------

class TestContentTypePayloads:
    def test_returns_list(self):
        result = content_type_payloads()
        assert isinstance(result, list)
        assert len(result) > 0

    def test_marker_embedded(self):
        marker = "CT123"
        for p in content_type_payloads(marker=marker):
            assert marker in p

    def test_contains_svg_response(self):
        payloads = content_type_payloads()
        assert any("<svg" in p and "onload" in p for p in payloads)

    def test_contains_xhtml_response(self):
        payloads = content_type_payloads()
        assert any("xhtml" in p.lower() and "<script>" in p for p in payloads)

    def test_contains_xsl_response(self):
        payloads = content_type_payloads()
        assert any("xsl:" in p.lower() for p in payloads)

    def test_contains_cdata_xss(self):
        payloads = content_type_payloads()
        assert any("CDATA" in p for p in payloads)

    def test_no_duplicates(self):
        payloads = content_type_payloads()
        assert len(payloads) == len(set(payloads))


# ---------------------------------------------------------------------------
# Cross-cutting: all new contexts included in all_contexts parametric test
# ---------------------------------------------------------------------------

class TestNewContextsInAllContexts:
    """Ensure the parametric test_all_contexts_return_payloads covers new contexts."""

    @pytest.mark.parametrize("ctx", [
        ReflectionContext.VUE_TEMPLATE,
        ReflectionContext.JS_HOISTING,
        ReflectionContext.DANGLING_MARKUP,
    ])
    def test_new_contexts_return_payloads(self, ctx):
        payloads = generate(ctx, level=3)
        assert len(payloads) > 0

    @pytest.mark.parametrize("ctx", [
        ReflectionContext.VUE_TEMPLATE,
        ReflectionContext.JS_HOISTING,
    ])
    def test_new_contexts_embed_marker(self, ctx):
        # DANGLING_MARKUP payloads are intentionally open-ended (no marker slot)
        marker = "NEWCTX"
        payloads = generate(ctx, marker=marker, level=3)
        for p in payloads:
            assert marker in p
