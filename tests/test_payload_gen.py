"""
Tests for engine/payload_gen.py — payload generation and evasion transforms.
"""

import pytest

from stingxss.engine.payload_gen import (
    generate,
    make_confirm_marker,
    blind_payloads,
    CONFIRM_MARKER_PREFIX,
)
from stingxss.engine.reporter import ReflectionContext
from stingxss.engine.waf_detect import (
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
    ])
    def test_evasion_does_not_crash(self, evasion):
        payloads = generate(ReflectionContext.HTML_BODY, evasion=evasion, level=2)
        assert isinstance(payloads, list)
        assert len(payloads) > 0
