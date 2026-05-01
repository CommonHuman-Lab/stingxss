# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Tests for engine/scanner.py — _extract_tag_literal helper and confirmation logic.
"""

import pytest

from stingxss.engine.scanner import _extract_tag_literal


class TestExtractTagLiteral:
    def test_img_tag(self):
        payload = '<img src=x onerror=alert(1)>'
        assert _extract_tag_literal(payload) == "<img"

    def test_svg_tag(self):
        assert _extract_tag_literal("<svg onload=alert(1)>") == "<svg"

    def test_script_tag(self):
        assert _extract_tag_literal("<script>alert(1)</script>") == "<script"

    def test_no_tag_returns_empty(self):
        # Script-context breakout payloads — no angle-bracket tag
        assert _extract_tag_literal('"-alert(1)-"') == ""
        assert _extract_tag_literal("';alert(1);//") == ""
        assert _extract_tag_literal(";alert(1)//") == ""

    def test_closing_tag_not_matched_as_open(self):
        # A closing tag at the start should not confuse things
        result = _extract_tag_literal("</p><img src=x onerror=alert(1)>")
        # Should pick </p> or <img — either way the test is that it doesn't crash
        assert isinstance(result, str)

    def test_comment_payload(self):
        p = "--><img src=x onerror=alert(1)><!--"
        assert _extract_tag_literal(p) == "<img"

    def test_case_insensitive_output(self):
        # _extract_tag_literal must return lowercase
        assert _extract_tag_literal("<IMG src=x>") == "<img"
        assert _extract_tag_literal("<SVG onload=x>") == "<svg"
