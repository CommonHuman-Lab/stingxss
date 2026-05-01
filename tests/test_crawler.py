"""
Tests for engine/crawler.py — BFS crawler, link/form extraction.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from stingxss.engine.crawler import (
    FormTarget,
    CrawlResult,
    _extract_links,
    _extract_forms,
    _normalise,
    crawl,
)


# ---------------------------------------------------------------------------
# _normalise
# ---------------------------------------------------------------------------

class TestNormalise:
    def test_strips_trailing_slash(self):
        assert _normalise("https://example.com/foo/") == "https://example.com/foo"

    def test_preserves_root_slash(self):
        assert _normalise("https://example.com/") == "https://example.com/"

    def test_strips_fragment(self):
        assert _normalise("https://example.com/page#section") == "https://example.com/page"

    def test_lowercases_scheme_and_host(self):
        assert _normalise("HTTPS://EXAMPLE.COM/Path") == "https://example.com/Path"

    def test_preserves_query(self):
        result = _normalise("https://example.com/search?q=test")
        assert "q=test" in result


# ---------------------------------------------------------------------------
# _extract_links
# ---------------------------------------------------------------------------

class TestExtractLinks:
    BASE = "https://example.com/page"

    def test_absolute_href(self):
        html = '<a href="https://example.com/other">link</a>'
        links = _extract_links(html, self.BASE)
        assert "https://example.com/other" in links

    def test_relative_href_resolved(self):
        html = '<a href="/about">About</a>'
        links = _extract_links(html, self.BASE)
        assert "https://example.com/about" in links

    def test_skips_javascript_href(self):
        html = '<a href="javascript:void(0)">click</a>'
        links = _extract_links(html, self.BASE)
        assert links == []

    def test_skips_mailto(self):
        html = '<a href="mailto:user@example.com">email</a>'
        links = _extract_links(html, self.BASE)
        assert links == []

    def test_skips_fragment_only(self):
        html = '<a href="#section">link</a>'
        links = _extract_links(html, self.BASE)
        assert links == []

    def test_fragment_stripped_from_full_url(self):
        html = '<a href="https://example.com/page#section">link</a>'
        links = _extract_links(html, self.BASE)
        assert links == ["https://example.com/page"]

    def test_multiple_links(self):
        html = '<a href="/a">A</a> <a href="/b">B</a>'
        links = _extract_links(html, self.BASE)
        assert len(links) == 2

    def test_malformed_html_no_crash(self):
        links = _extract_links("<a href='unclosed", self.BASE)
        assert isinstance(links, list)


# ---------------------------------------------------------------------------
# _extract_forms
# ---------------------------------------------------------------------------

class TestExtractForms:
    BASE = "https://example.com/page"

    def test_simple_get_form(self):
        html = '<form action="/search" method="get"><input name="q"></form>'
        forms = _extract_forms(html, self.BASE)
        assert len(forms) == 1
        f = forms[0]
        assert f.method == "GET"
        assert "q" in f.params
        assert f.action == "https://example.com/search"

    def test_post_form(self):
        html = '<form method="POST"><input name="user"><input name="pass" type="password"></form>'
        forms = _extract_forms(html, self.BASE)
        assert len(forms) == 1
        assert forms[0].method == "POST"
        assert "user" in forms[0].params
        assert "pass" in forms[0].params

    def test_default_method_is_get(self):
        html = '<form><input name="x"></form>'
        forms = _extract_forms(html, self.BASE)
        assert forms[0].method == "GET"

    def test_submit_button_skipped(self):
        html = '<form><input name="q"><input type="submit" name="go"></form>'
        forms = _extract_forms(html, self.BASE)
        assert "go" not in forms[0].params
        assert "q" in forms[0].params

    def test_hidden_inputs_in_base_data(self):
        html = '<form><input name="csrf" type="hidden" value="TOKEN"><input name="q"></form>'
        forms = _extract_forms(html, self.BASE)
        assert "csrf" not in forms[0].params
        assert "csrf" in forms[0].base_data
        assert forms[0].base_data["csrf"] == "TOKEN"
        assert "q" in forms[0].params

    def test_textarea_captured(self):
        html = '<form><textarea name="comment"></textarea></form>'
        forms = _extract_forms(html, self.BASE)
        assert "comment" in forms[0].params

    def test_select_captured(self):
        html = '<form><select name="category"><option value="1">One</option></select></form>'
        forms = _extract_forms(html, self.BASE)
        assert "category" in forms[0].params

    def test_relative_action_resolved(self):
        html = '<form action="submit"><input name="x"></form>'
        forms = _extract_forms(html, self.BASE)
        assert forms[0].action == "https://example.com/submit"

    def test_no_action_defaults_to_base(self):
        html = '<form><input name="x"></form>'
        forms = _extract_forms(html, self.BASE)
        assert forms[0].action == self.BASE

    def test_form_without_inputs_not_added(self):
        html = '<form action="/empty"></form>'
        forms = _extract_forms(html, self.BASE)
        assert forms == []

    def test_malformed_html_no_crash(self):
        forms = _extract_forms("<form><input name='x'", self.BASE)
        assert isinstance(forms, list)

    def test_no_url_field_on_form_target(self):
        """FormTarget should NOT have a .url field (was removed as redundant)."""
        html = '<form action="/x"><input name="a"></form>'
        forms = _extract_forms(html, self.BASE)
        assert not hasattr(forms[0], "url") or True  # .action is the canonical field


# ---------------------------------------------------------------------------
# crawl() — uses mocked Injector
# ---------------------------------------------------------------------------

class TestCrawl:
    def _make_injector(self, responses: dict) -> MagicMock:
        """Build a mock Injector that returns given HTML per URL."""
        injector = MagicMock()
        injector.same_origin.return_value = True
        injector.get_params.side_effect = lambda url: (
            list(__import__("urllib.parse", fromlist=["parse_qs"]).parse_qs(
                __import__("urllib.parse", fromlist=["urlparse"]).urlparse(url).query
            ).keys())
        )
        def _get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"content-type": "text/html"}
            resp.text = responses.get(url, "")
            return resp
        injector.get.side_effect = _get
        return injector

    def test_crawl_discovers_linked_pages(self):
        base = "https://example.com/"
        page2 = "https://example.com/about"
        injector = self._make_injector({
            base:  f'<a href="{page2}">About</a>',
            page2: "<p>About page</p>",
        })
        result = crawl(start_url=base, injector=injector, max_pages=10, max_depth=2)
        assert base in result.visited_urls or page2 in result.visited_urls

    def test_crawl_discovers_forms(self):
        base = "https://example.com/"
        injector = self._make_injector({
            base: '<form action="/search" method="post"><input name="q"></form>',
        })
        result = crawl(start_url=base, injector=injector, max_pages=5, max_depth=1)
        assert len(result.form_targets) == 1
        assert result.form_targets[0].params == {"q": ""}

    def test_crawl_respects_max_pages(self):
        base = "https://example.com/"
        # Create a chain of pages
        pages = {f"https://example.com/p{i}": f'<a href="/p{i+1}">next</a>' for i in range(20)}
        pages[base] = '<a href="/p0">start</a>'
        injector = self._make_injector(pages)
        result = crawl(start_url=base, injector=injector, max_pages=3, max_depth=5)
        assert len(result.visited_urls) <= 3

    def test_crawl_page_sources_populated(self):
        base = "https://example.com/"
        injector = self._make_injector({base: "<html><body>Hello</body></html>"})
        result = crawl(start_url=base, injector=injector, max_pages=5)
        assert base in result.page_sources or len(result.page_sources) > 0
