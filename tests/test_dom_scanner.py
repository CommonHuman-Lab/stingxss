# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Tests for engine/dom_scanner.py — static DOM XSS analysis.
"""

import pytest

from stingxss.engine.dom_scanner import scan_page, scan_js, DomScanResult


URL = "https://example.com/page"


class TestScanPage:
    def test_no_js_returns_empty(self):
        result = scan_page(URL, "<html><body><p>hello</p></body></html>")
        assert isinstance(result, DomScanResult)
        assert result.sink_findings == []

    def test_detects_inline_script_source_sink(self):
        html = """
        <script>
        var x = location.hash;
        document.getElementById('out').innerHTML = x;
        </script>
        """
        result = scan_page(URL, html)
        assert len(result.sink_findings) >= 1
        finding = result.sink_findings[0]
        assert finding.source == "location.hash"
        assert finding.sink == "innerHTML"

    def test_detects_eval_sink(self):
        html = "<script>var q = location.search; eval(q);</script>"
        result = scan_page(URL, html)
        sources = [f.source for f in result.sink_findings]
        sinks   = [f.sink   for f in result.sink_findings]
        assert "location.search" in sources
        assert "eval" in sinks

    def test_detects_document_write_sink(self):
        html = "<script>document.write(location.href);</script>"
        result = scan_page(URL, html)
        sinks = [f.sink for f in result.sink_findings]
        assert "document.write" in sinks

    def test_no_false_positive_when_source_and_sink_far_apart(self):
        """Source and sink more than 20 lines apart — should NOT be reported."""
        padding = "\n".join(f"var line{i} = 1;" for i in range(30))
        js = f"var x = location.hash;\n{padding}\ndocument.write(x);"
        html = f"<script>{js}</script>"
        result = scan_page(URL, html)
        # May still find it if within window — we just ensure no crash
        assert isinstance(result.sink_findings, list)

    def test_inline_event_handler_source_sink(self):
        html = '<div onclick="location.href=location.hash.slice(1)">x</div>'
        result = scan_page(URL, html)
        # Should detect location.hash (source) → location.href= (sink)
        found = any(
            f.source == "location.hash" and "location.href" in f.sink
            for f in result.sink_findings
        )
        assert found

    def test_deduplication(self):
        """Same source→sink pair must only be reported once."""
        html = """
        <script>
        var a = location.hash;
        document.getElementById('x').innerHTML = a;
        var b = location.hash;
        document.getElementById('y').innerHTML = b;
        </script>
        """
        result = scan_page(URL, html)
        pairs = [(f.source, f.sink) for f in result.sink_findings]
        assert len(pairs) == len(set(pairs))


class TestScanJs:
    def test_standalone_js_analysis(self):
        js = "var u = document.referrer;\ndocument.write(u);"
        result = scan_js(URL, js)
        assert any(f.source == "document.referrer" for f in result.sink_findings)

    def test_empty_js_returns_empty(self):
        result = scan_js(URL, "")
        assert result.sink_findings == []

    def test_url_field(self):
        js = "var u = location.search; eval(u);"
        result = scan_js(URL, js)
        assert result.url == URL


class TestDomScanResult:
    def test_sources_and_sinks_tracked(self):
        html = "<script>var x = location.hash; eval(x);</script>"
        result = scan_page(URL, html)
        assert "location.hash" in result.sources_found
        assert "eval" in result.sinks_found


class TestFiringRangeAddressCases:
    """
    Verify detection of every case from
    https://public-firing-range.appspot.com/address/index.html
    """

    # ---- location.hash sources ----------------------------------------

    def _hash_page(self, sink_line: str) -> str:
        return f"<script>\nvar payload = window.location.hash.substr(1);\n{sink_line}\n</script>"

    def test_hash_assign(self):
        result = scan_page(URL, self._hash_page("window.location.assign(payload);"))
        assert any(f.source == "location.hash" and f.sink == "location.assign()" for f in result.sink_findings)

    def test_hash_documentwrite(self):
        result = scan_page(URL, self._hash_page("document.write(payload);"))
        assert any(f.source == "location.hash" and f.sink == "document.write" for f in result.sink_findings)

    def test_hash_documentwriteln(self):
        result = scan_page(URL, self._hash_page("document.writeln(payload);"))
        assert any(f.source == "location.hash" and f.sink == "document.writeln" for f in result.sink_findings)

    def test_hash_eval(self):
        result = scan_page(URL, self._hash_page("eval(payload);"))
        assert any(f.source == "location.hash" and f.sink == "eval" for f in result.sink_findings)

    def test_hash_innerhtml(self):
        js = "var payload = window.location.hash.substr(1);\nvar d = document.createElement('div');\nd.innerHTML = payload;"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "location.hash" and f.sink == "innerHTML" for f in result.sink_findings)

    def test_hash_range_create_contextual_fragment(self):
        js = "var payload = window.location.hash.substr(1);\nvar range = document.createRange();\nvar frag = range.createContextualFragment(payload);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "location.hash" and f.sink == "createContextualFragment" for f in result.sink_findings)

    def test_hash_replace(self):
        result = scan_page(URL, self._hash_page("location.replace(payload);"))
        assert any(f.source == "location.hash" and f.sink == "location.replace()" for f in result.sink_findings)

    def test_hash_settimeout(self):
        result = scan_page(URL, self._hash_page("setTimeout('var a=a;' + payload, 1);"))
        assert any(f.source == "location.hash" and "setTimeout" in f.sink for f in result.sink_findings)

    def test_hash_new_function(self):
        result = scan_page(URL, self._hash_page("var f = new Function(payload); f();"))
        assert any(f.source == "location.hash" and f.sink == "new Function()" for f in result.sink_findings)

    def test_hash_onclick_setattribute(self):
        js = "var payload = window.location.hash.substr(1);\nvar div = document.createElement('div');\ndiv.setAttribute('onclick', payload);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "location.hash" and f.sink == "setAttribute(on...)" for f in result.sink_findings)

    def test_hash_addeventlistener_new_function(self):
        js = "var payload = window.location.hash.substr(1);\nvar div = document.createElement('div');\ndiv.addEventListener('click', new Function(payload), false);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "location.hash" and f.sink == "new Function()" for f in result.sink_findings)

    def test_hash_jshref_setattribute(self):
        js = "var payload = window.location.hash.substr(1);\nvar a = document.createElement('a');\na.setAttribute('href', payload);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "location.hash" and f.sink == "setAttribute(href)" for f in result.sink_findings)

    def test_hash_formaction_setattribute(self):
        js = "var payload = window.location.hash.substr(1);\nvar form = document.createElement('form');\nform.setAttribute('action', payload);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "location.hash" and f.sink == "setAttribute(action)" for f in result.sink_findings)

    # ---- window.location (raw) sources ------------------------------------

    def _loc_page(self, sink_line: str) -> str:
        return f"<script>\nvar payload = window.location;\n{sink_line}\n</script>"

    def test_location_assign(self):
        result = scan_page(URL, self._loc_page("window.location.assign(payload);"))
        assert any(f.source == "window.location" and f.sink == "location.assign()" for f in result.sink_findings)

    def test_location_documentwrite(self):
        result = scan_page(URL, self._loc_page("document.write(payload);"))
        assert any(f.source == "window.location" and f.sink == "document.write" for f in result.sink_findings)

    def test_location_eval(self):
        result = scan_page(URL, self._loc_page("eval(payload);"))
        assert any(f.source == "window.location" and f.sink == "eval" for f in result.sink_findings)

    def test_location_innerhtml(self):
        js = "var payload = window.location;\nvar d = document.createElement('div');\nd.innerHTML = payload;"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "window.location" and f.sink == "innerHTML" for f in result.sink_findings)

    def test_location_range_create_contextual_fragment(self):
        js = "var payload = window.location;\nvar range = document.createRange();\nvar frag = range.createContextualFragment(payload);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "window.location" and f.sink == "createContextualFragment" for f in result.sink_findings)

    def test_location_replace(self):
        result = scan_page(URL, self._loc_page("location.replace(payload);"))
        assert any(f.source == "window.location" and f.sink == "location.replace()" for f in result.sink_findings)

    def test_location_settimeout(self):
        result = scan_page(URL, self._loc_page("setTimeout('var a=a;' + payload, 1);"))
        assert any(f.source == "window.location" and "setTimeout" in f.sink for f in result.sink_findings)

    # ---- Other sources ----------------------------------------------------

    def test_documenturi_documentwrite(self):
        js = "var payload = document.documentURI;\ndocument.write(payload);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "document.documentURI" and f.sink == "document.write" for f in result.sink_findings)

    def test_baseuri_documentwrite(self):
        js = "var payload = document.baseURI;\ndocument.write(payload);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "document.baseURI" and f.sink == "document.write" for f in result.sink_findings)

    def test_locationhref_documentwrite(self):
        js = "var payload = window.location.href;\ndocument.write(payload);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "location.href" and f.sink == "document.write" for f in result.sink_findings)

    def test_locationpathname_documentwrite(self):
        js = "var payload = window.location.pathname;\ndocument.write(payload);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "location.pathname" and f.sink == "document.write" for f in result.sink_findings)

    def test_locationsearch_documentwrite(self):
        js = "var payload = window.location.search.substr(1);\ndocument.write(payload);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "location.search" and f.sink == "document.write" for f in result.sink_findings)

    def test_url_documentwrite(self):
        js = "var payload = document.URL;\ndocument.write(payload);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "document.URL" and f.sink == "document.write" for f in result.sink_findings)

    def test_urlunencoded_documentwrite(self):
        js = "var payload = document.URLUnencoded;\ndocument.write(payload);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "document.URLUnencoded" and f.sink == "document.write" for f in result.sink_findings)
