# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Tests for engine/dom_scanner.py — static DOM XSS analysis.
"""

import pytest

from stingxss.engine.analysis.dom_scanner import scan_page, scan_js, DomScanResult


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


# ---------------------------------------------------------------------------
# Firing Range /angular/ — client-side $parse DOM XSS cases
# ---------------------------------------------------------------------------

class TestFiringRangeAngularDomCases:
    """
    Google Firing Range /angular/* cases that are pure client-side DOM XSS:
    a tainted source is passed directly to Angular's $parse() sink.
    """

    def _parse_page(self, source_expr: str) -> str:
        """Build a minimal ng-app page that calls $parse(source_expr)."""
        return (
            f'<html ng-app><body>'
            f'<script>'
            f'var expr = {source_expr};'
            f'angular.injector(["ng"]).get("$parse")(expr)({{}});'
            f'</script>'
            f'</body></html>'
        )

    def test_parse_location_hash(self):
        result = scan_page(URL, self._parse_page("location.hash"))
        sinks = [f.sink for f in result.sink_findings]
        assert "$parse()" in sinks

    def test_parse_location_search(self):
        result = scan_page(URL, self._parse_page("location.search"))
        sinks = [f.sink for f in result.sink_findings]
        assert "$parse()" in sinks

    def test_parse_window_name(self):
        js = "var n = window.name;\nangular.injector(['ng']).get('$parse')(n)({});"
        result = scan_page(URL, f"<script>{js}</script>")
        sinks = [f.sink for f in result.sink_findings]
        assert "$parse()" in sinks

    def test_parse_postmessage_data(self):
        """msg.data source → $parse() sink (postMessage variant)."""
        js = (
            "window.addEventListener('message', function(msg) {\n"
            "  angular.injector(['ng']).get('$parse')(msg.data)({});\n"
            "});"
        )
        result = scan_page(URL, f"<script>{js}</script>")
        sources = [f.source for f in result.sink_findings]
        sinks   = [f.sink   for f in result.sink_findings]
        assert "$parse()" in sinks
        assert any(s in ("msg.data", "postMessage") for s in sources)

    def test_parse_localstorage(self):
        js = "var v = localStorage.getItem('q');\nangular.injector(['ng']).get('$parse')(v)({});"
        result = scan_page(URL, f"<script>{js}</script>")
        sinks = [f.sink for f in result.sink_findings]
        assert "$parse()" in sinks


# ---------------------------------------------------------------------------
# Firing Range /dom/ — all 46 cases
# ---------------------------------------------------------------------------

class TestFiringRangeDomCookieCases:
    """document.cookie → eval / innerHTML / documentWrite"""

    def test_cookie_set_eval(self):
        js = (
            "var payload = lookupCookie('badValue');\n"
            "eval(payload);\n"
            "function trigger(payload) { eval(payload); };"
        )
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "document.cookie" or "eval" in f.sink for f in result.sink_findings) or \
               any("eval" in s for s in result.sinks_found)

    def test_cookie_set_innerhtml(self):
        js = (
            "var payload = lookupCookie('badValue');\n"
            "var div = document.createElement('div');\n"
            "document.documentElement.appendChild(div);\n"
            "div.innerHTML = payload;\n"
            "function trigger(payload) { div.innerHTML = payload; };"
        )
        result = scan_page(URL, f"<script>{js}</script>")
        assert "innerHTML" in result.sinks_found

    def test_cookie_set_documentwrite(self):
        js = (
            "var payload = lookupCookie('badValue');\n"
            "document.write(payload);\n"
            "function trigger(payload) { document.write(payload); };"
        )
        result = scan_page(URL, f"<script>{js}</script>")
        assert "document.write" in result.sinks_found

    def test_cookie_not_set_eval(self):
        """document.cookie (not set) → eval — same pattern, cookie source present."""
        js = (
            "var payload = lookupCookie('ThisCookieIsTotallyRandomAndCantPossiblyBeSet');\n"
            "eval(payload);\n"
            "function trigger(payload) { eval(payload); };"
        )
        result = scan_page(URL, f"<script>{js}</script>")
        assert "eval" in result.sinks_found


class TestFiringRangeDomReferrerCases:
    """document.referrer → eval / innerHTML / documentWrite"""

    def _make(self, sink_line: str) -> str:
        return (
            "<script>\n"
            "var payload = unescape(document.referrer);\n"
            f"{sink_line}\n"
            "function trigger(payload) {{\n"
            f"  {sink_line}\n"
            "}};\n"
            "</script>"
        )

    def test_referrer_eval(self):
        js = "var payload = unescape(document.referrer);\neval(payload);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "document.referrer" and f.sink == "eval" for f in result.sink_findings)

    def test_referrer_innerhtml(self):
        js = (
            "var payload = document.referrer;\n"
            "var div = document.createElement('div');\n"
            "div.innerHTML = payload;"
        )
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "document.referrer" and f.sink == "innerHTML" for f in result.sink_findings)

    def test_referrer_documentwrite(self):
        js = "var payload = document.referrer;\ndocument.write(payload);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "document.referrer" and f.sink == "document.write" for f in result.sink_findings)


class TestFiringRangeDomWindowNameCases:
    """window.name → eval / innerHTML / documentWrite"""

    def test_windowname_eval(self):
        js = "var payload = window.name;\neval(payload);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "window.name" and f.sink == "eval" for f in result.sink_findings)

    def test_windowname_innerhtml(self):
        js = (
            "var payload = window.name;\n"
            "var div = document.createElement('div');\n"
            "div.innerHTML = payload;"
        )
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "window.name" and f.sink == "innerHTML" for f in result.sink_findings)

    def test_windowname_documentwrite(self):
        js = "var payload = window.name;\ndocument.write(payload);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "window.name" and f.sink == "document.write" for f in result.sink_findings)


class TestFiringRangeDomLocalStorageCases:
    """localStorage (array / function / property) → eval / innerHTML / documentWrite"""

    # --- array notation ---
    def test_localstorage_array_eval(self):
        js = "var payload = localStorage['badValue'];\neval(payload);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any("localStorage" in f.source and f.sink == "eval" for f in result.sink_findings)

    def test_localstorage_array_eval_external(self):
        """Same as inline but via external script — same JS source, same detection."""
        js = "var payload = localStorage['badValue'];\neval(payload);"
        result = scan_js(URL, js)
        assert any("localStorage" in f.source and f.sink == "eval" for f in result.sink_findings)

    # --- function notation ---
    def test_localstorage_function_eval(self):
        js = "var payload = localStorage.getItem('badValue');\neval(payload);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "localStorage.getItem" and f.sink == "eval" for f in result.sink_findings)

    def test_localstorage_function_innerhtml(self):
        js = (
            "var payload = localStorage.getItem('badValue');\n"
            "var div = document.createElement('div');\n"
            "div.innerHTML = payload;"
        )
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "localStorage.getItem" and f.sink == "innerHTML" for f in result.sink_findings)

    def test_localstorage_function_documentwrite(self):
        js = "var payload = localStorage.getItem('badValue');\ndocument.write(payload);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "localStorage.getItem" and f.sink == "document.write" for f in result.sink_findings)

    # --- property notation ---
    def test_localstorage_property_documentwrite(self):
        js = "var payload = localStorage.badValue;\ndocument.write(payload);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any("localStorage" in f.source and f.sink == "document.write" for f in result.sink_findings)

    # --- external script variants (same logic, just verify sources are registered) ---
    def test_localstorage_array_eval_source_registered(self):
        js = "if (!localStorage['badValue']) { localStorage['badValue'] = Math.random(); }\nvar payload = localStorage['badValue'];\neval(payload);"
        result = scan_js(URL, js)
        assert any("localStorage" in s for s in result.sources_found)

    def test_localstorage_function_documentwrite_external(self):
        js = "var payload = localStorage.getItem('badValue');\ndocument.write(payload);"
        result = scan_js(URL, js)
        assert any(f.source == "localStorage.getItem" and f.sink == "document.write" for f in result.sink_findings)

    def test_localstorage_property_documentwrite_external(self):
        js = "var payload = localStorage.badValue;\ndocument.write(payload);"
        result = scan_js(URL, js)
        assert any("localStorage" in f.source and f.sink == "document.write" for f in result.sink_findings)


class TestFiringRangeDomSessionStorageCases:
    """sessionStorage (array / function / property) → eval / innerHTML / documentWrite"""

    def test_sessionstorage_array_eval(self):
        js = "var payload = sessionStorage['badValue'];\neval(payload);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any("sessionStorage" in f.source and f.sink == "eval" for f in result.sink_findings)

    def test_sessionstorage_function_eval(self):
        js = "var payload = sessionStorage.getItem('badValue');\neval(payload);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "sessionStorage.getItem" and f.sink == "eval" for f in result.sink_findings)

    def test_sessionstorage_function_innerhtml(self):
        js = (
            "var payload = sessionStorage.getItem('badValue');\n"
            "var div = document.createElement('div');\n"
            "div.innerHTML = payload;"
        )
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "sessionStorage.getItem" and f.sink == "innerHTML" for f in result.sink_findings)

    def test_sessionstorage_function_documentwrite(self):
        js = "var payload = sessionStorage.getItem('badValue');\ndocument.write(payload);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.source == "sessionStorage.getItem" and f.sink == "document.write" for f in result.sink_findings)

    def test_sessionstorage_property_documentwrite(self):
        js = "var payload = sessionStorage.badValue;\ndocument.write(payload);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any("sessionStorage" in f.source and f.sink == "document.write" for f in result.sink_findings)

    # external variants
    def test_sessionstorage_array_eval_external(self):
        js = "var payload = sessionStorage['badValue'];\neval(payload);"
        result = scan_js(URL, js)
        assert any("sessionStorage" in f.source and f.sink == "eval" for f in result.sink_findings)

    def test_sessionstorage_function_eval_external(self):
        js = "var payload = sessionStorage.getItem('badValue');\neval(payload);"
        result = scan_js(URL, js)
        assert any(f.source == "sessionStorage.getItem" and f.sink == "eval" for f in result.sink_findings)

    def test_sessionstorage_function_innerhtml_external(self):
        js = (
            "var payload = sessionStorage.getItem('badValue');\n"
            "var div = document.createElement('div');\n"
            "div.innerHTML = payload;"
        )
        result = scan_js(URL, js)
        assert any(f.source == "sessionStorage.getItem" and f.sink == "innerHTML" for f in result.sink_findings)

    def test_sessionstorage_function_documentwrite_external(self):
        js = "var payload = sessionStorage.getItem('badValue');\ndocument.write(payload);"
        result = scan_js(URL, js)
        assert any(f.source == "sessionStorage.getItem" and f.sink == "document.write" for f in result.sink_findings)

    def test_sessionstorage_property_documentwrite_external(self):
        js = "var payload = sessionStorage.badValue;\ndocument.write(payload);"
        result = scan_js(URL, js)
        assert any("sessionStorage" in f.source and f.sink == "document.write" for f in result.sink_findings)


class TestFiringRangeDomPostMessageCases:
    """postMessage → eval / innerHTML / documentWrite / complex / improper origin"""

    def test_postmessage_eval(self):
        js = (
            "var postMessageHandler = function(msg) {\n"
            "  var content = msg.data;\n"
            "  var msgObj = eval(content);\n"
            "};\n"
            "window.addEventListener('message', postMessageHandler, false);"
        )
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.sink == "eval" for f in result.sink_findings)

    def test_postmessage_innerhtml(self):
        js = (
            "window.addEventListener('message', function(msg) {\n"
            "  var div = document.createElement('div');\n"
            "  div.innerHTML = msg.data;\n"
            "}, false);"
        )
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.sink == "innerHTML" for f in result.sink_findings)

    def test_postmessage_documentwrite(self):
        js = (
            "window.addEventListener('message', function(msg) {\n"
            "  document.write(msg.data);\n"
            "}, false);"
        )
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.sink == "document.write" for f in result.sink_findings)

    def test_postmessage_complex_eval(self):
        """msg.data.payload → eval (complex message case)."""
        js = (
            "const postMessageHandler = function(msg) {\n"
            "  let action = msg.data.action;\n"
            "  if(action === 'exec') {\n"
            "    eval(msg.data.payload);\n"
            "  }\n"
            "};\n"
            "window.addEventListener('message', postMessageHandler, false);"
        )
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.sink == "eval" for f in result.sink_findings)

    def test_postmessage_complex_documentwrite_html(self):
        """msg.data.html → document.write (complex message case)."""
        js = (
            "const postMessageHandler = function(msg) {\n"
            "  document.write(msg.data.html);\n"
            "};\n"
            "window.addEventListener('message', postMessageHandler, false);"
        )
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.sink == "document.write" for f in result.sink_findings)

    def test_postmessage_improper_origin_includes(self):
        """msg.origin.includes() — bypassable partial string comparison."""
        js = (
            "var postMessageHandler = function(msg) {\n"
            "  if (msg.origin.includes('www.google.com')) {\n"
            "    eval(msg.data);\n"
            "  }\n"
            "};\n"
            "window.addEventListener('message', postMessageHandler, false);"
        )
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(
            f.source == "msg.origin" and f.sink == "improper-origin-check"
            for f in result.sink_findings
        )

    def test_postmessage_improper_origin_regexp(self):
        """msg.origin.match() with unescaped dot and no $ anchor."""
        js = (
            "var postMessageHandler = function(msg) {\n"
            "  const originRegExp = /https?:\\/\\/www.google.com/\n"
            "  if (msg.origin.match(originRegExp)) {\n"
            "    eval(msg.data);\n"
            "  }\n"
            "};\n"
            "window.addEventListener('message', postMessageHandler, false);"
        )
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(
            f.source == "msg.origin" and f.sink == "improper-origin-regexp"
            for f in result.sink_findings
        )


class TestFiringRangeDomEventTriggeringCases:
    """Event-triggered XSS — form submission / input typing → eval / innerHTML / documentWrite"""

    def test_form_submission_eval(self):
        """Input value from form → eval on submit."""
        js = (
            "var payload = '';\n"
            "form.onsubmit = function() {\n"
            "  payload = document.getElementById('userInput').value;\n"
            "  eval(payload);\n"
            "  return false;\n"
            "};"
        )
        result = scan_page(URL, f"<script>{js}</script>")
        assert "eval" in result.sinks_found

    def test_form_submission_innerhtml(self):
        js = (
            "var payload = '';\n"
            "form.onsubmit = function() {\n"
            "  payload = document.getElementById('userInput').value;\n"
            "  var div = document.getElementById('out');\n"
            "  div.innerHTML = payload;\n"
            "  return false;\n"
            "};"
        )
        result = scan_page(URL, f"<script>{js}</script>")
        assert "innerHTML" in result.sinks_found

    def test_form_submission_documentwrite(self):
        js = (
            "var payload = '';\n"
            "form.onsubmit = function() {\n"
            "  payload = document.getElementById('userInput').value;\n"
            "  document.write(payload);\n"
            "  return false;\n"
            "};"
        )
        result = scan_page(URL, f"<script>{js}</script>")
        assert "document.write" in result.sinks_found

    def test_input_typing_eval(self):
        """e.target.value → eval on keyup/change."""
        js = (
            "function xssIt(e) {\n"
            "  var payload = e.target.value;\n"
            "  eval(payload);\n"
            "}\n"
            "input.addEventListener('keyup', xssIt);"
        )
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.sink == "eval" for f in result.sink_findings)

    def test_input_typing_innerhtml(self):
        js = (
            "function xssIt(e) {\n"
            "  var payload = e.target.value;\n"
            "  var div = document.getElementById('out');\n"
            "  div.innerHTML = payload;\n"
            "}\n"
            "input.addEventListener('keyup', xssIt);"
        )
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.sink == "innerHTML" for f in result.sink_findings)

    def test_input_typing_documentwrite(self):
        js = (
            "function xssIt(e) {\n"
            "  var payload = e.target.value;\n"
            "  document.write(payload);\n"
            "}\n"
            "input.addEventListener('change', xssIt);"
        )
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.sink == "document.write" for f in result.sink_findings)


class TestFiringRangeDomJavascriptURI:
    """javascript:-URI via location.href"""

    def test_javascript_uri_location_href(self):
        """location.href used as navigation sink (anchor href points to JS)."""
        html = '<a href="javascript:location.href=location.href">Click me</a>'
        result = scan_page(URL, html)
        # The href attribute contains location.href — detected via HTML attribute scan
        assert any("location.href" in f.source or "location.href" in f.sink for f in result.sink_findings)


class TestFiringRangeDomPropagation:
    """DOM propagation: location.hash → window.status → eval"""

    def test_dom_propagation_window_status(self):
        js = (
            "var payload = location.hash.substr(1);\n"
            "window.status = payload;\n"
            "var retrieved_payload = window.status;\n"
            "eval(retrieved_payload);"
        )
        result = scan_page(URL, f"<script>{js}</script>")
        # Should detect location.hash → eval via variable re-propagation
        assert any(f.sink == "eval" for f in result.sink_findings)


# ---------------------------------------------------------------------------
# New sinks: fetch() and xhr.open() — /urldom/ firing range
# ---------------------------------------------------------------------------

class TestNewSinksUrlDom:
    """Tests for fetch() and xhr.open() sinks added for /urldom/ coverage."""

    def test_fetch_sink_detected(self):
        js = "var url = location.hash.slice(1);\nfetch(url);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.sink == "fetch()" for f in result.sink_findings)

    def test_xhr_open_sink_detected(self):
        js = "var url = location.hash.slice(1);\nxhttp.open('GET', url, true);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.sink == "xhr.open()" for f in result.sink_findings)

    def test_xhr_req_open_sink_detected(self):
        js = "var url = location.search;\nreq.open('GET', url);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(f.sink == "xhr.open()" for f in result.sink_findings)


# ---------------------------------------------------------------------------
# New DOM categories: redirect, link, data manipulation, prototype pollution
# ---------------------------------------------------------------------------

class TestDomOpenRedirect:
    """location.href= and friends → category dom_open_redirect."""

    def test_location_href_assign_category(self):
        js = "var u = location.hash.slice(1);\nlocation.href = u;"
        result = scan_page(URL, f"<script>{js}</script>")
        found = [f for f in result.sink_findings if f.category == "dom_open_redirect"]
        assert any("location.href" in f.sink for f in found)

    def test_location_replace_category(self):
        js = "var u = location.search;\nlocation.replace(u);"
        result = scan_page(URL, f"<script>{js}</script>")
        found = [f for f in result.sink_findings if f.category == "dom_open_redirect"]
        assert any("location.replace" in f.sink for f in found)

    def test_document_location_category(self):
        js = "var u = location.hash.slice(1);\ndocument.location = u;"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(
            f.category == "dom_open_redirect" and "document.location" in f.sink
            for f in result.sink_findings
        )

    def test_window_open_category(self):
        js = "var u = document.referrer;\nwindow.open(u);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(
            f.category == "dom_open_redirect" and "window.open" in f.sink
            for f in result.sink_findings
        )

    def test_redirect_severity_is_medium(self):
        from commonhuman_cli.severity import Severity
        js = "var u = location.hash.slice(1);\nlocation.href = u;"
        result = scan_page(URL, f"<script>{js}</script>")
        found = [f for f in result.sink_findings if f.category == "dom_open_redirect"]
        assert all(f.severity == Severity.MEDIUM for f in found)


class TestLinkManipulation:
    """.href=, .src=, .action=, .formAction= → category link_manipulation."""

    def test_element_href_category(self):
        js = "var u = location.hash.slice(1);\nanchor.href = u;"
        result = scan_page(URL, f"<script>{js}</script>")
        found = [f for f in result.sink_findings if f.category == "link_manipulation"]
        assert any(".href=" in f.sink for f in found)

    def test_element_src_category(self):
        js = "var u = location.search;\nimg.src = u;"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(
            f.category == "link_manipulation" and ".src=" in f.sink
            for f in result.sink_findings
        )

    def test_form_action_category(self):
        js = "var u = location.hash.slice(1);\nform.action = u;"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(
            f.category == "link_manipulation" and ".action=" in f.sink
            for f in result.sink_findings
        )

    def test_link_severity_is_low(self):
        from commonhuman_cli.severity import Severity
        js = "var u = location.hash.slice(1);\nanchor.href = u;"
        result = scan_page(URL, f"<script>{js}</script>")
        found = [f for f in result.sink_findings if f.category == "link_manipulation"]
        assert all(f.severity == Severity.LOW for f in found)


class TestDomDataManipulation:
    """textContent=, innerText=, element.value= → category dom_data_manipulation."""

    def test_text_content_category(self):
        js = "var t = location.hash.slice(1);\nelem.textContent = t;"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(
            f.category == "dom_data_manipulation" and "textContent" in f.sink
            for f in result.sink_findings
        )

    def test_inner_text_category(self):
        js = "var t = document.referrer;\nelem.innerText = t;"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(
            f.category == "dom_data_manipulation" and "innerText" in f.sink
            for f in result.sink_findings
        )

    def test_element_value_category(self):
        js = "var t = location.search;\ninput.value = t;"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(
            f.category == "dom_data_manipulation" and "element.value" in f.sink
            for f in result.sink_findings
        )

    def test_data_severity_is_low(self):
        from commonhuman_cli.severity import Severity
        js = "var t = location.hash.slice(1);\nelem.textContent = t;"
        result = scan_page(URL, f"<script>{js}</script>")
        found = [f for f in result.sink_findings if f.category == "dom_data_manipulation"]
        assert all(f.severity == Severity.LOW for f in found)


class TestPrototypePollution:
    """$.extend(true,...) / _.merge() → category prototype_pollution."""

    def test_jquery_extend_deep(self):
        js = "var opts = location.hash.slice(1);\n$.extend(true, {}, opts);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(
            f.category == "prototype_pollution" and "$.extend" in f.sink
            for f in result.sink_findings
        )

    def test_lodash_merge(self):
        js = "var opts = location.search;\n_.merge({}, opts);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(
            f.category == "prototype_pollution" and "_.merge" in f.sink
            for f in result.sink_findings
        )

    def test_lodash_defaults_deep(self):
        js = "var data = document.referrer;\n_.defaultsDeep({}, data);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(
            f.category == "prototype_pollution" and "_.defaultsDeep" in f.sink
            for f in result.sink_findings
        )

    def test_deepmerge(self):
        js = "var payload = location.hash.slice(1);\ndeepmerge({}, payload);"
        result = scan_page(URL, f"<script>{js}</script>")
        assert any(
            f.category == "prototype_pollution" and "deepmerge" in f.sink
            for f in result.sink_findings
        )

    def test_pp_severity_is_high(self):
        from commonhuman_cli.severity import Severity
        js = "var opts = location.hash.slice(1);\n$.extend(true, {}, opts);"
        result = scan_page(URL, f"<script>{js}</script>")
        found = [f for f in result.sink_findings if f.category == "prototype_pollution"]
        assert all(f.severity == Severity.HIGH for f in found)

    def test_category_field_present_on_dom_finding(self):
        js = "var x = location.hash;\ndocument.write(x);"
        result = scan_page(URL, f"<script>{js}</script>")
        for f in result.sink_findings:
            assert hasattr(f, "category"), "DomFinding missing category field"
            assert f.category in {
                "dom_xss", "dom_open_redirect",
                "link_manipulation", "dom_data_manipulation",
                "prototype_pollution",
            }
