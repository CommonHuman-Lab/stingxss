# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Tests for engine/reporter.py — ScanResult and finding dataclasses.
"""

import threading
import time

import pytest

from stingxss.engine.reporter import (
    ScanResult,
    ReflectedFinding,
    DomFinding,
    BlindFinding,
    CRLFFinding,
    XSTFinding,
    GraphqlFinding,
    WebsocketFinding,
    ReflectionContext,
    FindingType,
)


def _reflected(confirmed: bool = True) -> ReflectedFinding:
    return ReflectedFinding(
        url="https://example.com/search?q=x",
        parameter="q",
        method="GET",
        context=ReflectionContext.HTML_BODY,
        payload='<img src=x onerror=alert(1)>',
        confirmed=confirmed,
        evidence="<p><img src=x onerror=alert(1)></p>",
    )


def _dom() -> DomFinding:
    return DomFinding(
        url="https://example.com/",
        source="location.hash",
        sink="innerHTML",
        line=10,
        snippet="elem.innerHTML = location.hash.slice(1);",
    )


def _blind() -> BlindFinding:
    return BlindFinding(
        url="https://example.com/comment",
        parameter="body",
        method="POST",
        payload='<script src="https://cb.io/x.js"></script>',
        callback="https://cb.io",
    )


class TestScanResult:
    def test_initial_state(self):
        r = ScanResult(target="https://example.com")
        assert r.total_findings == 0
        assert r.success is True  # no errors and findings=0 still success

    def test_total_findings(self):
        r = ScanResult(target="https://example.com")
        r.reflected.append(_reflected())
        r.dom.append(_dom())
        r.blind.append(_blind())
        assert r.total_findings == 3

    def test_finish_sets_duration(self):
        r = ScanResult(target="https://example.com")
        time.sleep(0.01)
        r.finish()
        assert r.duration_s > 0

    def test_to_dict_structure(self):
        r = ScanResult(target="https://example.com")
        r.reflected.append(_reflected())
        r.dom.append(_dom())
        r.blind.append(_blind())
        r.finish()
        d = r.to_dict()
        assert d["target"] == "https://example.com"
        assert d["total_findings"] == 3
        assert len(d["findings"]) == 3
        types = {f["type"] for f in d["findings"]}
        assert FindingType.REFLECTED_XSS in types
        assert FindingType.DOM_XSS in types
        assert FindingType.BLIND_XSS in types

    def test_thread_safe_append_reflected(self):
        r = ScanResult(target="https://example.com")
        errors = []

        def worker(tid):
            try:
                for i in range(100):
                    f = ReflectedFinding(
                        url=f"https://example.com/p{tid}-{i}",
                        parameter="q",
                        method="GET",
                        context=ReflectionContext.HTML_BODY,
                        payload="<img>",
                        confirmed=True,
                    )
                    r.append_reflected(f)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(r.reflected) == 1000

    def test_thread_safe_append_dom(self):
        r = ScanResult(target="https://example.com")

        def worker(tid):
            for i in range(50):
                f = DomFinding(
                    url=f"https://example.com/p{tid}-{i}",
                    source="location.hash",
                    sink="innerHTML",
                    line=10,
                )
                r.append_dom(f)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(r.dom) == 250

    def test_append_error(self):
        r = ScanResult(target="https://example.com")
        r.append_error("something went wrong")
        assert "something went wrong" in r.errors

    def test_append_log(self):
        r = ScanResult(target="https://example.com")
        r.append_log("[*] test message")
        assert "[*] test message" in r.log

    def test_success_false_when_errors_and_no_findings(self):
        r = ScanResult(target="https://example.com")
        r.errors.append("fatal error")
        assert r.success is False

    def test_success_true_when_findings_despite_errors(self):
        r = ScanResult(target="https://example.com")
        r.errors.append("some non-fatal error")
        r.reflected.append(_reflected())
        assert r.success is True


# ---------------------------------------------------------------------------
# FindingType enum — new values
# ---------------------------------------------------------------------------

class TestFindingTypeNewValues:
    def test_crlf_value(self):
        assert FindingType.CRLF == "crlf"

    def test_xst_value(self):
        assert FindingType.XST == "xst"

    def test_crlf_is_str(self):
        assert isinstance(FindingType.CRLF, str)

    def test_xst_is_str(self):
        assert isinstance(FindingType.XST, str)


# ---------------------------------------------------------------------------
# CRLFFinding
# ---------------------------------------------------------------------------

def _crlf() -> CRLFFinding:
    return CRLFFinding(
        url="http://example.com/?q=test",
        parameter="q",
        method="GET",
        vector="param",
        payload="%0d%0aX-Injected: yes",
        injected_header="X-StingXSS-Crlf",
        reason="CRLF injection via parameter 'q'",
    )


class TestCRLFFinding:
    def test_fields(self):
        f = _crlf()
        assert f.url == "http://example.com/?q=test"
        assert f.parameter == "q"
        assert f.method == "GET"
        assert f.vector == "param"
        assert "0d" in f.payload or "0a" in f.payload
        assert "X-StingXSS-Crlf" in f.injected_header
        assert len(f.reason) > 0

    def test_vector_can_be_header(self):
        f = CRLFFinding(
            url="http://example.com/",
            parameter="Referer",
            method="GET",
            vector="header",
            payload="%0d%0aX-StingXSS-Crlf: sting",
            injected_header="X-StingXSS-Crlf",
            reason="CRLF via Referer header",
        )
        assert f.vector == "header"


class TestScanResultCRLF:
    def test_crlf_list_initially_empty(self):
        r = ScanResult(target="https://example.com")
        assert r.crlf == []

    def test_append_crlf(self):
        r = ScanResult(target="https://example.com")
        r.append_crlf(_crlf())
        assert len(r.crlf) == 1

    def test_crlf_counts_in_total_findings(self):
        r = ScanResult(target="https://example.com")
        r.append_crlf(_crlf())
        assert r.total_findings == 1

    def test_crlf_included_in_to_dict(self):
        r = ScanResult(target="https://example.com")
        r.append_crlf(_crlf())
        r.finish()
        d = r.to_dict()
        types = {f["type"] for f in d["findings"]}
        assert FindingType.CRLF in types


# ---------------------------------------------------------------------------
# XSTFinding
# ---------------------------------------------------------------------------

def _xst() -> XSTFinding:
    return XSTFinding(
        url="http://example.com/",
        reason="TRACE method enabled — HttpOnly cookie exfil risk",
    )


class TestXSTFinding:
    def test_fields(self):
        f = _xst()
        assert f.url == "http://example.com/"
        assert len(f.reason) > 0
        assert f.method == "TRACE"

    def test_method_default(self):
        f = XSTFinding(url="http://x.com/", reason="test")
        assert f.method == "TRACE"

    def test_custom_method(self):
        f = XSTFinding(url="http://x.com/", reason="test", method="OPTIONS")
        assert f.method == "OPTIONS"


class TestScanResultXST:
    def test_xst_list_initially_empty(self):
        r = ScanResult(target="https://example.com")
        assert r.xst == []

    def test_append_xst(self):
        r = ScanResult(target="https://example.com")
        r.append_xst(_xst())
        assert len(r.xst) == 1

    def test_xst_counts_in_total_findings(self):
        r = ScanResult(target="https://example.com")
        r.append_xst(_xst())
        assert r.total_findings == 1

    def test_xst_included_in_to_dict(self):
        r = ScanResult(target="https://example.com")
        r.append_xst(_xst())
        r.finish()
        d = r.to_dict()
        types = {f["type"] for f in d["findings"]}
        assert FindingType.XST in types

    def test_crlf_and_xst_together_in_total(self):
        r = ScanResult(target="https://example.com")
        r.append_crlf(_crlf())
        r.append_xst(_xst())
        assert r.total_findings == 2


# ---------------------------------------------------------------------------
# DomFinding.category field
# ---------------------------------------------------------------------------

class TestDomFindingCategory:
    def test_default_category_is_dom_xss(self):
        f = DomFinding(url="https://example.com/", source="location.hash", sink="innerHTML", line=5)
        assert f.category == "dom_xss"

    def test_custom_category_redirect(self):
        f = DomFinding(
            url="https://example.com/",
            source="location.hash",
            sink="location.href=",
            line=3,
            category="dom_open_redirect",
        )
        assert f.category == "dom_open_redirect"

    def test_custom_category_prototype_pollution(self):
        f = DomFinding(
            url="https://example.com/",
            source="location.search",
            sink="_.merge()",
            line=7,
            category="prototype_pollution",
        )
        assert f.category == "prototype_pollution"

    def test_all_valid_categories_accepted(self):
        valid = {
            "dom_xss", "dom_open_redirect",
            "link_manipulation", "dom_data_manipulation",
            "prototype_pollution",
        }
        for cat in valid:
            f = DomFinding(url="https://x.com", source="s", sink="k", line=1, category=cat)
            assert f.category == cat


# ---------------------------------------------------------------------------
# GraphqlFinding
# ---------------------------------------------------------------------------

def _graphql() -> GraphqlFinding:
    return GraphqlFinding(
        url="https://example.com/graphql",
        endpoint="https://example.com/graphql",
        field="name",
        operation="query",
        payload='<img src=x onerror=alert(1)>',
        confirmed=True,
        evidence='"name": "<img src=x onerror=alert(1)>"',
    )


class TestGraphqlFinding:
    def test_fields(self):
        f = _graphql()
        assert f.url == "https://example.com/graphql"
        assert f.endpoint == "https://example.com/graphql"
        assert f.field == "name"
        assert f.operation == "query"
        assert f.confirmed is True
        assert f.evidence != ""

    def test_severity_default_high(self):
        from commonhuman_cli.severity import Severity
        f = _graphql()
        assert f.severity == Severity.HIGH

    def test_custom_severity(self):
        from commonhuman_cli.severity import Severity
        f = GraphqlFinding(
            url="u", endpoint="e", field="f", operation="query",
            payload="p", confirmed=False, severity=Severity.MEDIUM,
        )
        assert f.severity == Severity.MEDIUM


class TestScanResultGraphql:
    def test_graphql_list_initially_empty(self):
        r = ScanResult(target="https://example.com")
        assert r.graphql == []

    def test_append_graphql(self):
        r = ScanResult(target="https://example.com")
        r.append_graphql(_graphql())
        assert len(r.graphql) == 1

    def test_graphql_counts_in_total_findings(self):
        r = ScanResult(target="https://example.com")
        r.append_graphql(_graphql())
        assert r.total_findings == 1

    def test_graphql_included_in_to_dict(self):
        r = ScanResult(target="https://example.com")
        r.append_graphql(_graphql())
        r.finish()
        d = r.to_dict()
        types = {f["type"] for f in d["findings"]}
        assert FindingType.GRAPHQL_XSS in types


# ---------------------------------------------------------------------------
# WebsocketFinding
# ---------------------------------------------------------------------------

def _websocket() -> WebsocketFinding:
    return WebsocketFinding(
        url="https://example.com/",
        ws_url="wss://example.com/ws",
        payload='<img src=x onerror=alert(1)>',
        response='{"msg":"<img src=x onerror=alert(1)>"}',
        confirmed=True,
    )


class TestWebsocketFinding:
    def test_fields(self):
        f = _websocket()
        assert f.url == "https://example.com/"
        assert f.ws_url == "wss://example.com/ws"
        assert f.confirmed is True
        assert f.response != ""

    def test_severity_default_high(self):
        from commonhuman_cli.severity import Severity
        f = _websocket()
        assert f.severity == Severity.HIGH


class TestScanResultWebsocket:
    def test_websocket_list_initially_empty(self):
        r = ScanResult(target="https://example.com")
        assert r.websocket == []

    def test_append_websocket(self):
        r = ScanResult(target="https://example.com")
        r.append_websocket(_websocket())
        assert len(r.websocket) == 1

    def test_websocket_counts_in_total_findings(self):
        r = ScanResult(target="https://example.com")
        r.append_websocket(_websocket())
        assert r.total_findings == 1

    def test_websocket_included_in_to_dict(self):
        r = ScanResult(target="https://example.com")
        r.append_websocket(_websocket())
        r.finish()
        d = r.to_dict()
        types = {f["type"] for f in d["findings"]}
        assert FindingType.WEBSOCKET_XSS in types

    def test_graphql_and_websocket_together_in_total(self):
        r = ScanResult(target="https://example.com")
        r.append_graphql(_graphql())
        r.append_websocket(_websocket())
        assert r.total_findings == 2


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

class TestDeduplication:
    def test_reflected_same_url_param_context_deduplicated(self):
        r = ScanResult(target="https://example.com")
        r.append_reflected(_reflected())
        r.append_reflected(_reflected())  # identical key → dropped
        assert len(r.reflected) == 1

    def test_reflected_different_param_not_deduplicated(self):
        r = ScanResult(target="https://example.com")
        r.append_reflected(_reflected())
        r.append_reflected(ReflectedFinding(
            url="https://example.com/search?q=x",
            parameter="name",  # different param
            method="GET",
            context=ReflectionContext.HTML_BODY,
            payload="<img>",
            confirmed=True,
        ))
        assert len(r.reflected) == 2

    def test_reflected_different_url_not_deduplicated(self):
        r = ScanResult(target="https://example.com")
        r.append_reflected(_reflected())
        r.append_reflected(ReflectedFinding(
            url="https://example.com/other",
            parameter="q",
            method="GET",
            context=ReflectionContext.HTML_BODY,
            payload="<svg>",
            confirmed=True,
        ))
        assert len(r.reflected) == 2

    def test_reflected_different_context_not_deduplicated(self):
        r = ScanResult(target="https://example.com")
        r.append_reflected(_reflected())  # HTML_BODY
        r.append_reflected(ReflectedFinding(
            url="https://example.com/search?q=x",
            parameter="q",
            method="GET",
            context=ReflectionContext.ANGULAR_TEMPLATE,  # different context
            payload="{{constructor.constructor('alert(1)')()}}",
            confirmed=True,
        ))
        assert len(r.reflected) == 2

    def test_dom_same_url_source_sink_deduplicated(self):
        r = ScanResult(target="https://example.com")
        r.append_dom(_dom())
        r.append_dom(_dom())
        assert len(r.dom) == 1

    def test_dom_different_sink_not_deduplicated(self):
        r = ScanResult(target="https://example.com")
        r.append_dom(_dom())
        r.append_dom(DomFinding(
            url="https://example.com/",
            source="location.hash",
            sink="outerHTML",  # different sink
            line=5,
        ))
        assert len(r.dom) == 2

    def test_graphql_same_endpoint_field_deduplicated(self):
        r = ScanResult(target="https://example.com")
        r.append_graphql(_graphql())
        r.append_graphql(_graphql())
        assert len(r.graphql) == 1

    def test_websocket_same_url_deduplicated(self):
        r = ScanResult(target="https://example.com")
        r.append_websocket(_websocket())
        r.append_websocket(_websocket())
        assert len(r.websocket) == 1

    def test_dedup_thread_safe_concurrent_duplicates(self):
        r = ScanResult(target="https://example.com")
        errors = []

        def worker():
            try:
                for _ in range(50):
                    r.append_reflected(_reflected())  # all identical → only 1 survives
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(r.reflected) == 1
