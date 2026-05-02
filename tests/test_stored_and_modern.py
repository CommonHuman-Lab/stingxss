# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Tests for new payload lists and scanner modules added to cover the remaining
gaps identified against the Hackviser XSS guide:

  - MODERN_BROWSER payloads (Import Maps, Shadow DOM, Trusted Types, Service Worker,
    MutationObserver, IntersectionObserver, ResizeObserver, Custom Elements,
    Template injection, Blob URL, CSS :target onanimationcancel)
  - STORED_XSS payloads (keylogger, form hijack, WebSocket, localStorage, session API)
  - prototype_pollution_params() helper
  - stored.py: test_stored, test_prototype_pollution, test_localstorage
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from stingxss.engine.analysis.payload_gen import (
    modern_browser_payloads,
    stored_xss_payloads,
    prototype_pollution_params,
    make_confirm_marker,
)
from stingxss.engine._scanner.stored import (
    run_stored,
    run_prototype_pollution,
    run_localstorage,
)
from stingxss.engine._scanner.options import ScanOptions
from stingxss.engine.reporter import ScanResult, StoredFinding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resp(text: str = "", status: int = 200) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {"content-type": "text/html"}
    return r


# ---------------------------------------------------------------------------
# MODERN_BROWSER payload list
# ---------------------------------------------------------------------------

class TestModernBrowserPayloads:
    def test_returns_list(self):
        payloads = modern_browser_payloads()
        assert isinstance(payloads, list)
        assert len(payloads) > 0

    def test_marker_embedded(self):
        marker = "MODERN42"
        for p in modern_browser_payloads(marker=marker):
            assert marker in p

    def test_no_duplicates(self):
        payloads = modern_browser_payloads()
        assert len(payloads) == len(set(payloads))

    def test_contains_import_maps(self):
        payloads = modern_browser_payloads()
        assert any("importmap" in p for p in payloads)

    def test_contains_shadow_dom(self):
        payloads = modern_browser_payloads()
        assert any("attachShadow" in p for p in payloads)

    def test_contains_trusted_types(self):
        payloads = modern_browser_payloads()
        assert any("trustedTypes" in p for p in payloads)

    def test_contains_service_worker(self):
        payloads = modern_browser_payloads()
        assert any("serviceWorker" in p and "register" in p for p in payloads)

    def test_contains_mutation_observer(self):
        payloads = modern_browser_payloads()
        assert any("MutationObserver" in p for p in payloads)

    def test_contains_intersection_observer(self):
        payloads = modern_browser_payloads()
        assert any("IntersectionObserver" in p for p in payloads)

    def test_contains_resize_observer(self):
        payloads = modern_browser_payloads()
        assert any("ResizeObserver" in p for p in payloads)

    def test_contains_custom_elements(self):
        payloads = modern_browser_payloads()
        assert any("customElements" in p for p in payloads)

    def test_contains_template_element(self):
        payloads = modern_browser_payloads()
        assert any("<template>" in p.lower() or "template" in p for p in payloads)

    def test_contains_blob_url(self):
        payloads = modern_browser_payloads()
        assert any("Blob" in p and "createObjectURL" in p for p in payloads)

    def test_contains_css_target_animation_cancel(self):
        payloads = modern_browser_payloads()
        assert any("onanimationcancel" in p and ":target" in p for p in payloads)


# ---------------------------------------------------------------------------
# STORED_XSS payload list
# ---------------------------------------------------------------------------

class TestStoredXssPayloads:
    def test_returns_list(self):
        payloads = stored_xss_payloads()
        assert isinstance(payloads, list)
        assert len(payloads) > 0

    def test_marker_embedded(self):
        marker = "STORED99"
        for p in stored_xss_payloads(marker=marker):
            assert marker in p

    def test_contains_keylogger(self):
        payloads = stored_xss_payloads()
        assert any("onkeypress" in p or "onkeydown" in p for p in payloads)

    def test_contains_form_hijack(self):
        payloads = stored_xss_payloads()
        assert any("forms[0]" in p and "action" in p for p in payloads)

    def test_contains_websocket(self):
        payloads = stored_xss_payloads()
        assert any("WebSocket" in p for p in payloads)

    def test_contains_localstorage_exfil(self):
        payloads = stored_xss_payloads()
        assert any("localStorage" in p for p in payloads)

    def test_contains_fetch_api_exfil(self):
        payloads = stored_xss_payloads()
        assert any("fetch" in p for p in payloads)


# ---------------------------------------------------------------------------
# prototype_pollution_params()
# ---------------------------------------------------------------------------

class TestPrototypePollutionParams:
    def test_returns_list_of_tuples(self):
        pairs = prototype_pollution_params()
        assert isinstance(pairs, list)
        assert len(pairs) > 0
        for name, value in pairs:
            assert isinstance(name, str)
            assert isinstance(value, str)

    def test_marker_embedded_in_values(self):
        marker = "PP_TEST"
        pairs = prototype_pollution_params(marker=marker)
        # At least some values should contain the marker (key-path-only payloads may not)
        assert any(marker in value for _, value in pairs)

    def test_contains_proto_html_key(self):
        pairs = prototype_pollution_params()
        assert any("__proto__" in name and "html" in name for name, _ in pairs)

    def test_contains_constructor_prototype_key(self):
        pairs = prototype_pollution_params()
        assert any("constructor" in name for name, _ in pairs)

    def test_contains_source_url_key(self):
        pairs = prototype_pollution_params()
        assert any("sourceURL" in name for name, _ in pairs)

    def test_contains_allowed_tags_key(self):
        pairs = prototype_pollution_params()
        assert any("ALLOWED_TAGS" in name for name, _ in pairs)


# ---------------------------------------------------------------------------
# test_stored() — stored XSS inject + revisit
# ---------------------------------------------------------------------------

class TestTestStored:
    def _make_injector(self, revisit_text: str = "") -> MagicMock:
        inj = MagicMock()
        inj.inject_get.return_value = _resp("ok")
        inj.inject_post.return_value = _resp("ok")
        inj.get.return_value = _resp(revisit_text)
        return inj

    def _surface(self, url: str = "https://example.com/?q=x") -> dict:
        return {
            "url": url, "method": "GET",
            "params": {"q": ""}, "single_param": "q",
        }

    def test_no_confirmation_if_marker_absent(self):
        result = ScanResult(target="https://example.com/")
        inj = self._make_injector(revisit_text="nothing here")
        run_stored(
            seed_url="https://example.com/",
            surfaces=[self._surface()],
            page_sources={"https://example.com/": "nothing here"},
            opts=ScanOptions(),
            injector=inj,
            result=result,
        )
        confirmed = [f for f in result.stored if f.confirmed]
        assert confirmed == []

    def test_confirmed_when_marker_in_revisit(self):
        result = ScanResult(target="https://example.com/")

        marker_holder: list[str] = []

        def inject_side(url, param, payload):
            # Extract marker from the payload and store it
            import re
            m = re.search(r"StingXSS_\w+", payload)
            if m:
                marker_holder.append(m.group())
            return _resp("ok")

        inj = MagicMock()
        inj.inject_get.side_effect = inject_side
        inj.inject_post.return_value = _resp("ok")

        def get_side(url):
            if marker_holder:
                return _resp(f"<div>{marker_holder[0]}</div>")
            return _resp("nothing")

        inj.get.side_effect = get_side

        run_stored(
            seed_url="https://example.com/",
            surfaces=[self._surface()],
            page_sources={"https://example.com/": "nothing"},
            opts=ScanOptions(),
            injector=inj,
            result=result,
        )
        confirmed = [f for f in result.stored if f.confirmed]
        assert len(confirmed) > 0

    def test_exclude_pattern_skips_surface(self):
        import re
        result = ScanResult(target="https://example.com/")
        inj = self._make_injector()
        opts = ScanOptions(exclude_patterns=[re.compile(r"/\?q=")])
        run_stored(
            seed_url="https://example.com/",
            surfaces=[self._surface()],
            page_sources={},
            opts=opts,
            injector=inj,
            result=result,
        )
        inj.inject_get.assert_not_called()


# ---------------------------------------------------------------------------
# test_prototype_pollution()
# ---------------------------------------------------------------------------

class TestTestPrototypePollution:
    def test_no_finding_when_marker_absent(self):
        result = ScanResult(target="https://example.com/")
        inj = MagicMock()
        inj.get.return_value = _resp("no marker here")
        run_prototype_pollution("https://example.com/", ScanOptions(), inj, result)
        confirmed = [f for f in result.stored if f.confirmed]
        assert confirmed == []

    def test_confirmed_when_marker_reflected(self):
        result = ScanResult(target="https://example.com/")
        captured: list[str] = []

        def get_side(url):
            import re
            m = re.search(r"StingXSS_\w+", url)
            if m:
                captured.append(m.group())
                return _resp(f"<div>{m.group()}</div>")
            return _resp("nothing")

        inj = MagicMock()
        inj.get.side_effect = get_side
        run_prototype_pollution("https://example.com/", ScanOptions(), inj, result)
        confirmed = [f for f in result.stored if f.confirmed]
        assert len(confirmed) > 0

    def test_requests_made_for_all_pairs(self):
        result = ScanResult(target="https://example.com/")
        inj = MagicMock()
        inj.get.return_value = _resp("nothing")
        run_prototype_pollution("https://example.com/", ScanOptions(), inj, result)
        # Should have made one GET per pollution pair
        from stingxss.engine.analysis.payload_gen import prototype_pollution_params
        assert inj.get.call_count == len(prototype_pollution_params())


# ---------------------------------------------------------------------------
# test_localstorage()
# ---------------------------------------------------------------------------

class TestTestLocalstorage:
    def test_no_finding_when_not_reflected(self):
        result = ScanResult(target="https://example.com/")
        inj = MagicMock()
        inj.inject_get.return_value = _resp("nothing")
        inj.get.return_value = _resp("nothing")
        run_localstorage("https://example.com/", ScanOptions(), inj, result)
        confirmed = [f for f in result.stored if f.confirmed]
        assert confirmed == []

    def test_confirmed_when_marker_in_inject_response(self):
        result = ScanResult(target="https://example.com/")
        import re

        def inject_side(url, param, payload):
            m = re.search(r"StingXSS_\w+", payload)
            if m:
                return _resp(f"<div>{m.group()}</div>")
            return _resp("nothing")

        inj = MagicMock()
        inj.inject_get.side_effect = inject_side
        inj.get.return_value = _resp("nothing")
        run_localstorage("https://example.com/", ScanOptions(), inj, result)
        confirmed = [f for f in result.stored if f.confirmed]
        assert len(confirmed) > 0

    def test_confirmed_on_revisit_when_not_in_inject_response(self):
        result = ScanResult(target="https://example.com/")
        import re
        captured: list[str] = []

        def inject_side(url, param, payload):
            m = re.search(r"StingXSS_\w+", payload)
            if m:
                captured.append(m.group())
            return _resp("nothing")   # not reflected in inject response

        def get_side(url):
            if captured:
                return _resp(f"<div>{captured[0]}</div>")
            return _resp("nothing")

        inj = MagicMock()
        inj.inject_get.side_effect = inject_side
        inj.get.side_effect = get_side
        run_localstorage("https://example.com/", ScanOptions(), inj, result)
        confirmed = [f for f in result.stored if f.confirmed]
        assert len(confirmed) > 0


# ---------------------------------------------------------------------------
# ScanOptions.test_stored
# ---------------------------------------------------------------------------

class TestScanOptionsTestStored:
    def test_default_is_false(self):
        opts = ScanOptions()
        assert opts.test_stored is False

    def test_can_be_set_true(self):
        opts = ScanOptions(test_stored=True)
        assert opts.test_stored is True


# ---------------------------------------------------------------------------
# Reporter — StoredFinding and FindingType.STORED_XSS
# ---------------------------------------------------------------------------

class TestStoredFindingReporter:
    def test_stored_finding_in_scan_result(self):
        result = ScanResult(target="https://example.com/")
        f = StoredFinding(
            inject_url="https://example.com/?q=x",
            revisit_url="https://example.com/",
            parameter="q", method="GET",
            payload="<img src=x onerror=alert(1)>",
            confirmed=True, evidence="<img src=x …>",
        )
        result.append_stored(f)
        assert len(result.stored) == 1
        assert result.total_findings == 1

    def test_stored_finding_in_to_dict(self):
        result = ScanResult(target="https://example.com/")
        result.append_stored(StoredFinding(
            inject_url="https://example.com/?q=x",
            revisit_url="https://example.com/",
            parameter="q", method="GET",
            payload="<payload>", confirmed=False,
        ))
        d = result.to_dict()
        types = [f["type"] for f in d["findings"]]
        assert "stored_xss" in types

    def test_finding_type_stored_xss_exists(self):
        from stingxss.engine.reporter import FindingType
        assert FindingType.STORED_XSS == "stored_xss"
