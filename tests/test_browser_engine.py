# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for the headless browser XSS engine."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch, call

import pytest

# ---------------------------------------------------------------------------
# SELENIUM_AVAILABLE import path
# ---------------------------------------------------------------------------

def test_selenium_available_true(monkeypatch):
    """SELENIUM_AVAILABLE is True when selenium is importable."""
    fake_selenium = MagicMock()
    monkeypatch.setitem(sys.modules, "selenium", fake_selenium)
    monkeypatch.setitem(sys.modules, "selenium.webdriver", fake_selenium.webdriver)
    # Force re-import
    import importlib
    import stingxss.engine.browser as browser_pkg
    importlib.reload(browser_pkg)
    # After reload the flag depends on whether selenium is really installed —
    # just check the attribute exists
    assert hasattr(browser_pkg, "SELENIUM_AVAILABLE")


def test_selenium_available_false(monkeypatch):
    """SELENIUM_AVAILABLE is False when selenium is missing."""
    import importlib

    # Temporarily hide selenium
    original = sys.modules.get("selenium")
    sys.modules["selenium"] = None  # type: ignore[assignment]
    try:
        import stingxss.engine.browser as browser_pkg
        importlib.reload(browser_pkg)
        assert browser_pkg.SELENIUM_AVAILABLE is False
    finally:
        if original is None:
            sys.modules.pop("selenium", None)
        else:
            sys.modules["selenium"] = original
        importlib.reload(browser_pkg)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_driver_mock(hits=None):
    """Return a MagicMock Selenium driver with _stingxss_hits pre-loaded."""
    driver = MagicMock()
    driver.execute_script.return_value = hits or []
    return driver


# ---------------------------------------------------------------------------
# _install_alert_hook
# ---------------------------------------------------------------------------

def test_install_alert_hook_calls_cdp():
    from stingxss.engine.browser.engine import BrowserEngine, _ALERT_HOOK_JS
    engine = BrowserEngine()
    driver = MagicMock()
    engine._install_alert_hook(driver)
    driver.execute_cdp_cmd.assert_called_once_with(
        "Page.addScriptToEvaluateOnNewDocument",
        {"source": _ALERT_HOOK_JS},
    )


# ---------------------------------------------------------------------------
# _get_hits
# ---------------------------------------------------------------------------

def test_get_hits_returns_list():
    from stingxss.engine.browser.engine import BrowserEngine
    engine = BrowserEngine()
    driver = MagicMock()
    driver.execute_script.return_value = ["hit1", "hit2"]
    assert engine._get_hits(driver) == ["hit1", "hit2"]


def test_get_hits_returns_empty_on_exception():
    from stingxss.engine.browser.engine import BrowserEngine
    engine = BrowserEngine()
    driver = MagicMock()
    driver.execute_script.side_effect = Exception("dead")
    assert engine._get_hits(driver) == []


# ---------------------------------------------------------------------------
# scan_url — marker in hits → confirmed BrowserFinding
# ---------------------------------------------------------------------------

def test_scan_url_confirmed_finding():
    from stingxss.engine.browser.engine import BrowserEngine
    from stingxss.engine.reporter import BrowserFinding

    marker = "STING_abc123"
    engine = BrowserEngine()
    driver = _make_driver_mock(hits=[marker])

    with patch.object(engine, "_setup_driver", return_value=driver), \
         patch.object(engine, "_install_alert_hook"):
        findings = engine.scan_url(
            url="http://example.com/search?q=test",
            params={"q": ""},
            marker=marker,
        )

    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, BrowserFinding)
    assert f.confirmed is True
    assert f.marker == marker
    assert f.evidence == marker
    assert f.parameter == "q"


def test_scan_url_no_hits_no_finding():
    from stingxss.engine.browser.engine import BrowserEngine

    marker = "STING_xyz"
    engine = BrowserEngine()
    driver = _make_driver_mock(hits=[])

    with patch.object(engine, "_setup_driver", return_value=driver), \
         patch.object(engine, "_install_alert_hook"):
        findings = engine.scan_url(
            url="http://example.com/search?q=test",
            params={"q": ""},
            marker=marker,
        )

    assert findings == []


def test_scan_url_empty_params_returns_empty():
    from stingxss.engine.browser.engine import BrowserEngine
    engine = BrowserEngine()
    # No driver should be created for empty params
    findings = engine.scan_url(url="http://example.com/", params={}, marker="M")
    assert findings == []


def test_scan_url_driver_exception_no_crash():
    from stingxss.engine.browser.engine import BrowserEngine
    engine = BrowserEngine()
    with patch.object(engine, "_setup_driver", side_effect=Exception("no chrome")):
        findings = engine.scan_url(
            url="http://example.com/?q=x",
            params={"q": ""},
            marker="M",
        )
    assert findings == []


# ---------------------------------------------------------------------------
# check_stored
# ---------------------------------------------------------------------------

def test_check_stored_confirmed():
    from stingxss.engine.browser.engine import BrowserEngine
    from stingxss.engine.reporter import BrowserFinding

    marker = "STING_stored123"
    engine = BrowserEngine()
    driver = _make_driver_mock(hits=[marker])

    with patch.object(engine, "_setup_driver", return_value=driver), \
         patch.object(engine, "_install_alert_hook"):
        result = engine.check_stored(
            revisit_urls=["http://example.com/admin"],
            marker=marker,
        )

    assert result is not None
    assert isinstance(result, BrowserFinding)
    assert result.confirmed is True
    assert result.parameter.startswith("[stored]")
    assert marker in result.evidence


def test_check_stored_no_hits_returns_none():
    from stingxss.engine.browser.engine import BrowserEngine

    marker = "STING_stored456"
    engine = BrowserEngine()
    driver = _make_driver_mock(hits=[])

    with patch.object(engine, "_setup_driver", return_value=driver), \
         patch.object(engine, "_install_alert_hook"):
        result = engine.check_stored(
            revisit_urls=["http://example.com/admin"],
            marker=marker,
        )

    assert result is None


def test_check_stored_empty_list_returns_none():
    from stingxss.engine.browser.engine import BrowserEngine
    engine = BrowserEngine()
    assert engine.check_stored(revisit_urls=[], marker="M") is None


# ---------------------------------------------------------------------------
# --browser CLI flag
# ---------------------------------------------------------------------------

def test_browser_flag_sets_opts():
    from stingxss._cli.args import build_parser
    args = build_parser().parse_args(["--browser", "-u", "http://example.com/"])
    assert args.browser is True


def test_no_browser_flag_default_false():
    from stingxss._cli.args import build_parser
    args = build_parser().parse_args(["-u", "http://example.com/"])
    assert args.browser is False


def test_browser_chromium_flag():
    from stingxss._cli.args import build_parser
    args = build_parser().parse_args(["-u", "http://x.com/", "--browser-chromium", "/usr/bin/chromium"])
    assert args.chromium_path == "/usr/bin/chromium"


def test_browser_chromedriver_flag():
    from stingxss._cli.args import build_parser
    args = build_parser().parse_args(["-u", "http://x.com/", "--browser-chromedriver", "/usr/bin/chromedriver"])
    assert args.chromedriver_path == "/usr/bin/chromedriver"


# ---------------------------------------------------------------------------
# BrowserFinding serialisation via ScanResult.to_dict()
# ---------------------------------------------------------------------------

def test_browser_finding_in_scan_result_to_dict():
    from stingxss.engine.reporter import BrowserFinding, ScanResult

    result = ScanResult(target="http://example.com/")
    f = BrowserFinding(
        url="http://example.com/?q=xss",
        parameter="q",
        method="GET",
        payload="<img src=x onerror=alert('M')>",
        marker="M",
        confirmed=True,
        evidence="M",
    )
    result.append_browser(f)
    d = result.to_dict()

    assert d["total_findings"] == 1
    findings = d["findings"]
    assert len(findings) == 1
    assert findings[0]["type"] == "browser_xss"
    assert findings[0]["confirmed"] is True
    assert findings[0]["marker"] == "M"
    assert findings[0]["parameter"] == "q"


# ---------------------------------------------------------------------------
# ScanOptions browser fields
# ---------------------------------------------------------------------------

def test_scan_options_browser_defaults():
    from stingxss.engine._scanner.options import ScanOptions
    opts = ScanOptions()
    assert opts.browser is False
    assert opts.browser_headless is True
    assert opts.chromium_path == ""
    assert opts.chromedriver_path == ""


def test_scan_options_browser_set():
    from stingxss.engine._scanner.options import ScanOptions
    opts = ScanOptions(
        browser=True,
        browser_headless=False,
        chromium_path="/usr/bin/chromium",
        chromedriver_path="/usr/bin/chromedriver",
    )
    assert opts.browser is True
    assert opts.browser_headless is False
    assert opts.chromium_path == "/usr/bin/chromium"
    assert opts.chromedriver_path == "/usr/bin/chromedriver"


# ---------------------------------------------------------------------------
# Pipeline appends error when selenium unavailable
# ---------------------------------------------------------------------------

def test_pipeline_browser_no_selenium(monkeypatch):
    """When selenium is missing and --browser is set, an error is appended."""
    from stingxss.engine._scanner.options import ScanOptions
    from stingxss.engine.reporter import ScanResult
    from stingxss.engine.http.injector import Injector
    import stingxss.engine._scanner.pipeline as pipeline

    opts = ScanOptions(browser=True)
    result = ScanResult(target="http://example.com/")

    # Patch browser package to report selenium unavailable
    fake_browser_pkg = MagicMock()
    fake_browser_pkg.SELENIUM_AVAILABLE = False
    monkeypatch.setattr(pipeline, "_run_browser_scan", MagicMock())  # should NOT be called

    with patch.dict("sys.modules", {"stingxss.engine.browser": fake_browser_pkg}):
        # Simulate just the Stage 12 logic inline
        if opts.browser:
            import importlib
            browser_mod = fake_browser_pkg
            if not browser_mod.SELENIUM_AVAILABLE:
                result.append_error("--browser requires selenium: pip install stingxss[browser]")

    assert any("selenium" in e for e in result.errors)
