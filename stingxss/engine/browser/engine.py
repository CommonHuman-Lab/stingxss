# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""BrowserEngine — headless Selenium-based XSS detection for JavaScript SPAs."""

from __future__ import annotations

import time
import urllib.parse
from typing import Any

from ..reporter import BrowserFinding
from ..log import get_logger

logger = get_logger("stingxss.browser")

# Payloads to test in browser — ordered by likelihood of firing.
# Backtick variants are tested first because Juice Shop's bypassSecurityTrustHtml
# renders those; single/double-quote variants cover other sinks.
_BROWSER_PAYLOADS = [
    # img onerror — fires through Angular bypassSecurityTrustHtml and plain innerHTML
    "<img src=x onerror=\"alert(`{marker}`)\">",
    "<img src=x onerror=\"alert('{marker}')\">",
    # svg onload — alternative to img
    "<svg onload=\"alert(`{marker}`)\">",
    # iframe javascript: with backticks — required for Juice Shop reflected/DOM challenges
    "<iframe src=\"javascript:alert(`{marker}`)\">",
    # iframe javascript: with single quotes — fallback
    "<iframe src=\"javascript:alert('{marker}')\">",
]

_ALERT_HOOK_JS = (
    "window._stingxss_hits=[];"
    "window.alert=window.confirm=window.prompt=function(v)"
    "{window._stingxss_hits.push(String(v));}"
)

_SPA_BOOTSTRAP_SLEEP = 2.0   # seconds to wait for Angular/Vue/React
_XSS_FIRE_SLEEP      = 3.0   # seconds to wait after navigation for XSS to fire


class BrowserEngine:
    def __init__(
        self,
        chromium_path:     str   = "",
        chromedriver_path: str   = "",
        headless:          bool  = True,
        timeout:           int   = 20,
    ) -> None:
        self.chromium_path     = chromium_path
        self.chromedriver_path = chromedriver_path
        self.headless          = headless
        self.timeout           = timeout

    def _setup_driver(self) -> Any:
        from selenium import webdriver
        from selenium.webdriver.chrome.service import Service
        from selenium.webdriver.chrome.options import Options

        opts = Options()
        if self.headless:
            opts.add_argument("--headless")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")

        # Resolve chromium binary
        chromium = self.chromium_path
        if not chromium:
            import shutil
            for candidate in ("/usr/bin/chromium", "chromium", "google-chrome"):
                if candidate.startswith("/") or shutil.which(candidate):
                    chromium = candidate
                    break
        if chromium:
            opts.binary_location = chromium

        # Resolve chromedriver
        chromedriver = self.chromedriver_path
        if not chromedriver:
            import shutil
            for candidate in ("/usr/bin/chromedriver", "chromedriver"):
                if candidate.startswith("/") or shutil.which(candidate):
                    chromedriver = candidate
                    break

        svc = Service(chromedriver) if chromedriver else Service()
        driver = webdriver.Chrome(service=svc, options=opts)
        driver.set_page_load_timeout(self.timeout)
        return driver

    def _install_alert_hook(self, driver: Any) -> None:
        driver.execute_cdp_cmd(
            "Page.addScriptToEvaluateOnNewDocument",
            {"source": _ALERT_HOOK_JS},
        )

    def _get_hits(self, driver: Any) -> list[str]:
        try:
            hits = driver.execute_script("return window._stingxss_hits||[]")
            return hits if isinstance(hits, list) else []
        except Exception:
            return []

    def scan_url(
        self,
        url:      str,
        params:   dict[str, str],
        marker:   str,
        headers:  dict[str, str] | None = None,
        cookies:  str = "",
        base_url: str | None = None,
    ) -> list[BrowserFinding]:
        """Test each param in *params* for DOM/reflected XSS via headless browser.

        Also automatically discovers and tests params that live inside the URL's
        hash fragment (Angular / Vue hash-router style: ``#/path?param=val``).
        """
        # Merge caller-supplied params with any hash-fragment params in the URL
        all_params = dict(_hash_params(url))
        all_params.update(params)

        findings: list[BrowserFinding] = []
        if not all_params:
            return findings

        # Derive base URL for SPA bootstrap (scheme + host)
        parsed = urllib.parse.urlparse(url)
        spa_base = base_url or f"{parsed.scheme}://{parsed.netloc}/"

        driver = None
        try:
            driver = self._setup_driver()
            self._install_alert_hook(driver)

            # Bootstrap SPA once so Angular/Vue/React is initialised
            driver.get(spa_base)
            time.sleep(_SPA_BOOTSTRAP_SLEEP)

            for param in all_params:
                payloads = [p.replace("{marker}", marker) for p in _BROWSER_PAYLOADS]
                for payload in payloads:
                    try:
                        test_url = _inject_param(url, param, payload)
                        driver.get(test_url)
                        time.sleep(_XSS_FIRE_SLEEP)
                        hits = self._get_hits(driver)
                        confirmed = any(marker in h for h in hits)
                        if confirmed:
                            evidence = next(h for h in hits if marker in h)
                            findings.append(BrowserFinding(
                                url=test_url,
                                parameter=param,
                                method="GET",
                                payload=payload,
                                marker=marker,
                                confirmed=True,
                                evidence=evidence,
                            ))
                            logger.info(
                                "Browser XSS confirmed: param=%s url=%s marker=%s",
                                param, test_url, marker,
                            )
                            break  # one confirmed payload per param is enough
                    except Exception as exc:
                        logger.debug("Browser probe error (param=%s): %s", param, exc)
                        # Recover: reinstall hook and re-bootstrap
                        try:
                            self._install_alert_hook(driver)
                            driver.get(spa_base)
                            time.sleep(_SPA_BOOTSTRAP_SLEEP)
                        except Exception:
                            pass
        except Exception as exc:
            logger.warning("BrowserEngine.scan_url failed: %s", exc)
        finally:
            if driver:
                try:
                    driver.quit()
                except Exception:
                    pass

        return findings

    def check_stored(
        self,
        revisit_urls: list[str],
        marker:       str,
        base_url:     str | None = None,
    ) -> BrowserFinding | None:
        """Visit each URL; return a BrowserFinding if the marker fires as an alert."""
        if not revisit_urls:
            return None

        first_url = revisit_urls[0]
        parsed = urllib.parse.urlparse(first_url)
        spa_base = base_url or f"{parsed.scheme}://{parsed.netloc}/"

        driver = None
        try:
            driver = self._setup_driver()
            self._install_alert_hook(driver)

            driver.get(spa_base)
            time.sleep(_SPA_BOOTSTRAP_SLEEP)

            for revisit_url in revisit_urls:
                try:
                    driver.get(revisit_url)
                    time.sleep(_XSS_FIRE_SLEEP)
                    hits = self._get_hits(driver)
                    confirmed = any(marker in h for h in hits)
                    if confirmed:
                        evidence = next(h for h in hits if marker in h)
                        logger.info(
                            "Browser stored XSS confirmed: revisit=%s marker=%s",
                            revisit_url, marker,
                        )
                        return BrowserFinding(
                            url=revisit_url,
                            parameter=f"[stored] {revisit_url}",
                            method="GET",
                            payload="(stored)",
                            marker=marker,
                            confirmed=True,
                            evidence=evidence,
                        )
                except Exception as exc:
                    logger.debug("Browser stored probe error (%s): %s", revisit_url, exc)
        except Exception as exc:
            logger.warning("BrowserEngine.check_stored failed: %s", exc)
        finally:
            if driver:
                try:
                    driver.quit()
                except Exception:
                    pass

        return None


def _inject_param(url: str, param: str, value: str) -> str:
    """Return *url* with *param* replaced by *value*.

    Handles both regular query strings (?param=val) and hash-fragment query
    strings (#/path?param=val) — Angular / Vue / React hash routers put params
    in the fragment, which the HTTP server never sees but the browser does.
    """
    parsed = urllib.parse.urlparse(url)

    # Does the fragment contain its own query string?  (#/path?q=...)
    frag = parsed.fragment  # e.g.  "/search?q=test"
    if "?" in frag:
        frag_path, frag_qs = frag.split("?", 1)
        frag_params = urllib.parse.parse_qs(frag_qs, keep_blank_values=True)
        if param in frag_params or not parsed.query:
            # Inject into the fragment query string
            frag_params[param] = [value]
            new_frag = frag_path + "?" + urllib.parse.urlencode(frag_params, doseq=True)
            return urllib.parse.urlunparse(parsed._replace(fragment=new_frag))

    # Fall back to regular query string
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def _hash_params(url: str) -> dict[str, str]:
    """Return params found inside the hash fragment query string, if any."""
    frag = urllib.parse.urlparse(url).fragment
    if "?" not in frag:
        return {}
    _, frag_qs = frag.split("?", 1)
    return {k: (v[0] if v else "") for k, v in urllib.parse.parse_qs(frag_qs).items()}
