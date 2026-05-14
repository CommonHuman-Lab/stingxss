# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
StingXSS — engine/http/injector.py
Thin Injector subclass that adds XSS-specific probe methods.
All HTTP session handling is inherited from commonhuman_core.HttpClient.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from requests import Response

from commonhuman_core.http import HttpClient, parse_post_data
from commonhuman_core.http._cookies import parse_cookie_string as _parse_cookie_string


class Injector(HttpClient):
    """HttpClient subclass with XSS reflection probing."""

    def probe_header_reflection(
        self, url: str, header_name: str, marker: str
    ) -> Tuple[bool, Response]:
        """Probe whether ``marker`` injected via ``header_name`` is reflected."""
        resp = self.inject_header(url, header_name, marker)
        from ..analysis.parser import is_reflected
        return is_reflected(resp.text, marker), resp

    def probe_reflection(
        self,
        url: str,
        param: str,
        marker: str,
        method: str = "GET",
        base_data: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Response]:
        """Send a reflection probe for ``marker`` on ``param``.

        Strategy:
        1. Plain string probe — catches most cases.
        2. Tag-wrapping fallback probes — handles servers that validate input
           must look like a specific HTML tag (e.g. Google Firing Range /tags/*).

        Returns ``(reflected: bool, response)``.
        """
        from ..analysis.parser import is_reflected

        if method.upper() == "POST":
            resp = self.inject_post(url, param, marker, base_data)
        else:
            resp = self.inject_get(url, param, marker)

        if resp.status_code < 400 and is_reflected(resp.text, marker):
            return True, resp

        if is_reflected(resp.text, marker):
            return True, resp

        _TAG_PROBE_TEMPLATES = [
            '<img src="{marker}">',
            '<img src=x alt="{marker}">',
            '<div style="{marker}">',
            '<img src=x onerror="{marker}">',
            '<a href="{marker}">x</a>',
            '<script src="{marker}"></script>',
            '<meta name="x" content="{marker}">',
            '<body>{marker}</body>',
            '<body onload="{marker}">',
            '\n<img src="{marker}">',
            '\n<script>var x="{marker}"</script>',
        ]
        for template in _TAG_PROBE_TEMPLATES:
            probe_value = template.replace("{marker}", marker)
            try:
                if method.upper() == "POST":
                    r = self.inject_post(url, param, probe_value, base_data)
                else:
                    r = self.inject_get(url, param, probe_value)
            except Exception:
                continue
            if is_reflected(r.text, marker):
                return True, r

        return False, resp
