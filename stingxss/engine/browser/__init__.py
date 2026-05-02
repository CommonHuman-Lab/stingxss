# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Browser engine package — optional headless XSS detection via Selenium."""

from __future__ import annotations

try:
    from selenium import webdriver  # noqa: F401
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

from .engine import BrowserEngine
from ..reporter import BrowserFinding

__all__ = ["BrowserEngine", "BrowserFinding", "SELENIUM_AVAILABLE"]
