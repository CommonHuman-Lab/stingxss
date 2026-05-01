# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
StingXSS — context-aware XSS scanner.

Quick start:

    from stingxss import scan, ScanOptions

    result = scan("https://target.com/search?q=test")
    print(result.total_findings)

    opts = ScanOptions(level=2, crawl=True)
    result = scan("https://target.com/search?q=test", opts)
"""

from stingxss.engine import scan, ScanOptions
from stingxss.engine.reporter import (
    ScanResult,
    ReflectedFinding,
    DomFinding,
    BlindFinding,
    ReflectionContext,
    FindingType,
)

__version__ = "0.2.0"

__all__ = [
    "__version__",
    "scan",
    "ScanOptions",
    "ScanResult",
    "ReflectedFinding",
    "DomFinding",
    "BlindFinding",
    "ReflectionContext",
    "FindingType",
]
