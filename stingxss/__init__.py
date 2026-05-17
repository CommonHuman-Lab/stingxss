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

__version__ = "0.1.6"

BANNER = r"""
   _____ __  _            _  ____________
  / ___// /_(_)___  ____ | |/ / ___/ ___/
  \__ \/ __/ / __ \/ __ `/   /\__ \\__ \
 ___/ / /_/ / / / / /_/ /   |___/ /__/ /
/____/\__/_/_/ /_/\__, /_/|_/____/____/
                 /____/

  Every parameter is a door.
  XSS Detection Engine — CommonHuman-Lab
"""

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
