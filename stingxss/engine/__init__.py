# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
StingXSS — engine/__init__.py
Public API surface for the StingXSS engine.

Usage:
    from stingxss.engine import scan, ScanOptions, ScanResult
"""

from .reporter import (
  BlindFinding,
  DomFinding,
  FindingType,
  ReflectedFinding,
  ReflectionContext,
  ScanResult,
)
from .scanner import ScanOptions, scan

__all__ = [
  "scan",
  "ScanOptions",
  "ScanResult",
  "ReflectionContext",
  "FindingType",
  "ReflectedFinding",
  "DomFinding",
  "BlindFinding",
]
