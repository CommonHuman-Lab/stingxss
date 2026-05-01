"""
StingXSS — engine/reporter.py
Dataclasses and result builder for structured scan output.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class FindingType(str, Enum):
  REFLECTED_XSS  = "reflected_xss"
  DOM_XSS        = "dom_xss"
  BLIND_XSS      = "blind_xss"
  PARAM_REFLECTED = "param_reflected"  # reflected but not confirmed exploitable


class ReflectionContext(str, Enum):
  HTML_BODY       = "html_body"
  ATTR_DOUBLE     = "attr_double_quote"
  ATTR_SINGLE     = "attr_single_quote"
  ATTR_UNQUOTED   = "attr_unquoted"
  SCRIPT_STRING_D = "script_string_double"
  SCRIPT_STRING_S = "script_string_single"
  SCRIPT_BARE     = "script_bare"
  EVENT_HANDLER   = "event_handler"
  URL_ATTR        = "url_attribute"
  CSS             = "css_context"
  COMMENT         = "html_comment"
  UNKNOWN         = "unknown"


# ---------------------------------------------------------------------------
# Finding dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ReflectedFinding:
  url:       str
  parameter: str
  method:    str                  # GET / POST
  context:   ReflectionContext
  payload:   str
  confirmed: bool
  evidence:  str = ""             # snippet of response around the reflection


@dataclass
class DomFinding:
  url:    str
  source: str                     # e.g. "location.hash"
  sink:   str                     # e.g. "innerHTML"
  line:   int
  snippet: str = ""               # JS snippet around the sink


@dataclass
class BlindFinding:
  url:       str
  parameter: str
  method:    str
  payload:   str
  callback:  str


# ---------------------------------------------------------------------------
# Top-level ScanResult
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
  # --- Meta ---
  target:         str
  started_at:     float = field(default_factory=time.time)
  finished_at:    float = 0.0
  duration_s:     float = 0.0

  # --- WAF ---
  waf_detected:   Optional[str] = None
  evasion_applied: Optional[str] = None

  # --- Stats ---
  crawled_urls:   int = 0
  params_tested:  int = 0
  requests_sent:  int = 0

  # --- Findings ---
  reflected:  List[ReflectedFinding] = field(default_factory=list)
  dom:        List[DomFinding]       = field(default_factory=list)
  blind:      List[BlindFinding]     = field(default_factory=list)

  # --- Raw log ---
  log: List[str] = field(default_factory=list)

  # --- Errors ---
  errors: List[str] = field(default_factory=list)

  # --- Internal lock (not serialised) ---
  _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

  def append_reflected(self, finding: ReflectedFinding) -> None:
    with self._lock:
      self.reflected.append(finding)

  def append_dom(self, finding: DomFinding) -> None:
    with self._lock:
      self.dom.append(finding)

  def append_blind(self, finding: BlindFinding) -> None:
    with self._lock:
      self.blind.append(finding)

  def append_error(self, msg: str) -> None:
    with self._lock:
      self.errors.append(msg)

  def append_log(self, msg: str) -> None:
    with self._lock:
      self.log.append(msg)

  def finish(self) -> "ScanResult":
    self.finished_at = time.time()
    self.duration_s  = round(self.finished_at - self.started_at, 2)
    return self

  @property
  def total_findings(self) -> int:
    return len(self.reflected) + len(self.dom) + len(self.blind)

  @property
  def success(self) -> bool:
    return not bool(self.errors) or self.total_findings > 0

  def to_dict(self) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []

    for r in self.reflected:
      findings.append({
        "type":      FindingType.REFLECTED_XSS,
        "url":       r.url,
        "parameter": r.parameter,
        "method":    r.method,
        "context":   r.context,
        "payload":   r.payload,
        "confirmed": r.confirmed,
        "evidence":  r.evidence,
      })

    for d in self.dom:
      findings.append({
        "type":    FindingType.DOM_XSS,
        "url":     d.url,
        "source":  d.source,
        "sink":    d.sink,
        "line":    d.line,
        "snippet": d.snippet,
      })

    for b in self.blind:
      findings.append({
        "type":      FindingType.BLIND_XSS,
        "url":       b.url,
        "parameter": b.parameter,
        "method":    b.method,
        "payload":   b.payload,
        "callback":  b.callback,
      })

    return {
      "success":         self.success,
      "target":          self.target,
      "duration_s":      self.duration_s,
      "waf_detected":    self.waf_detected,
      "evasion_applied": self.evasion_applied,
      "crawled_urls":    self.crawled_urls,
      "params_tested":   self.params_tested,
      "requests_sent":   self.requests_sent,
      "total_findings":  self.total_findings,
      "findings":        findings,
      "errors":          self.errors,
      "log":             self.log,
    }
