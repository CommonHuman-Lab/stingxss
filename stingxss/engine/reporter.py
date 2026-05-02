# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""StingXSS — engine/reporter.py — scan result dataclasses and serialisation."""

from __future__ import annotations

import dataclasses
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class FindingType(str, Enum):
  REFLECTED_XSS   = "reflected_xss"
  STORED_XSS      = "stored_xss"
  DOM_XSS         = "dom_xss"
  BLIND_XSS       = "blind_xss"
  PARAM_REFLECTED = "param_reflected"
  CLICKJACKING    = "clickjacking"
  CORS            = "cors"
  JSONP_SOME      = "jsonp_some"
  MIXED_CONTENT   = "mixed_content"
  LEAKED_COOKIE   = "leaked_cookie"
  OPEN_REDIRECT   = "open_redirect"
  HSTS            = "hsts"
  VULN_LIB        = "vuln_lib"
  SRI_MISSING     = "sri_missing"
  BROWSER_XSS     = "browser_xss"


class ReflectionContext(str, Enum):
  HTML_BODY            = "html_body"
  ATTR_DOUBLE          = "attr_double_quote"
  ATTR_SINGLE          = "attr_single_quote"
  ATTR_UNQUOTED        = "attr_unquoted"
  SCRIPT_STRING_D      = "script_string_double"
  SCRIPT_STRING_S      = "script_string_single"
  SCRIPT_BARE          = "script_bare"
  SCRIPT_TEMPLATE      = "script_template_literal"
  EVENT_HANDLER        = "event_handler"
  URL_ATTR             = "url_attribute"
  SCRIPT_SRC           = "script_src"           # <script src="MARKER">
  CSS                  = "css_context"
  COMMENT              = "html_comment"
  ANGULAR_TEMPLATE     = "angular_template"     # {{ MARKER }} on ng-app page
  ANGULAR_TEMPLATE_ALT = "angular_template_alt" # [[ MARKER ]] custom delimiters
  ANGULAR_ATTR         = "angular_attr"          # ng-* attribute value
  TEXTAREA             = "textarea"
  TAG_NAME             = "tag_name"
  ATTR_NAME            = "attr_name"
  CSS_VALUE            = "css_value"
  SCRIPT_REGEX         = "script_regex"
  SCRIPT_COMMENT       = "script_comment"
  TITLE                = "title"
  IFRAME_SRCDOC        = "iframe_srcdoc"
  NOSCRIPT             = "noscript"
  OBJECT_DATA          = "object_data"
  VUE_TEMPLATE         = "vue_template"         # {{ MARKER }} on Vue-app page
  JS_HOISTING          = "js_hoisting"           # eval(name) / window.name hoisting
  DANGLING_MARKUP      = "dangling_markup"       # scriptless data-exfil via open tags
  UNKNOWN              = "unknown"


# ---------------------------------------------------------------------------
# Finding dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ReflectedFinding:
  url:       str
  parameter: str
  method:    str
  context:   ReflectionContext
  payload:   str
  confirmed: bool
  evidence:  str = ""


@dataclass
class DomFinding:
  url:     str
  source:  str
  sink:    str
  line:    int
  snippet: str = ""


@dataclass
class BlindFinding:
  url:       str
  parameter: str
  method:    str
  payload:   str
  callback:  str


@dataclass
class StoredFinding:
  """Confirmed stored XSS: payload injected via one request, detected on a subsequent visit."""
  inject_url:  str
  revisit_url: str
  parameter:   str
  method:      str
  payload:     str
  confirmed:   bool
  evidence:    str = ""


@dataclass
class BrowserFinding:
  url:       str
  parameter: str
  method:    str
  payload:   str
  marker:    str
  confirmed: bool
  evidence:  str = ""


@dataclass
class HstsFinding:
  url:          str
  issue:        str
  reason:       str
  header_value: str


@dataclass
class ClickjackingFinding:
  url:        str
  reason:     str
  xfo_header: str = ""
  csp_header: str = ""


@dataclass
class CORSFinding:
  url:           str
  issue:         str
  reason:        str
  origin_sent:   str
  acao_received: str
  credentials:   bool = False


@dataclass
class OpenRedirectFinding:
  url:       str
  parameter: str
  method:    str
  issue:     str
  payload:   str
  location:  str
  reason:    str


# ---------------------------------------------------------------------------
# Finding type → list attribute mapping (used by to_dict and total_findings)
# ---------------------------------------------------------------------------

_FINDING_LISTS: List[tuple[str, FindingType]] = [
  ("reflected",     FindingType.REFLECTED_XSS),
  ("stored",        FindingType.STORED_XSS),
  ("dom",           FindingType.DOM_XSS),
  ("blind",         FindingType.BLIND_XSS),
  ("clickjacking",  FindingType.CLICKJACKING),
  ("cors",          FindingType.CORS),
  ("jsonp_some",    FindingType.JSONP_SOME),
  ("mixed_content", FindingType.MIXED_CONTENT),
  ("leaked_cookie", FindingType.LEAKED_COOKIE),
  ("redirects",     FindingType.OPEN_REDIRECT),
  ("hsts",          FindingType.HSTS),
  ("vuln_libs",     FindingType.VULN_LIB),
  ("sri",           FindingType.SRI_MISSING),
  ("browser",       FindingType.BROWSER_XSS),
]


# ---------------------------------------------------------------------------
# Top-level ScanResult
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
  # Meta
  target:          str
  started_at:      float = field(default_factory=time.time)
  finished_at:     float = 0.0
  duration_s:      float = 0.0

  # WAF
  waf_detected:    Optional[str] = None
  evasion_applied: Optional[str] = None

  # Stats
  crawled_urls:    int = 0
  params_tested:   int = 0
  requests_sent:   int = 0

  # Findings
  reflected:     List[ReflectedFinding]    = field(default_factory=list)
  stored:        List[StoredFinding]       = field(default_factory=list)
  dom:           List[DomFinding]          = field(default_factory=list)
  blind:         List[BlindFinding]        = field(default_factory=list)
  clickjacking:  List[ClickjackingFinding] = field(default_factory=list)
  cors:          List[CORSFinding]         = field(default_factory=list)
  jsonp_some:    List[Any]                 = field(default_factory=list)
  mixed_content: List[Any]                 = field(default_factory=list)
  leaked_cookie: List[Any]                 = field(default_factory=list)
  redirects:     List[OpenRedirectFinding] = field(default_factory=list)
  hsts:          List[HstsFinding]         = field(default_factory=list)
  vuln_libs:     List[Any]                 = field(default_factory=list)
  sri:           List[Any]                 = field(default_factory=list)
  browser:       List[Any]                 = field(default_factory=list)

  log:    List[str] = field(default_factory=list)
  errors: List[str] = field(default_factory=list)

  _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

  # --- Append helpers -------------------------------------------------------

  def _append(self, attr: str, finding: Any) -> None:
    with self._lock:
      getattr(self, attr).append(finding)

  def append_reflected(self, f)     -> None: self._append("reflected", f)
  def append_stored(self, f)        -> None: self._append("stored", f)
  def append_dom(self, f)           -> None: self._append("dom", f)
  def append_blind(self, f)         -> None: self._append("blind", f)
  def append_clickjacking(self, f)  -> None: self._append("clickjacking", f)
  def append_cors(self, f)          -> None: self._append("cors", f)
  def append_jsonp_some(self, f)    -> None: self._append("jsonp_some", f)
  def append_mixed_content(self, f) -> None: self._append("mixed_content", f)
  def append_leaked_cookie(self, f) -> None: self._append("leaked_cookie", f)
  def append_redirect(self, f)      -> None: self._append("redirects", f)
  def append_hsts(self, f)          -> None: self._append("hsts", f)
  def append_vuln_lib(self, f)      -> None: self._append("vuln_libs", f)
  def append_sri(self, f)           -> None: self._append("sri", f)
  def append_browser(self, f)       -> None: self._append("browser", f)
  def append_error(self, msg: str)  -> None: self._append("errors", msg)
  def append_log(self, msg: str)    -> None: self._append("log", msg)

  # --- Computed properties --------------------------------------------------

  def finish(self) -> "ScanResult":
    self.finished_at = time.time()
    self.duration_s  = round(self.finished_at - self.started_at, 2)
    return self

  @property
  def total_findings(self) -> int:
    return sum(len(getattr(self, attr)) for attr, _ in _FINDING_LISTS)

  @property
  def success(self) -> bool:
    return not bool(self.errors) or self.total_findings > 0

  def to_dict(self) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    for attr, ftype in _FINDING_LISTS:
      for item in getattr(self, attr):
        d = dataclasses.asdict(item)
        # Enums are kept as their .value by asdict; add the finding type tag.
        d["type"] = ftype.value
        findings.append(d)

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
