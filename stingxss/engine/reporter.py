# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""StingXSS — engine/reporter.py — scan result dataclasses and serialisation."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List

from commonhuman_cli.reporter import ScanResultBase
from commonhuman_cli.severity import Severity


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
    CRLF            = "crlf"
    XST             = "xst"
    GRAPHQL_XSS     = "graphql_xss"
    WEBSOCKET_XSS   = "websocket_xss"


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
    SCRIPT_SRC           = "script_src"
    CSS                  = "css_context"
    COMMENT              = "html_comment"
    ANGULAR_TEMPLATE     = "angular_template"
    ANGULAR_TEMPLATE_ALT = "angular_template_alt"
    ANGULAR_ATTR         = "angular_attr"
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
    VUE_TEMPLATE         = "vue_template"
    JS_HOISTING          = "js_hoisting"
    DANGLING_MARKUP      = "dangling_markup"
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
    severity:  str = Severity.HIGH


@dataclass
class DomFinding:
    url:      str
    source:   str
    sink:     str
    line:     int
    snippet:  str = ""
    severity: str = Severity.MEDIUM
    category: str = "dom_xss"  # dom_xss | dom_open_redirect | link_manipulation | dom_data_manipulation | prototype_pollution


@dataclass
class BlindFinding:
    url:       str
    parameter: str
    method:    str
    payload:   str
    callback:  str
    severity:  str = Severity.HIGH


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
    severity:    str = Severity.CRITICAL


@dataclass
class BrowserFinding:
    url:       str
    parameter: str
    method:    str
    payload:   str
    marker:    str
    confirmed: bool
    evidence:  str = ""
    severity:  str = Severity.HIGH


@dataclass
class HstsFinding:
    url:          str
    issue:        str
    reason:       str
    header_value: str
    severity:     str = Severity.LOW


@dataclass
class ClickjackingFinding:
    url:        str
    reason:     str
    xfo_header: str = ""
    csp_header: str = ""
    severity:   str = Severity.LOW


@dataclass
class CORSFinding:
    url:           str
    issue:         str
    reason:        str
    origin_sent:   str
    acao_received: str
    credentials:   bool = False
    severity:      str  = Severity.HIGH


@dataclass
class CRLFFinding:
    url:       str
    parameter: str
    method:    str
    vector:    str   # "param" or "header"
    payload:   str
    injected_header: str
    reason:    str
    severity:  str = Severity.MEDIUM


@dataclass
class XSTFinding:
    url:      str
    reason:   str
    method:   str = "TRACE"
    severity: str = Severity.LOW


@dataclass
class OpenRedirectFinding:
    url:       str
    parameter: str
    method:    str
    issue:     str
    payload:   str
    location:  str
    reason:    str
    severity:  str = Severity.MEDIUM


@dataclass
class GraphqlFinding:
    """XSS confirmed via GraphQL string field injection."""
    url:        str
    endpoint:   str
    field:      str       # GraphQL field name the payload was injected into
    operation:  str       # query / mutation / subscription
    payload:    str
    confirmed:  bool
    evidence:   str = ""
    severity:   str = Severity.HIGH


@dataclass
class WebsocketFinding:
    """XSS payload reflected in a WebSocket response frame."""
    url:       str
    ws_url:    str
    payload:   str
    response:  str       # response frame that contained the marker
    confirmed: bool
    severity:  str = Severity.HIGH


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
    ("crlf",          FindingType.CRLF),
    ("xst",           FindingType.XST),
    ("graphql",       FindingType.GRAPHQL_XSS),
    ("websocket",     FindingType.WEBSOCKET_XSS),
]


# ---------------------------------------------------------------------------
# Top-level ScanResult
# ---------------------------------------------------------------------------

@dataclass
class ScanResult(ScanResultBase):
    # Findings — all tool-specific, all defaulted (required field `target` is in base)
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
    crlf:          List[CRLFFinding]         = field(default_factory=list)
    xst:           List[XSTFinding]          = field(default_factory=list)
    graphql:       List[GraphqlFinding]      = field(default_factory=list)
    websocket:     List[WebsocketFinding]    = field(default_factory=list)

    # --- Append helpers -------------------------------------------------------

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
    def append_crlf(self, f)          -> None: self._append("crlf", f)
    def append_xst(self, f)           -> None: self._append("xst", f)
    def append_graphql(self, f)       -> None: self._append("graphql", f)
    def append_websocket(self, f)     -> None: self._append("websocket", f)

    # --- Computed properties --------------------------------------------------

    @property
    def total_findings(self) -> int:
        return sum(len(getattr(self, attr)) for attr, _ in _FINDING_LISTS)

    @property
    def severity_counts(self) -> Dict[str, int]:
        """Count findings per severity level across all finding lists."""
        from commonhuman_cli.severity import SEVERITY_ORDER
        counts: Dict[str, int] = {sev: 0 for sev in SEVERITY_ORDER}
        for attr, _ in _FINDING_LISTS:
            for item in getattr(self, attr):
                sev = getattr(item, "severity", None)
                if sev in counts:
                    counts[sev] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        for attr, ftype in _FINDING_LISTS:
            for item in getattr(self, attr):
                d = dataclasses.asdict(item)
                d["type"] = ftype.value
                findings.append(d)

        result = self._base_dict()
        result["total_findings"] = self.total_findings
        result["severity_counts"] = self.severity_counts
        result["findings"] = findings
        return result
