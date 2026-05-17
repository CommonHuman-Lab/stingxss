# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Source and sink pattern tables for DOM XSS analysis."""

from typing import List, Tuple

# Attacker-controllable sources
SOURCES: List[Tuple[str, str]] = [
  (r"location\.hash",                                              "location.hash"),
  (r"location\.search",                                            "location.search"),
  (r"location\.href",                                              "location.href"),
  (r"location\.pathname",                                          "location.pathname"),
  (r"window\.location(?![\.\[])",                                  "window.location"),
  (r"document\.referrer",                                          "document.referrer"),
  (r"document\.URL\b",                                             "document.URL"),
  (r"document\.baseURI",                                           "document.baseURI"),
  (r"document\.documentURI",                                       "document.documentURI"),
  (r"document\.URLUnencoded",                                      "document.URLUnencoded"),
  (r"document\.cookie",                                            "document.cookie"),
  (r"document\.domain",                                            "document.domain"),
  (r"window\.name",                                                "window.name"),
  (r"history\.state",                                              "history.state"),
  (r"postMessage",                                                  "postMessage"),
  (r"addEventListener\s*\(\s*['\"]message['\"]",                   "postMessage"),
  (r"\bmsg\.data\b",                                               "msg.data"),
  (r"\be\.data\b",                                                 "e.data"),
  (r"URLSearchParams",                                             "URLSearchParams"),
  (r"localStorage\.getItem",                                       "localStorage.getItem"),
  (r"localStorage\[",                                              "localStorage[key]"),
  (r"localStorage\.[a-zA-Z_$][\w$]*(?!\s*[\(\[])",                "localStorage.property"),
  (r"sessionStorage\.getItem",                                     "sessionStorage.getItem"),
  (r"sessionStorage\[",                                            "sessionStorage[key]"),
  (r"sessionStorage\.[a-zA-Z_$][\w$]*(?!\s*[\(\[])",              "sessionStorage.property"),
  (r"\bwindow\.status\b",                                          "window.status"),
  (r"\be\.target\.value\b",                                        "e.target.value"),
  (r"\bmsg\.data\.\w+",                                            "msg.data.*"),
  (r"frames\[",                                                    "frames[n].name"),
]

# ── Sink lists by category ─────────────────────────────────────────────────

# HTML/JS execution sinks — can lead to arbitrary code execution (DOM XSS)
XSS_SINKS: List[Tuple[str, str]] = [
  (r"\.innerHTML\s*=",                                             "innerHTML"),
  (r"\.outerHTML\s*=",                                             "outerHTML"),
  (r"\.insertAdjacentHTML\s*\(",                                   "insertAdjacentHTML"),
  (r"document\.write\s*\(",                                        "document.write"),
  (r"document\.writeln\s*\(",                                      "document.writeln"),
  (r"\beval\s*\(",                                                 "eval"),
  (r"setTimeout\s*\(\s*['\"`]",                                    "setTimeout(string)"),
  (r"setTimeout\s*\(\s*(?!function\b)[a-zA-Z_$][\w$]*\s*,",       "setTimeout(variable)"),
  (r"setInterval\s*\(\s*['\"`]",                                   "setInterval(string)"),
  (r"new\s+Function\s*\(",                                         "new Function()"),
  (r"\.setAttribute\s*\(\s*['\"]on",                               "setAttribute(on...)"),
  (r"\.setAttribute\s*\(\s*['\"]src",                              "setAttribute(src)"),
  (r"\.setAttribute\s*\(\s*['\"]href",                             "setAttribute(href)"),
  (r"\.setAttribute\s*\(\s*['\"]action",                           "setAttribute(action)"),
  (r"\.createContextualFragment\s*\(",                             "createContextualFragment"),
  (r"\$\s*\(\s*['\"`][^'\"`]*location",                            "jQuery(location...)"),
  (r"\.html\s*\(",                                                 "jQuery.html()"),
  (r"dangerouslySetInnerHTML",                                     "React dangerouslySetInnerHTML"),
  (r"document\.execCommand\s*\(",                                  "document.execCommand"),
  (r"\$\$?\.globalEval\s*\(",                                      "$.globalEval()"),
  (r"angular\.element.*\.html\s*\(",                               "angular.html()"),
  (r"(?:\$parse\s*\(|get\s*\(\s*['\"]?\$parse['\"]?\s*\))",       "$parse()"),
  (r"\bfetch\s*\(",                                                "fetch()"),
  (r"(?:xhttp|xhr|req)\s*\.open\s*\(",                            "xhr.open()"),
  (r"\.setAttributeNS\s*\(",                                       "setAttributeNS()"),
  (r"\.srcdoc\s*=",                                                ".srcdoc="),
  (r"\.data\s*=",                                                  ".data="),
]

# DOM-based open redirect sinks — source-controlled navigation target
REDIRECT_SINKS: List[Tuple[str, str]] = [
  (r"location\.href\s*=",                                          "location.href="),
  (r"document\.location\s*=",                                      "document.location="),
  (r"location\.replace\s*\(",                                      "location.replace()"),
  (r"location\.assign\s*\(",                                       "location.assign()"),
  (r"window\.open\s*\(",                                           "window.open()"),
  (r"(?<!\w)location\s*=\s*[^=]",                                  "location="),
]

# Link / URL-attribute manipulation sinks — source-controlled navigable attribute
LINK_SINKS: List[Tuple[str, str]] = [
  (r"(?<!location)\.href\s*=",                                     ".href="),
  (r"\.src\s*=",                                                   ".src="),
  (r"\.action\s*=",                                                ".action="),
  (r"\.formAction\s*=",                                            ".formAction="),
]

# DOM data manipulation sinks — source-controlled data flows into DOM without execution
DATA_SINKS: List[Tuple[str, str]] = [
  (r"\.textContent\s*=",                                           "textContent="),
  (r"\.innerText\s*=",                                             "innerText="),
  (r"\.value\s*=",                                                 "element.value="),
  (r"\.setAttribute\s*\(\s*['\"](?:class|id|name|title|data-)",   "setAttribute(class/id/data-*)"),
  (r"\.placeholder\s*=",                                           "element.placeholder="),
]

# Prototype pollution sinks — attacker-controlled data deeply merged into Object.prototype
PP_SINKS: List[Tuple[str, str]] = [
  (r"\$\.extend\s*\(\s*true",                                      "$.extend(true,...)"),
  (r"_\.merge\s*\(",                                               "_.merge()"),
  (r"_\.defaultsDeep\s*\(",                                        "_.defaultsDeep()"),
  (r"\bdeepmerge\s*\(",                                            "deepmerge()"),
  (r"(?:merge|extend)\s*\(\s*(?:\{\}|Object\.create\b)",           "merge({})"),
]

# Legacy alias — kept so any code that does `from .patterns import SINKS` still works.
# Points to XSS_SINKS only; prefer ALL_SINKS for new code.
SINKS = XSS_SINKS

# Comprehensive tagged sink list: (pattern, name, category)
# category values: dom_xss | dom_open_redirect | link_manipulation | dom_data_manipulation | prototype_pollution
ALL_SINKS: List[Tuple[str, str, str]] = (
    [(p, n, "dom_xss")               for p, n in XSS_SINKS] +
    [(p, n, "dom_open_redirect")     for p, n in REDIRECT_SINKS] +
    [(p, n, "link_manipulation")     for p, n in LINK_SINKS] +
    [(p, n, "dom_data_manipulation") for p, n in DATA_SINKS] +
    [(p, n, "prototype_pollution")   for p, n in PP_SINKS]
)
