# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
# HTML / JavaScript context analyser.
# Given an HTTP response body and the injected marker, determine the
# reflection context so payload_gen can select the right payload class.

from __future__ import annotations

import html
import random
import re
import string
from typing import Optional

from ..reporter import ReflectionContext

# ---------------------------------------------------------------------------
# Unique probe marker injected during reflection testing.
# A per-process random token (16 chars) reduces false-positive risk vs a
# hardcoded static string.
# ---------------------------------------------------------------------------
PROBE_MARKER: str = "vXSS" + "".join(
    random.choices(string.ascii_lowercase + string.digits, k=12)
)

# Pre-compiled pattern for quick Angular detection
_NG_APP_RE = re.compile(r'\bng-app\b', re.IGNORECASE)

# Pre-compiled tag finders: (open_pattern, close_pattern)
_TAG_RES: dict[str, tuple[re.Pattern, re.Pattern]] = {
  tag: (
    re.compile(rf"<{tag}[\s>/]", re.IGNORECASE),
    re.compile(rf"</{tag}\s*>",  re.IGNORECASE),
  )
  for tag in ("script", "textarea", "title", "noscript", "style")
}


def page_uses_angular(body: str) -> bool:
  """Return True if the page appears to use AngularJS."""
  if _NG_APP_RE.search(body):
    return True
  if re.search(r'angular(?:js)?[\./]', body, re.IGNORECASE):
    return True
  return False


# ---------------------------------------------------------------------------
# Context detection
# ---------------------------------------------------------------------------

def find_context(body: str, marker: str = PROBE_MARKER) -> ReflectionContext:
  """
  Locate `marker` inside `body` and return the HTML/JS context it appears in.

  Strategy:
  1. Find all occurrences of the marker (case-insensitive, handles HTML-encoding).
  2. For the first occurrence, walk backwards through the raw body to determine
     the enclosing syntactic context.
  """
  # Normalise: sometimes servers HTML-encode the reflection
  normalised = html.unescape(body)

  pos = normalised.lower().find(marker.lower())
  if pos == -1:
    return ReflectionContext.UNKNOWN

  before = normalised[:pos]
  return _classify(before, normalised, pos)


def is_reflected(body: str, marker: str = PROBE_MARKER) -> bool:
  """Quick check — is the marker anywhere in the response?"""
  return marker.lower() in html.unescape(body).lower()


# ---------------------------------------------------------------------------
# Internal classifier
# ---------------------------------------------------------------------------

def _classify(before: str, full: str, pos: int) -> ReflectionContext:
  # ---- 1. Are we inside a <script> block? ---------------------------------
  last_script_open  = _rfind_tag(before, "script", opening=True)
  last_script_close = _rfind_tag(before, "script", opening=False)

  in_script = (
    last_script_open is not None
    and (last_script_close is None or last_script_close < last_script_open)
  )

  if in_script:
    # Make sure we're inside the *body* of the script, not its opening tag.
    # If there's no '>' after last_script_open, the marker is still inside
    # the opening tag (e.g. <script src="MARKER">) — defer to attribute classifier.
    tag_close_pos = before.find(">", last_script_open)
    if tag_close_pos == -1:
      # We are inside the opening <script ...> tag — fall through to attr classifier
      in_script = False

  if in_script:
    script_content = before[last_script_open:]
    return _classify_script(script_content, full[pos:pos + 30])

  # ---- 2. Are we inside an HTML comment? -----------------------------------
  if _in_comment(before):
    return ReflectionContext.COMMENT

  # ---- 3. Are we inside a <textarea> element? ------------------------------
  last_textarea_open  = _rfind_tag(before, "textarea", opening=True)
  last_textarea_close = _rfind_tag(before, "textarea", opening=False)
  in_textarea = (
    last_textarea_open is not None
    and (last_textarea_close is None or last_textarea_close < last_textarea_open)
  )
  if in_textarea:
    # Check we're in the body of textarea (past the >), not in its attributes
    tag_close_pos = before.find(">", last_textarea_open)
    if tag_close_pos != -1:
      return ReflectionContext.TEXTAREA

  # ---- 3b. Are we inside a <title> element? --------------------------------
  last_title_open  = _rfind_tag(before, "title", opening=True)
  last_title_close = _rfind_tag(before, "title", opening=False)
  in_title = (
    last_title_open is not None
    and (last_title_close is None or last_title_close < last_title_open)
  )
  if in_title:
    tag_close_pos = before.find(">", last_title_open)
    if tag_close_pos != -1:
      return ReflectionContext.TITLE

  # ---- 3c. Are we inside a <noscript> element? -----------------------------
  last_noscript_open  = _rfind_tag(before, "noscript", opening=True)
  last_noscript_close = _rfind_tag(before, "noscript", opening=False)
  in_noscript = (
    last_noscript_open is not None
    and (last_noscript_close is None or last_noscript_close < last_noscript_open)
  )
  if in_noscript:
    tag_close_pos = before.find(">", last_noscript_open)
    if tag_close_pos != -1:
      return ReflectionContext.NOSCRIPT

  # ---- 4. Are we inside a <style> block? -----------------------------------
  last_style_open  = _rfind_tag(before, "style", opening=True)
  last_style_close = _rfind_tag(before, "style", opening=False)
  in_style = (
    last_style_open is not None
    and (last_style_close is None or last_style_close < last_style_open)
  )
  if in_style:
    # Determine if we're inside a property value (after a colon) vs bare CSS
    style_body = before[before.find(">", last_style_open) + 1:]
    if _in_css_value(style_body):
      return ReflectionContext.CSS_VALUE
    return ReflectionContext.CSS

  # ---- 5. Are we inside an HTML tag attribute? ----------------------------
  attr_ctx = _classify_attribute(before, full, pos)
  if attr_ctx is not None:
    return attr_ctx

  # ---- 6. Are we used as a tag name? e.g. <MARKER> -----------------------
  # The last unclosed < is immediately followed by the marker
  last_open  = before.rfind("<")
  last_close = before.rfind(">")
  if last_open != -1 and last_close < last_open:
    tag_fragment = before[last_open + 1:].lstrip()
    if tag_fragment == "" or tag_fragment.isspace():
      # Nothing between < and the marker position
      return ReflectionContext.TAG_NAME

  # ---- 7. AngularJS template injection — marker inside {{ }} or [[ ]] ----
  angular_ctx = _classify_angular(before, full, pos)
  if angular_ctx is not None:
    return angular_ctx

  # ---- 8. Default: HTML body text -----------------------------------------
  return ReflectionContext.HTML_BODY


# ---------------------------------------------------------------------------
# Script-context classifier
# ---------------------------------------------------------------------------

def _classify_script(script_before: str, after_snippet: str) -> ReflectionContext:
  """
  Within a script block, determine whether the marker is:
  - inside a double-quoted string
  - inside a single-quoted string
  - inside a template literal
  - inside a regex literal
  - inside a block comment /* ... */
  - bare (not in any string)
  """
  # Walk the script content counting unescaped string delimiters
  in_double = False
  in_single = False
  in_template = False
  in_regex = False
  in_block_comment = False
  i = 0
  s = script_before
  while i < len(s):
    c = s[i]

    # Block comment start/end
    if not in_double and not in_single and not in_template and not in_regex:
      if s[i:i+2] == "/*":
        in_block_comment = True
        i += 2
        continue
    if in_block_comment:
      if s[i:i+2] == "*/":
        in_block_comment = False
        i += 2
        continue
      i += 1
      continue

    if c == "\\" and i + 1 < len(s):
      i += 2  # skip escaped char
      continue
    if c == '"'  and not in_single and not in_template and not in_regex:
      in_double = not in_double
    elif c == "'" and not in_double and not in_template and not in_regex:
      in_single = not in_single
    elif c == "`" and not in_double and not in_single and not in_regex:
      in_template = not in_template
    elif c == "/" and not in_double and not in_single and not in_template:
      # Heuristic: a / after =, (, [, !, &, |, return keyword, or at start
      # is likely a regex delimiter rather than division
      prev = s[:i].rstrip()
      if prev and prev[-1] in ("=", "(", "[", "!", "&", "|", ",", "{", "}", ";", "\n") \
         or prev.endswith(("return", "typeof", "in", "instanceof")):
        in_regex = not in_regex
    i += 1

  if in_block_comment:
    return ReflectionContext.SCRIPT_COMMENT
  if in_double:
    return ReflectionContext.SCRIPT_STRING_D
  if in_single:
    return ReflectionContext.SCRIPT_STRING_S
  if in_template:
    return ReflectionContext.SCRIPT_TEMPLATE
  if in_regex:
    return ReflectionContext.SCRIPT_REGEX
  return ReflectionContext.SCRIPT_BARE


# ---------------------------------------------------------------------------
# Attribute-context classifier
# ---------------------------------------------------------------------------

# Matches the last opening tag before the marker (greedy backwards search)
_LAST_TAG_RE = re.compile(r"<(\w[\w:-]*)([^>]*)$", re.DOTALL)


def _classify_attribute(before: str, full: str = "", pos: int = 0) -> Optional[ReflectionContext]:
  """
  Determine if we're inside an HTML tag attribute and which kind.
  Returns None if we're NOT inside a tag.
  """
  # Find the last unclosed < — if there's a > after the last <, we're not in a tag
  last_open  = before.rfind("<")
  last_close = before.rfind(">")

  if last_open == -1 or last_close > last_open:
    return None  # Not inside a tag

  inside_tag = before[last_open:]

  # Find the last attribute assignment (attr=["']...) to determine which
  # attribute the marker currently falls inside.
  # We search for the last occurrence of:   attrname=["']  or  attrname=
  last_attr_match = None
  for m in re.finditer(r'\b([\w:-]+)\s*=\s*(["\']?)', inside_tag, re.IGNORECASE):
    last_attr_match = m

  if last_attr_match is None:
    # Inside the tag but no attr= found yet.
    # Check if there IS a tag name already (word chars between < and here):
    tag_name_m = re.match(r"<(\w[\w:-]*)\s+", inside_tag)
    if tag_name_m:
      # Tag name is present but marker precedes any = sign → ATTR_NAME
      return ReflectionContext.ATTR_NAME
    # No tag name yet — the marker is the tag name itself.
    # Return None so _classify can handle it as TAG_NAME.
    return None

  attr_name = last_attr_match.group(1).lower()
  quote_char = last_attr_match.group(2)

  # Event handler attribute?
  if re.match(r'^on\w+$', attr_name, re.IGNORECASE):
    return ReflectionContext.EVENT_HANDLER

  # URL attribute?
  if attr_name in ("href", "src", "action", "formaction", "data",
                   "ping", "poster", "background"):
    # Special case: src inside a <script> tag is a remote JS include —
    # attacker controls which script file the browser fetches.
    tag_m = re.match(r"<(\w[\w:-]*)", inside_tag)
    if attr_name == "src" and tag_m and tag_m.group(1).lower() == "script":
      return ReflectionContext.SCRIPT_SRC
    # data= on <object> → OBJECT_DATA
    if attr_name == "data" and tag_m and tag_m.group(1).lower() == "object":
      return ReflectionContext.OBJECT_DATA
    return ReflectionContext.URL_ATTR

  # srcdoc= on <iframe> → IFRAME_SRCDOC
  if attr_name == "srcdoc":
    return ReflectionContext.IFRAME_SRCDOC

  # value= on <param> tag is a URL sink like OBJECT_DATA
  if attr_name == "value":
    tag_m = re.match(r"<(\w[\w:-]*)", inside_tag)
    if tag_m and tag_m.group(1).lower() == "param":
      return ReflectionContext.OBJECT_DATA

  # Generic attribute — determine quoting from the last attr match
  if quote_char == '"':
    return ReflectionContext.ATTR_DOUBLE
  if quote_char == "'":
    return ReflectionContext.ATTR_SINGLE
  return ReflectionContext.ATTR_UNQUOTED


# ---------------------------------------------------------------------------
# AngularJS template injection classifier
# ---------------------------------------------------------------------------

# AngularJS template injection classifier
# Detect custom interpolation symbol configuration: startSymbol / endSymbol
_NG_START_RE = re.compile(r"startSymbol\s*\(\s*['\"](.+?)['\"]", re.IGNORECASE)
_NG_END_RE   = re.compile(r"endSymbol\s*\(\s*['\"](.+?)['\"]", re.IGNORECASE)


def _classify_angular(before: str, full: str, pos: int) -> Optional[ReflectionContext]:
  """
  Return an Angular-specific context if the page uses AngularJS AND the
  marker is inside interpolation delimiters or an ng-* attribute.

  Returns None if the page does not appear to use AngularJS.
  """
  # Must have ng-app somewhere in the page
  if not _NG_APP_RE.search(full):
    return None

  # Detect custom interpolation symbols
  start_sym = "{{"
  end_sym   = "}}"
  m_start = _NG_START_RE.search(full)
  m_end   = _NG_END_RE.search(full)
  if m_start and m_end:
    start_sym = m_start.group(1)
    end_sym   = m_end.group(1)

  alt_symbols = (start_sym != "{{")

  # Check if marker is inside interpolation delimiters in the body
  # i.e. the text immediately before the marker ends with the start symbol
  # (or the marker is between start/end symbols)
  before_stripped = before.rstrip()
  if before_stripped.endswith(start_sym):
    return ReflectionContext.ANGULAR_TEMPLATE_ALT if alt_symbols else ReflectionContext.ANGULAR_TEMPLATE

  # Check if interpolation delimiters appear around the marker
  # by scanning for the last occurrence of start_sym before the marker
  last_start = before.rfind(start_sym)
  if last_start != -1:
    # Make sure there's no matching end_sym between last_start and pos
    between = before[last_start + len(start_sym):]
    if end_sym not in between:
      return ReflectionContext.ANGULAR_TEMPLATE_ALT if alt_symbols else ReflectionContext.ANGULAR_TEMPLATE

  # Check if we're inside an ng-* attribute value
  last_open  = before.rfind("<")
  last_close = before.rfind(">")
  if last_open != -1 and last_close < last_open:
    inside_tag = before[last_open:]
    # Look for the last attribute name before the marker
    last_attr_match = None
    for m in re.finditer(r'\b([\w:-]+)\s*=\s*(["\']?)', inside_tag, re.IGNORECASE):
      last_attr_match = m
    if last_attr_match:
      attr_name = last_attr_match.group(1).lower()
      if attr_name.startswith("ng-") or attr_name.startswith("data-ng-"):
        return ReflectionContext.ANGULAR_ATTR

  return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rfind_tag(text: str, tag: str, opening: bool) -> Optional[int]:
  """Return the position of the last opening or closing tag, or None."""
  pattern = _TAG_RES[tag][0 if opening else 1]
  last = None
  for m in pattern.finditer(text):
    last = m.start()
  return last


def _in_comment(before: str) -> bool:
  """True if the position is inside an HTML comment."""
  opens  = len(re.findall(r"<!--", before))
  closes = len(re.findall(r"-->", before))
  return opens > closes


def _in_css_value(style_body: str) -> bool:
  """
  Return True if the position inside a style block appears to be inside
  a CSS property *value* (i.e. after a colon and before a semicolon or
  closing brace within the current declaration).

  Heuristic: count unmatched { and }, then check if the most recent
  non-whitespace character before the marker is a colon (property value)
  rather than a { or ; (rule start).
  """
  # Walk backwards from end of style_body to find the last meaningful char
  stripped = style_body.rstrip()
  if not stripped:
    return False
  last_char = stripped[-1]
  # After a colon = property value context
  if last_char == ":":
    return True
  # After a value token (word, number, %), could be mid-value
  # Check if there's a colon somewhere in the current declaration
  # (since the last { or ;)
  last_delim = max(stripped.rfind("{"), stripped.rfind(";"))
  since_delim = stripped[last_delim + 1:] if last_delim != -1 else stripped
  if ":" in since_delim:
    return True
  return False
