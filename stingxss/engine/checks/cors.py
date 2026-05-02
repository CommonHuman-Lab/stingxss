# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
StingXSS — engine/cors.py
CORS misconfiguration detector.

Sends a series of crafted Origin header probes to the target URL and analyses
the Access-Control-Allow-Origin / Access-Control-Allow-Credentials response
headers to detect the following misconfiguration classes (matching the Google
Firing Range /cors/alloworigin/ test cases):

  1. dynamic_reflect        — blindly reflects any Origin value
  2. starts_with_bypass     — only validates origin prefix (e.g. startsWith)
  3. ends_with_bypass       — only validates origin suffix (e.g. endsWith)
  4. regex_dot_bypass       — regex uses unescaped '.' (any char matches)
  5. protocol_downgrade     — same hostname accepted over http:// as well as https://
  6. null_origin            — ACAO: null (or reflects the literal "null" origin)
  7. insecure_scheme        — accepts http:// origin for an https:// endpoint

The detector is active-only: it sends real HTTP requests with crafted Origin
headers.  Each probe is a single GET/HEAD request.

Public API
----------
  findings = check(url, injector, trusted_origin=None)

  Returns a list of CORSFinding (possibly empty if no issues are found).
"""

from __future__ import annotations

import re
import urllib.parse as up
from typing import List, Optional, Tuple

from ..reporter import CORSFinding

# ---------------------------------------------------------------------------
# Issue tag constants (used in CORSFinding.issue)
# ---------------------------------------------------------------------------
ISSUE_DYNAMIC_REFLECT    = "dynamic_reflect"
ISSUE_STARTS_WITH_BYPASS = "starts_with_bypass"
ISSUE_ENDS_WITH_BYPASS   = "ends_with_bypass"
ISSUE_REGEX_DOT_BYPASS   = "regex_dot_bypass"
ISSUE_PROTOCOL_DOWNGRADE = "protocol_downgrade"
ISSUE_NULL_ORIGIN        = "null_origin"
ISSUE_INSECURE_SCHEME    = "insecure_scheme"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check(
  url:            str,
  injector,                         # Injector instance (duck-typed)
  trusted_origin: Optional[str] = None,
) -> List[CORSFinding]:
  """
  Run all CORS probes against `url` and return a list of CORSFinding.

  Parameters
  ----------
  url            : The endpoint to probe.
  injector       : A stingxss Injector (used to send requests with custom
                   headers).  Any object with a
                   ``get(url, extra_headers=dict) -> response`` method works.
  trusted_origin : If provided, probes derived from the target's own origin
                   are generated relative to this value.  Defaults to
                   ``https://<host-of-url>``.
  """
  parsed = up.urlparse(url)
  host   = parsed.netloc  # e.g. "example.com" or "example.com:8080"
  scheme = parsed.scheme  # "https" or "http"

  if not trusted_origin:
    trusted_origin = f"{scheme}://{host}"

  findings: List[CORSFinding] = []

  # Run each probe; collect any returned finding
  probes = [
    _probe_dynamic_reflect,
    _probe_starts_with_bypass,
    _probe_ends_with_bypass,
    _probe_regex_dot_bypass,
    _probe_protocol_downgrade,
    _probe_null_origin,
    _probe_insecure_scheme,
  ]
  for probe_fn in probes:
    try:
      finding = probe_fn(url, injector, trusted_origin, host, scheme)
      if finding:
        findings.append(finding)
    except Exception:
      pass  # Network errors, timeouts, etc. — skip silently

  return findings


# ---------------------------------------------------------------------------
# Individual probes
# ---------------------------------------------------------------------------

def _probe_dynamic_reflect(
  url: str, injector, trusted_origin: str, host: str, scheme: str
) -> Optional[CORSFinding]:
  """
  Case 1: Does the server blindly reflect any Origin?
  Probe with a completely unrelated attacker origin.
  """
  attacker_origin = "https://evil.stingxss-probe.example.com"
  acao, credentials = _send(injector, url, attacker_origin)
  if acao and _origin_allowed(acao, attacker_origin):
    return CORSFinding(
      url=url,
      issue=ISSUE_DYNAMIC_REFLECT,
      reason=(
        "The server blindly reflects any Origin header value in "
        "Access-Control-Allow-Origin. An attacker on any origin can make "
        "credentialled cross-origin requests."
      ),
      origin_sent=attacker_origin,
      acao_received=acao,
      credentials=credentials,
    )
  return None


def _probe_starts_with_bypass(
  url: str, injector, trusted_origin: str, host: str, scheme: str
) -> Optional[CORSFinding]:
  """
  Case 2: startsWith validation bypass.
  Craft an origin that starts with the trusted hostname but appends an
  attacker-controlled suffix: https://<host>.evil.stingxss-probe.com
  """
  bypass_origin = f"https://{host}.evil.stingxss-probe.com"
  acao, credentials = _send(injector, url, bypass_origin)
  if acao and _origin_allowed(acao, bypass_origin):
    return CORSFinding(
      url=url,
      issue=ISSUE_STARTS_WITH_BYPASS,
      reason=(
        f"The Origin validation uses a startsWith check. An origin that begins "
        f"with the trusted hostname ({host}) but appends an attacker-controlled "
        f"domain suffix is accepted."
      ),
      origin_sent=bypass_origin,
      acao_received=acao,
      credentials=credentials,
    )
  return None


def _probe_ends_with_bypass(
  url: str, injector, trusted_origin: str, host: str, scheme: str
) -> Optional[CORSFinding]:
  """
  Case 3: endsWith validation bypass.
  Craft an origin that ends with the trusted hostname but prepends an
  attacker-controlled prefix: https://evil<host>
  """
  bypass_origin = f"https://evil{host}"
  acao, credentials = _send(injector, url, bypass_origin)
  if acao and _origin_allowed(acao, bypass_origin):
    return CORSFinding(
      url=url,
      issue=ISSUE_ENDS_WITH_BYPASS,
      reason=(
        f"The Origin validation uses an endsWith check. An origin that ends "
        f"with the trusted hostname ({host}) but prepends an attacker-controlled "
        f"domain prefix is accepted."
      ),
      origin_sent=bypass_origin,
      acao_received=acao,
      credentials=credentials,
    )
  return None


def _probe_regex_dot_bypass(
  url: str, injector, trusted_origin: str, host: str, scheme: str
) -> Optional[CORSFinding]:
  """
  Case 4: Regex with unescaped '.' bypass.
  Replace the first dot in the hostname with 'X': https://wwwXgoogle.com
  The unescaped '.' in the regex matches any character.
  """
  # Replace every '.' with 'X' in the host to form the bypass origin
  bypass_host   = host.replace(".", "X", 1)  # replace only the first dot
  bypass_origin = f"https://{bypass_host}"
  acao, credentials = _send(injector, url, bypass_origin)
  if acao and _origin_allowed(acao, bypass_origin):
    return CORSFinding(
      url=url,
      issue=ISSUE_REGEX_DOT_BYPASS,
      reason=(
        "The Origin validation uses a regex with an unescaped '.', which "
        "matches any character. An origin with the dot replaced by another "
        f"character ({bypass_origin}) is accepted."
      ),
      origin_sent=bypass_origin,
      acao_received=acao,
      credentials=credentials,
    )
  return None


def _probe_protocol_downgrade(
  url: str, injector, trusted_origin: str, host: str, scheme: str
) -> Optional[CORSFinding]:
  """
  Case 5: Protocol downgrade — http:// accepted where https:// is the target.
  Only relevant when the target scheme is https.
  """
  if scheme != "https":
    return None
  http_origin = f"http://{host}"
  acao, credentials = _send(injector, url, http_origin)
  if acao and _origin_allowed(acao, http_origin):
    return CORSFinding(
      url=url,
      issue=ISSUE_PROTOCOL_DOWNGRADE,
      reason=(
        "The Origin validation checks only the hostname and port, not the "
        "scheme. An http:// origin is accepted for an https:// endpoint, "
        "enabling SSL stripping attacks."
      ),
      origin_sent=http_origin,
      acao_received=acao,
      credentials=credentials,
    )
  return None


def _probe_null_origin(
  url: str, injector, trusted_origin: str, host: str, scheme: str
) -> Optional[CORSFinding]:
  """
  Case 6: null origin accepted.
  A response of ACAO: null grants access to sandboxed iframes and data: URIs.
  """
  acao, credentials = _send(injector, url, "null")
  if acao and acao.strip().lower() == "null":
    return CORSFinding(
      url=url,
      issue=ISSUE_NULL_ORIGIN,
      reason=(
        "The server returns Access-Control-Allow-Origin: null. Allowing the "
        "'null' origin grants cross-origin access to sandboxed iframes and "
        "data: URIs, which is equivalent to allowing any origin."
      ),
      origin_sent="null",
      acao_received=acao,
      credentials=credentials,
    )
  return None


def _probe_insecure_scheme(
  url: str, injector, trusted_origin: str, host: str, scheme: str
) -> Optional[CORSFinding]:
  """
  Case 7: http:// origin accepted for an https:// resource.
  Broader than protocol_downgrade — we probe with a generic http attacker
  origin (not just the same host over http).
  """
  if scheme != "https":
    return None
  http_attacker = "http://attacker.stingxss-probe.example.com"
  acao, credentials = _send(injector, url, http_attacker)
  if acao and _origin_allowed(acao, http_attacker):
    return CORSFinding(
      url=url,
      issue=ISSUE_INSECURE_SCHEME,
      reason=(
        "The server accepts an http:// origin for an https:// endpoint "
        "(Access-Control-Allow-Origin reflects the insecure origin). "
        "This defeats TLS protections by allowing a network attacker to "
        "perform credentialled cross-origin requests."
      ),
      origin_sent=http_attacker,
      acao_received=acao,
      credentials=credentials,
    )
  return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _send(injector, url: str, origin: str) -> Tuple[str, bool]:
  """
  Send a GET request with the given Origin header.
  Returns (acao_value, credentials_bool).
  acao_value is "" when the header is absent.
  """
  resp = injector.get(url, headers={"Origin": origin})
  headers = {k.lower(): v for k, v in resp.headers.items()}
  acao        = headers.get("access-control-allow-origin", "")
  credentials = headers.get("access-control-allow-credentials", "").lower() == "true"
  return acao, credentials


def _origin_allowed(acao: str, origin: str) -> bool:
  """
  Return True if the ACAO header value effectively grants access to `origin`.
  Handles: exact match, wildcard '*', and the case where ACAO == origin.
  """
  acao = acao.strip()
  if acao == "*":
    return True
  if acao.lower() == origin.lower():
    return True
  return False
