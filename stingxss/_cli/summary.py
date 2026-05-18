# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
from __future__ import annotations

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from commonhuman_cli.colour import BOLD, CYAN, DIM, GREEN, RED, YELLOW


def _proof_url(url: str, param: str, payload: str) -> str:
  try:
    p  = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [payload]
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))
  except Exception:
    return ""


def print_summary(result) -> None:
  print()
  print(BOLD("=" * 60))
  print(BOLD("  StingXSS — Scan Summary"))
  print(BOLD("=" * 60))
  print(f"  Target        : {result.target}")
  print(f"  Duration      : {result.duration_s}s")
  print(f"  Requests sent : {result.requests_sent}")
  print(f"  URLs crawled  : {result.crawled_urls}")
  print(f"  Params tested : {result.params_tested}")
  print(f"  WAF detected  : {result.waf_detected or 'None'}")
  print(f"  Evasion used  : {result.evasion_applied or 'None'}")
  print()

  if result.total_findings == 0:
    print(DIM("  No findings."))
  else:
    print(GREEN(f"  Total findings: {result.total_findings}"))
    print()
    i = 1

    for f in result.reflected:
      status = GREEN("[CONFIRMED]") if f.confirmed else YELLOW("[REFLECTED]")
      print(f"  {i}. {status} Reflected XSS")
      print(f"     Param   : {f.parameter}")
      print(f"     URL     : {f.url}")
      print(f"     Method  : {f.method}")
      print(f"     Context : {f.context}")
      print(f"     Payload : {f.payload}")
      if f.evidence:
        print(f"     Evidence: {DIM(f.evidence[:100])}")
      proof = _proof_url(f.url, f.parameter, f.payload)
      if proof:
        print(f"     Proof   : {CYAN(proof)}")
      print()
      i += 1

    _DOM_LABELS = {
      "dom_xss":               "DOM XSS",
      "dom_open_redirect":     "DOM OPEN REDIRECT",
      "link_manipulation":     "LINK MANIPULATION",
      "dom_data_manipulation": "DOM DATA MANIPULATION",
      "prototype_pollution":   "PROTOTYPE POLLUTION",
    }
    for d in result.dom:
      cat = getattr(d, "category", "dom_xss")
      label = _DOM_LABELS.get(cat, "DOM XSS")
      print(f"  {i}. {YELLOW(f'[{label}]')} {d.source} → {d.sink}")
      print(f"     URL  : {d.url}")
      if d.line:
        print(f"     Line : {d.line}")
      if d.snippet:
        print(f"     Code : {DIM(d.snippet[:120])}")
      print()
      i += 1

    for b in result.blind:
      print(f"  {i}. {CYAN('[BLIND XSS]')} Payload injected")
      print(f"     Param    : {b.parameter}")
      print(f"     URL      : {b.url}")
      print(f"     Callback : {b.callback}")
      print()
      i += 1

    for f in result.stored:
      status = GREEN("[CONFIRMED]") if f.confirmed else YELLOW("[UNCONFIRMED]")
      print(f"  {i}. {status} {RED('Stored XSS')}")
      print(f"     Param      : {f.parameter}")
      print(f"     Inject URL : {f.inject_url}")
      print(f"     Revisit URL: {f.revisit_url}")
      print(f"     Method     : {f.method}")
      print(f"     Payload    : {f.payload}")
      if f.evidence:
        print(f"     Evidence   : {DIM(f.evidence[:100])}")
      print()
      i += 1

    for f in result.graphql:
      status = GREEN("[CONFIRMED]") if f.confirmed else YELLOW("[REFLECTED]")
      print(f"  {i}. {status} {RED('GraphQL XSS')}")
      print(f"     Endpoint : {f.endpoint}")
      print(f"     Operation: {f.operation}")
      print(f"     Field    : {f.field}")
      print(f"     Payload  : {f.payload}")
      if f.evidence:
        print(f"     Evidence : {DIM(f.evidence[:100])}")
      print()
      i += 1

    for f in result.websocket:
      status = GREEN("[CONFIRMED]") if f.confirmed else YELLOW("[REFLECTED]")
      print(f"  {i}. {status} {RED('WebSocket XSS')}")
      print(f"     WS URL   : {f.ws_url}")
      print(f"     Payload  : {f.payload}")
      if f.response:
        print(f"     Response : {DIM(f.response[:100])}")
      print()
      i += 1

    for b in result.browser:
      status = GREEN("[CONFIRMED]") if b.confirmed else YELLOW("[UNCONFIRMED]")
      print(f"  {i}. {status} {RED('Browser XSS')}")
      print(f"     Param   : {b.parameter}")
      print(f"     URL     : {b.url}")
      print(f"     Payload : {b.payload}")
      if b.evidence:
        print(f"     Evidence: {DIM(b.evidence[:100])}")
      print()
      i += 1

    # Generic findings: (collection, tag, fields)
    _generic = [
      (result.clickjacking, "CLICKJACKING", lambda f: [
        f"     Reason : {f.reason}",
      ], lambda f: f.url),
      (result.hsts, "HSTS", lambda f: [
        f"     Issue  : {f.issue}",
        f"     Reason : {f.reason}",
      ], lambda f: f.url),
      (result.cors, "CORS", lambda f: [
        f"     Issue  : {f.issue}",
        f"     Reason : {f.reason}",
      ], lambda f: f.url),
      (result.sri, "SRI", lambda f: [
        f"     Issue  : {f.issue}",
        f"     Script : {f.script_src}",
      ], lambda f: f.url),
      (result.redirects, "OPEN REDIRECT", lambda f: [
        f"     Issue  : {f.issue}",
        f"     Param  : {f.parameter}",
        f"     Payload: {f.payload}",
      ], lambda f: f.url),
      (result.jsonp_some, "JSONP/SOME", lambda f: [
        f"     Issue  : {f.issue}",
        f"     Reason : {f.reason}",
      ], lambda f: f.url),
      (result.mixed_content, "MIXED CONTENT", lambda f: [
        f"     Tag      : <{f.tag}>",
        f"     Resource : {f.resource_url}",
      ], lambda f: f.url),
      (result.leaked_cookie, "LEAKED COOKIE", lambda f: [
        f"     Cookie : {f.cookie_name}",
        f"     Reason : {f.reason}",
      ], lambda f: f.url),
      (result.vuln_libs, "VULN LIB", lambda f: [
        f"     Lib      : {f.library} {f.version}",
        f"     Advisory : {f.advisory}",
      ], lambda f: f.url),
      (result.crlf, "CRLF INJECTION", lambda f: [
        f"     Vector : {f.vector}",
        f"     Param  : {f.parameter}",
        f"     Reason : {f.reason[:120]}",
      ], lambda f: f.url),
      (result.xst, "CROSS-SITE TRACING", lambda f: [
        f"     Method : {f.method}",
        f"     Reason : {f.reason[:120]}",
      ], lambda f: f.url),
    ]

    for collection, tag, extra_lines, url_fn in _generic:
      for f in collection:
        print(f"  {i}. {YELLOW(f'[{tag}]')} {url_fn(f)}")
        for line in extra_lines(f):
          print(line)
        print()
        i += 1

  if result.errors:
    print(RED("  Errors:"))
    for e in result.errors:
      print(f"    - {e}")

  print(BOLD("=" * 60))
