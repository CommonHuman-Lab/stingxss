# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Passive header/page checks against the seed response."""

from __future__ import annotations

from ..log import get_logger
from ..checks import clickjacking as cj_mod
from ..checks import cors as cors_mod
from ..checks import hsts as hsts_mod
from ..checks import jsonp_some as jsonp_mod
from ..checks import mixed_content as mc_mod
from ..checks import vuln_libs as vl_mod
from ..checks import sri as sri_mod
from ..checks import leaked_cookie as lc_mod
from ..http.injector import Injector
from ..reporter import ScanResult

logger = get_logger("stingxss.scanner")


def fetch_seed(injector: Injector, url: str):
  """Fetch the seed URL once; return response or None on error."""
  try:
    return injector.get(url)
  except Exception:
    return None


def run_passive_checks(url: str, seed_resp, injector: Injector, result: ScanResult) -> None:
  """Run all passive checks against the seed response."""
  headers = dict(seed_resp.headers) if seed_resp else {}
  body    = seed_resp.text if seed_resp else ""

  _check(lambda: _clickjacking(url, headers, result))
  _check(lambda: _hsts(url, headers, result))
  _check(lambda: _cors(url, injector, result))
  _check(lambda: _jsonp(url, injector, result))
  _check(lambda: _mixed_content(url, body, result))
  _check(lambda: _vuln_libs(url, body, result))
  _check(lambda: _sri(url, body, result))
  _check(lambda: _leaked_cookie(url, headers, body, injector, result))


def _check(fn):
  try:
    fn()
  except Exception:
    pass


def _clickjacking(url, headers, result):
  cj = cj_mod.check(url, headers)
  if cj:
    result.append_clickjacking(cj)
    logger.warning("Clickjacking: %s", cj.reason)
  else:
    logger.debug("Clickjacking: page appears protected against framing")


def _hsts(url, headers, result):
  for hf in hsts_mod.check(url, headers):
    result.append_hsts(hf)
    logger.warning("HSTS (%s): %s", hf.issue, hf.reason)
  if not result.hsts:
    logger.debug("HSTS: header present and well-configured")


def _cors(url, injector, result):
  for cf in cors_mod.check(url, injector):
    result.append_cors(cf)
    logger.warning("CORS (%s): %s", cf.issue, cf.reason)
  if not result.cors:
    logger.debug("CORS: no misconfigurations detected")


def _jsonp(url, injector, result):
  for jf in jsonp_mod.check(url, injector):
    result.append_jsonp_some(jf)
    logger.warning("JSONP/SOME (%s): %s", jf.issue, jf.reason)
  if not result.jsonp_some:
    logger.debug("JSONP/SOME: no callback injection detected")


def _mixed_content(url, body, result):
  for mcf in mc_mod.check(url, body):
    result.append_mixed_content(mcf)
    logger.warning("Mixed content: <%s> loads %s", mcf.tag, mcf.resource_url)
  if not result.mixed_content:
    logger.debug("Mixed content: none detected")


def _vuln_libs(url, body, result):
  for vf in vl_mod.check(url, body):
    result.append_vuln_lib(vf)
    logger.warning("Vulnerable library: %s %s (%s) @ %s", vf.library, vf.version, vf.source, url)
  if not result.vuln_libs:
    logger.debug("Vulnerable libraries: none detected")


def _sri(url, body, result):
  for sf in sri_mod.check(url, body):
    result.append_sri(sf)
    logger.warning("SRI missing (%s): %s", sf.issue, sf.script_src)
  if not result.sri:
    logger.debug("SRI: no insecure third-party scripts detected")


def _leaked_cookie(url, headers, body, injector, result):
  for lcf in lc_mod.check(url=url, response_headers=headers, response_body=body, injector=injector):
    result.append_leaked_cookie(lcf)
    logger.warning("Leaked httpOnly cookie '%s' (%s) @ %s", lcf.cookie_name, lcf.leak_type, url)
  if not result.leaked_cookie:
    logger.debug("Leaked cookie: no httpOnly cookie leaks detected")
