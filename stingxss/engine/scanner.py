# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
# Scan entry point — wires options, injector, and pipeline together.

from __future__ import annotations

import json

from .log import ScanResultHandler, get_logger
from .http.injector import Injector
from .reporter import ScanResult
from .http import waf_detect  # noqa: F401 (patch target for tests)
from .http.injector import Injector  # noqa: F401 (patch target for tests)
from ._scanner.options import ScanOptions  # noqa: F401 (re-exported)
from ._scanner.active import test_param as _test_param  # noqa: F401 (re-exported)
from ._scanner.active import _extract_tag_literal  # noqa: F401 (re-exported)
from ._scanner.pipeline import run

logger = get_logger("stingxss.scanner")


def scan(url: str, options: ScanOptions | None = None) -> ScanResult:
  """Run a full StingXSS scan against `url` and return a ScanResult."""
  if options is None:
    options = ScanOptions()

  result   = ScanResult(target=url)
  _root    = get_logger("stingxss")
  _handler = ScanResultHandler(result)
  _handler.setFormatter(__import__("logging").Formatter("%(name)s: %(message)s"))
  _root.addHandler(_handler)

  _auth = None
  if options.auth_type and options.auth_cred:
    from commonhuman_core.auth import http_auth as _http_auth
    _auth = _http_auth(options.auth_type, options.auth_cred)

  injector = Injector(
    timeout=options.timeout,
    proxy=options.proxy or None,
    headers=options.headers or None,
    cookies=options.cookies or None,
    delay=options.delay,
    auth=_auth,
  )

  try:
    run(url, options, injector, result)
  except Exception as exc:
    result.append_error(f"Scan aborted: {exc}")
    logger.exception("StingXSS scan error")
  finally:
    _root.removeHandler(_handler)
    injector.close()
    result.requests_sent = injector.request_count
    result.finish()

  return result
