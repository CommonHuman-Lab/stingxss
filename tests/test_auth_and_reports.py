# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Tests for HTTP auth wiring and report output flags.
Covers: ScanOptions, scanner.py auth path, CLI parser, __main__ report blocks.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open


# ---------------------------------------------------------------------------
# ScanOptions — auth fields
# ---------------------------------------------------------------------------

class TestScanOptionsAuth:
  def test_auth_type_default_empty(self):
    from stingxss.engine._scanner.options import ScanOptions
    opts = ScanOptions()
    assert opts.auth_type == ""

  def test_auth_cred_default_empty(self):
    from stingxss.engine._scanner.options import ScanOptions
    opts = ScanOptions()
    assert opts.auth_cred == ""

  def test_auth_type_stored_lowercase(self):
    from stingxss.engine._scanner.options import ScanOptions
    opts = ScanOptions(auth_type="Basic")
    assert opts.auth_type == "basic"

  def test_auth_cred_stored_stripped(self):
    from stingxss.engine._scanner.options import ScanOptions
    opts = ScanOptions(auth_cred="  user:pass  ")
    assert opts.auth_cred == "user:pass"

  def test_auth_type_and_cred_round_trip(self):
    from stingxss.engine._scanner.options import ScanOptions
    opts = ScanOptions(auth_type="digest", auth_cred="alice:s3cr3t")
    assert opts.auth_type == "digest"
    assert opts.auth_cred == "alice:s3cr3t"


# ---------------------------------------------------------------------------
# scanner.py — auth wiring into Injector
# ---------------------------------------------------------------------------

class TestScannerAuthWiring:
  def _run_scan(self, opts, mock_http_auth=None):
    """Run scan() with a no-op pipeline and return the Injector kwargs."""
    from stingxss.engine.scanner import scan

    injector_kwargs: dict = {}

    real_injector_init = None

    def capture_injector(**kwargs):
      injector_kwargs.update(kwargs)
      inst = MagicMock()
      inst.request_count = 0
      return inst

    patches = [
      patch("stingxss.engine.scanner.Injector", side_effect=capture_injector),
      patch("stingxss.engine._scanner.pipeline.run"),
    ]
    if mock_http_auth is not None:
      patches.append(
        patch("stingxss.engine.scanner.http_auth", mock_http_auth, create=True)
      )

    # We patch the import inside scanner.py
    with patch("stingxss.engine._scanner.pipeline.run"):
      with patch("stingxss.engine.scanner.Injector", side_effect=capture_injector):
        scan("https://example.com/", opts)

    return injector_kwargs

  def test_no_auth_passes_none_to_injector(self):
    from stingxss.engine._scanner.options import ScanOptions
    opts = ScanOptions()
    kwargs = self._run_scan(opts)
    assert kwargs.get("auth") is None

  def test_auth_set_calls_http_auth_and_passes_result(self):
    from stingxss.engine._scanner.options import ScanOptions
    from stingxss.engine.scanner import scan

    fake_auth_obj = object()
    captured: dict = {}

    def fake_injector(**kwargs):
      captured.update(kwargs)
      inst = MagicMock()
      inst.request_count = 0
      return inst

    with patch("stingxss.engine._scanner.pipeline.run"):
      with patch("stingxss.engine.scanner.Injector", side_effect=fake_injector):
        with patch("commonhuman_core.auth.http_auth", return_value=fake_auth_obj):
          opts = ScanOptions(auth_type="basic", auth_cred="user:pass")
          scan("https://example.com/", opts)

    assert captured.get("auth") is fake_auth_obj

  def test_auth_type_only_no_cred_skips_http_auth(self):
    from stingxss.engine._scanner.options import ScanOptions
    from stingxss.engine.scanner import scan

    captured: dict = {}

    def fake_injector(**kwargs):
      captured.update(kwargs)
      inst = MagicMock()
      inst.request_count = 0
      return inst

    with patch("stingxss.engine._scanner.pipeline.run"):
      with patch("stingxss.engine.scanner.Injector", side_effect=fake_injector):
        with patch("commonhuman_core.auth.http_auth") as mock_ha:
          opts = ScanOptions(auth_type="basic", auth_cred="")
          scan("https://example.com/", opts)
          mock_ha.assert_not_called()

    assert captured.get("auth") is None


# ---------------------------------------------------------------------------
# CLI parser — auth and report flags
# ---------------------------------------------------------------------------

class TestParserAuthFlags:
  def _parser(self):
    from stingxss._cli.args import build_parser
    return build_parser()

  def test_auth_type_basic(self):
    args = self._parser().parse_args(["--auth-type", "basic", "-u", "https://t.com/"])
    assert args.auth_type == "basic"

  def test_auth_type_digest(self):
    args = self._parser().parse_args(["--auth-type", "digest", "-u", "https://t.com/"])
    assert args.auth_type == "digest"

  def test_auth_type_ntlm(self):
    args = self._parser().parse_args(["--auth-type", "ntlm", "-u", "https://t.com/"])
    assert args.auth_type == "ntlm"

  def test_auth_cred_stored(self):
    args = self._parser().parse_args(["--auth-cred", "alice:secret", "-u", "https://t.com/"])
    assert args.auth_cred == "alice:secret"

  def test_auth_type_default_empty(self):
    args = self._parser().parse_args(["-u", "https://t.com/"])
    assert args.auth_type == ""

  def test_auth_cred_default_empty(self):
    args = self._parser().parse_args(["-u", "https://t.com/"])
    assert args.auth_cred == ""

  def test_invalid_auth_type_raises(self):
    import argparse
    with patch("sys.stderr"), pytest.raises(SystemExit):
      self._parser().parse_args(["--auth-type", "kerberos", "-u", "https://t.com/"])


class TestParserReportFlags:
  def _parser(self):
    from stingxss._cli.args import build_parser
    return build_parser()

  def test_report_html_stored(self):
    args = self._parser().parse_args(["--report-html", "out.html", "-u", "https://t.com/"])
    assert args.report_html == "out.html"

  def test_report_sarif_stored(self):
    args = self._parser().parse_args(["--report-sarif", "out.sarif", "-u", "https://t.com/"])
    assert args.report_sarif == "out.sarif"

  def test_report_html_default_empty(self):
    args = self._parser().parse_args(["-u", "https://t.com/"])
    assert args.report_html == ""

  def test_report_sarif_default_empty(self):
    args = self._parser().parse_args(["-u", "https://t.com/"])
    assert args.report_sarif == ""


# ---------------------------------------------------------------------------
# interactive_prompts() — new fields present in returned namespace
# ---------------------------------------------------------------------------

def _interactive_ns():
  """Run interactive_prompts() with safe mocks that avoid infinite loops.

  The header-collection loop runs `while True` and breaks only on a blank
  return value, so _prompt must return "" for every call after the URL.
  """
  from stingxss._cli.args import interactive_prompts
  # First call → URL; all subsequent calls → "" (skip all optional prompts)
  prompt_values = ["https://t.com/"] + [""] * 30
  with patch("stingxss._cli.args._prompt", side_effect=prompt_values):
    with patch("stingxss._cli.args._prompt_bool", return_value=False):
      with patch("stingxss._cli.args._section"):
        return interactive_prompts()


class TestInteractivePromptsNewFields:
  def test_auth_type_present_in_namespace(self):
    ns = _interactive_ns()
    assert hasattr(ns, "auth_type")
    assert ns.auth_type == ""

  def test_auth_cred_present_in_namespace(self):
    ns = _interactive_ns()
    assert hasattr(ns, "auth_cred")
    assert ns.auth_cred == ""

  def test_report_html_present_in_namespace(self):
    ns = _interactive_ns()
    assert hasattr(ns, "report_html")
    assert ns.report_html == ""

  def test_report_sarif_present_in_namespace(self):
    ns = _interactive_ns()
    assert hasattr(ns, "report_sarif")
    assert ns.report_sarif == ""


# ---------------------------------------------------------------------------
# __main__ — HTML and SARIF report writing blocks
# ---------------------------------------------------------------------------

import pytest


def _fake_result(total: int = 1) -> MagicMock:
  r = MagicMock()
  r.total_findings = total
  r.to_dict.return_value = {
    "target": "https://t.com/",
    "findings": [],
  }
  return r


class TestMainHtmlReport:
  def _run_main_report(self, tmp_path, extra_args=None):
    """Invoke main() with mocked scan and capture the HTML write."""
    from stingxss.__main__ import main

    html_file = str(tmp_path / "report.html")
    argv = [
      "stingxss",
      "-u", "https://t.com/",
      "--report-html", html_file,
      "--quiet",
    ] + (extra_args or [])

    fake_result = _fake_result(total=0)

    with patch("sys.argv", argv):
      with patch("stingxss.__main__.scan", return_value=fake_result):
        with patch("commonhuman_cli.report_html.render_html", return_value="<html/>") as mock_rh:
          main()

    return html_file, mock_rh

  def test_html_report_file_written(self, tmp_path):
    from stingxss.__main__ import main
    html_file = str(tmp_path / "report.html")
    fake_result = _fake_result(total=0)
    with patch("sys.argv", ["stingxss", "-u", "https://t.com/", "--report-html", html_file, "--quiet"]):
      with patch("stingxss.__main__.scan", return_value=fake_result):
        with patch("commonhuman_cli.report_html.render_html", return_value="<html>test</html>"):
          with pytest.raises(SystemExit):
            main()
    assert Path(html_file).exists()
    assert "<html>test</html>" in Path(html_file).read_text()

  def test_html_report_oserror_handled(self, tmp_path):
    from stingxss.__main__ import main
    fake_result = _fake_result(total=0)
    with patch("sys.argv", ["stingxss", "-u", "https://t.com/", "--report-html", "/no/such/dir/r.html", "--quiet"]):
      with patch("stingxss.__main__.scan", return_value=fake_result):
        with patch("commonhuman_cli.report_html.render_html", return_value="<html/>"):
          with pytest.raises(SystemExit):
            main()  # should not crash — OSError is caught internally


class TestMainSarifReport:
  def test_sarif_report_file_written(self, tmp_path):
    from stingxss.__main__ import main
    sarif_file = str(tmp_path / "results.sarif")
    fake_result = _fake_result(total=0)
    fake_sarif = {"version": "2.1.0", "runs": []}
    with patch("sys.argv", ["stingxss", "-u", "https://t.com/", "--report-sarif", sarif_file, "--quiet"]):
      with patch("stingxss.__main__.scan", return_value=fake_result):
        with patch("commonhuman_cli.report_sarif.render_sarif", return_value=fake_sarif):
          with pytest.raises(SystemExit):
            main()
    assert Path(sarif_file).exists()
    data = json.loads(Path(sarif_file).read_text())
    assert data["version"] == "2.1.0"

  def test_sarif_report_oserror_handled(self, tmp_path):
    from stingxss.__main__ import main
    fake_result = _fake_result(total=0)
    fake_sarif = {"version": "2.1.0", "runs": []}
    with patch("sys.argv", ["stingxss", "-u", "https://t.com/", "--report-sarif", "/no/such/dir/r.sarif", "--quiet"]):
      with patch("stingxss.__main__.scan", return_value=fake_result):
        with patch("commonhuman_cli.report_sarif.render_sarif", return_value=fake_sarif):
          with pytest.raises(SystemExit):
            main()  # OSError caught internally — no crash
