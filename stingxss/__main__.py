"""
StingXSS — __main__.py
Standalone CLI entry point.

Usage (from NyxStrike repo):
    python -m plugins.tools.stingxss -u https://target.com/search?q=test

Usage (from standalone StingXSS repo):
    python -m stingxss -u https://target.com/search?q=test

Run with no arguments for interactive mode.

Options:
    -u, --url          Target URL (required)
    --crawl            Enable BFS crawler
    --blind            Blind XSS callback URL
    -d, --data         POST body (urlencoded or JSON)
    -H, --header       Custom header KEY:VALUE (repeatable)
    -c, --cookie       Cookie string
    --proxy            HTTP proxy URL
    -t, --threads      Threads (default 5)
    --timeout          Request timeout seconds (default 15)
    --level            Scan depth 1-3 (default 1)
    -f, --payloads     File of custom payloads (one per line)
    --max-pages        Max pages to crawl (default 50)
    --max-depth        Max crawl depth (default 3)
    --json             Output raw JSON instead of coloured text
    -q, --quiet        Suppress live log output
"""

from __future__ import annotations

import argparse
import json
import os
import sys

try:
  # Installed package import
  from stingxss.engine import scan, ScanOptions
  from stingxss.engine.reporter import FindingType
except ImportError:
  # Direct / editable run: add the package dir to path
  _HERE = os.path.dirname(os.path.abspath(__file__))
  if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
  from engine import scan, ScanOptions
  from engine.reporter import FindingType

# ---------------------------------------------------------------------------
# ANSI colours (disabled when --json or no TTY)
# ---------------------------------------------------------------------------
_USE_COLOUR = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
  if not _USE_COLOUR:
    return text
  return f"\033[{code}m{text}\033[0m"

RED    = lambda t: _c("31;1",    t)
GREEN  = lambda t: _c("38;5;46", t)
YELLOW = lambda t: _c("33;1",    t)
CYAN   = lambda t: _c("36",      t)
BOLD   = lambda t: _c("1",       t)
DIM    = lambda t: _c("2",       t)

BANNER = r"""
   _____ __  _            _  ____________
  / ___// /_(_)___  ____ | |/ / ___/ ___/
  \__ \/ __/ / __ \/ __ `/   /\__ \\__ \ 
 ___/ / /_/ / / / / /_/ /   |___/ /__/ / 
/____/\__/_/_/ /_/\__, /_/|_/____/____/  
                 /____/                  

  Every parameter is a door.
  XSS Detection Engine — CommonHuman-Lab
"""


# ---------------------------------------------------------------------------
# Interactive prompt helper
# ---------------------------------------------------------------------------

def _prompt(label: str, default: str = "", hint: str = "") -> str:
  """Print a styled prompt and return stripped input. Enter accepts default."""
  hint_str = f"  {DIM(hint)}" if hint else ""
  if default:
    display = f"{BOLD(label)} {DIM(f'[{default}]')}{hint_str}: "
  else:
    display = f"{BOLD(label)}{hint_str}: "
  try:
    val = input(display).strip()
  except (EOFError, KeyboardInterrupt):
    print()
    sys.exit(0)
  return val if val else default


def _prompt_bool(label: str, default: bool = False) -> bool:
  default_str = "Y/n" if default else "y/N"
  display = f"{BOLD(label)} {DIM(f'[{default_str}]')}: "
  try:
    val = input(display).strip().lower()
  except (EOFError, KeyboardInterrupt):
    print()
    sys.exit(0)
  if not val:
    return default
  return val in ("y", "yes", "1", "true")


def _section(title: str) -> None:
  print()
  print(DIM("  ─── " + title + " " + "─" * max(0, 40 - len(title))))


def interactive_prompts() -> argparse.Namespace:
  """Walk the user through all scan options interactively."""
  print(CYAN(BANNER))
  print(DIM("  No arguments supplied — entering interactive mode."))
  print(DIM("  Press Enter to accept defaults. Ctrl+C to exit.\n"))

  # Required
  _section("Target")
  url = ""
  while not url:
    url = _prompt("  Target URL", hint="e.g. https://target.com/search?q=test")
    if not url:
      print(YELLOW("  [!] URL is required."))
    elif not url.startswith(("http://", "https://")):
      print(YELLOW("  [!] URL must start with http:// or https://"))
      url = ""

  # Auth
  _section("Authentication  (optional)")
  cookie  = _prompt("  Cookies", hint="name=val; name2=val2")
  headers_raw: list[str] = []
  while True:
    h = _prompt("  Header", hint="KEY:VALUE  (blank to finish)")
    if not h:
      break
    headers_raw.append(h)

  # Request
  _section("Request")
  data   = _prompt("  POST body", hint="form-encoded or JSON  (blank = GET)")
  proxy  = _prompt("  Proxy", hint="http://127.0.0.1:8080")

  # Scan options
  _section("Scan options")
  level_str   = _prompt("  Scan level", default="1", hint="1=fast  2=thorough  3=deep")
  threads_str = _prompt("  Threads",    default="5")
  timeout_str = _prompt("  Timeout",    default="15", hint="seconds per request")

  crawl = _prompt_bool("  Enable crawler", default=False)
  if crawl:
    max_pages_str = _prompt("  Max pages",  default="50")
    max_depth_str = _prompt("  Max depth",  default="3")
  else:
    max_pages_str = "50"
    max_depth_str = "3"

  blind = _prompt("  Blind XSS callback", hint="https://your.interactsh.io/x  (blank to skip)")
  payloads_file = _prompt("  Custom payloads file", hint="path to file, one payload per line")

  print()

  # Build a Namespace that matches what build_parser() produces
  ns = argparse.Namespace(
    url=url,
    crawl=crawl,
    blind=blind,
    data=data,
    header=headers_raw,
    cookie=cookie,
    proxy=proxy,
    threads=_safe_int(threads_str, 5, 1, 20),
    timeout=_safe_int(timeout_str, 15, 5, 120),
    level=_safe_int(level_str, 1, 1, 3),
    payloads=payloads_file,
    max_pages=_safe_int(max_pages_str, 50, 1, 500),
    max_depth=_safe_int(max_depth_str, 3, 1, 10),
    json_output=False,
    quiet=False,
  )
  return ns


def _safe_int(val: str, default: int, lo: int, hi: int) -> int:
  try:
    return max(lo, min(int(val), hi))
  except (TypeError, ValueError):
    return default


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
  p = argparse.ArgumentParser(
    prog="stingxss",
    description="StingXSS — native context-aware XSS scanner",
    formatter_class=argparse.RawDescriptionHelpFormatter,
  )
  p.add_argument("-u", "--url",      default="",     help="Target URL")
  p.add_argument("--crawl",          action="store_true", help="Enable BFS crawler")
  p.add_argument("--blind",          default="",     metavar="URL",
                 help="Blind XSS callback URL")
  p.add_argument("-d", "--data",     default="",     help="POST body")
  p.add_argument("-H", "--header",   action="append", default=[], metavar="KEY:VALUE",
                 help="Custom header (repeatable)")
  p.add_argument("-c", "--cookie",   default="",     help="Cookie string")
  p.add_argument("--proxy",          default="",     help="HTTP proxy URL")
  p.add_argument("-t", "--threads",  type=int, default=5)
  p.add_argument("--timeout",        type=int, default=15)
  p.add_argument("--level",          type=int, default=1, choices=[1, 2, 3])
  p.add_argument("-f", "--payloads", default="",     metavar="FILE",
                 help="File with custom payloads (one per line)")
  p.add_argument("--max-pages",      type=int, default=50)
  p.add_argument("--max-depth",      type=int, default=3)
  p.add_argument("--json",           action="store_true", dest="json_output",
                 help="Output raw JSON")
  p.add_argument("-q", "--quiet",    action="store_true",
                 help="Suppress live log output")
  return p


def main() -> None:
  parser = build_parser()
  args   = parser.parse_args()

  # No URL supplied on the command line → interactive mode
  if not args.url:
    args = interactive_prompts()
  elif not args.json_output:
    print(CYAN(BANNER))

  # Parse headers
  headers: dict = {}
  for h in args.header:
    if ":" in h:
      k, _, v = h.partition(":")
      headers[k.strip()] = v.strip()

  # Parse custom payload file
  custom_payloads: list = []
  if args.payloads:
    try:
      with open(args.payloads) as fh:
        custom_payloads = [line.strip() for line in fh if line.strip()]
      if not args.json_output and not args.quiet:
        print(DIM(f"[*] Loaded {len(custom_payloads)} custom payloads from {args.payloads}"))
    except OSError as e:
      print(f"[!] Cannot read payload file: {e}", file=sys.stderr)
      sys.exit(1)

  def live_log(msg: str) -> None:
    if not args.quiet and not args.json_output:
      if msg.startswith("[+]"):
        print(GREEN(msg))
      elif msg.startswith("[!]"):
        print(YELLOW(msg))
      elif msg.startswith("[~]"):
        print(CYAN(msg))
      else:
        print(DIM(msg))

  opts = ScanOptions(
    crawl=args.crawl,
    blind_callback=args.blind,
    data=args.data,
    headers=headers,
    cookies=args.cookie,
    proxy=args.proxy,
    threads=args.threads,
    timeout=args.timeout,
    level=args.level,
    custom_payloads=custom_payloads,
    max_pages=args.max_pages,
    max_depth=args.max_depth,
    on_log=live_log,
  )

  if not args.json_output and not args.quiet:
    print(BOLD(f"[*] Target : {args.url}"))
    print(BOLD(f"[*] Level  : {args.level}  Threads: {args.threads}  Crawl: {args.crawl}"))
    print()

  result = scan(args.url, opts)

  # ---- Output ----
  if args.json_output:
    print(json.dumps(result.to_dict(), indent=2))
    sys.exit(0 if result.total_findings == 0 else 1)

  # Human-readable summary
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

    for i, f in enumerate(result.reflected, 1):
      status = GREEN("[CONFIRMED]") if f.confirmed else YELLOW("[REFLECTED]")
      print(f"  {i}. {status} Reflected XSS")
      print(f"     Param   : {f.parameter}")
      print(f"     URL     : {f.url}")
      print(f"     Method  : {f.method}")
      print(f"     Context : {f.context}")
      print(f"     Payload : {f.payload}")
      if f.evidence:
        print(f"     Evidence: {DIM(f.evidence[:100])}")
      try:
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        _p = urlparse(f.url)
        _qs = parse_qs(_p.query, keep_blank_values=True)
        _qs[f.parameter] = [f.payload]
        _proof_url = urlunparse(_p._replace(query=urlencode(_qs, doseq=True)))
        print(f"     Proof   : {CYAN(_proof_url)}")
      except Exception:
        pass
      print()

    for i, d in enumerate(result.dom, 1):
      print(f"  {i}. {YELLOW('[DOM XSS]')} {d.source} → {d.sink}")
      print(f"     URL  : {d.url}")
      print(f"     Line : {d.line}")
      if d.snippet:
        print(f"     Code : {DIM(d.snippet[:120])}")
      print()

    for i, b in enumerate(result.blind, 1):
      print(f"  {i}. {CYAN('[BLIND XSS]')} Payload injected")
      print(f"     Param    : {b.parameter}")
      print(f"     URL      : {b.url}")
      print(f"     Callback : {b.callback}")
      print()

  if result.errors:
    print(RED("  Errors:"))
    for e in result.errors:
      print(f"    - {e}")

  print(BOLD("=" * 60))

  sys.exit(0 if result.total_findings == 0 else 1)


if __name__ == "__main__":
  main()
