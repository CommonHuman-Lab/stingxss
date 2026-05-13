# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
import sys


def _use_colour() -> bool:
  """Evaluate at output time so stdout redirections are respected."""
  return sys.stdout.isatty()


def _c(code: str, text: str) -> str:
  if not _use_colour():
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
