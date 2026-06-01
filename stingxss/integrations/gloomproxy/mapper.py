# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Map native StingXSS findings → GloomProxy SDK Finding objects."""
from __future__ import annotations

import dataclasses
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from gloomproxy_sdk import Finding

from stingxss.engine.reporter import (
    BlindFinding,
    BrowserFinding,
    ClickjackingFinding,
    CORSFinding,
    CRLFFinding,
    DomFinding,
    GraphqlFinding,
    HstsFinding,
    OpenRedirectFinding,
    ReflectedFinding,
    ScanResult,
    StoredFinding,
    WebsocketFinding,
    XSTFinding,
    _FINDING_LISTS,
)

_SCANNER = "stingxss"


def _proof_url(url: str, param: str, payload: str) -> str:
    try:
        p = urlparse(url)
        qs = parse_qs(p.query, keep_blank_values=True)
        qs[param] = [payload]
        return urlunparse(p._replace(query=urlencode(qs, doseq=True)))
    except Exception:
        return ""

# Severity passthrough — StingXSS findings carry their own severity
_SEVERITY_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}


def _sev(f: object) -> str:
    raw = getattr(f, "severity", "medium")
    return _SEVERITY_MAP.get(str(raw).lower(), "medium")


def _map_reflected(f: ReflectedFinding) -> Finding:
    proof = _proof_url(f.url, f.parameter, f.payload)
    return Finding(
        scanner=_SCANNER,
        type="reflected_xss",
        severity=_sev(f),
        target=f.url,
        evidence=f.evidence or f"Payload reflected in {f.context.value} context",
        title=f"Reflected XSS — {f.parameter} ({f.context.value})",
        description=f"Reflected XSS confirmed in parameter '{f.parameter}' within a {f.context.value} context.",
        confidence=0.95 if f.confirmed else 0.75,
        request=f"Parameter: {f.parameter}\nMethod: {f.method}\nPayload: {f.payload}",
        references=[proof] if proof else [],
        extra={"parameter": f.parameter, "method": f.method, "context": f.context.value, "confirmed": f.confirmed},
        tags=["xss", "reflected", f"context:{f.context.value}"],
    )


def _map_stored(f: StoredFinding) -> Finding:
    return Finding(
        scanner=_SCANNER,
        type="stored_xss",
        severity=_sev(f),
        target=f.inject_url,
        evidence=f.evidence or f"Payload injected via '{f.parameter}', triggers on revisit of {f.revisit_url}",
        title=f"Stored XSS — {f.parameter}",
        description="Stored XSS confirmed — payload persists and executes on subsequent page visits.",
        confidence=0.95 if f.confirmed else 0.70,
        request=f"Inject: {f.inject_url}\nParameter: {f.parameter}\nMethod: {f.method}\nPayload: {f.payload}",
        extra={"parameter": f.parameter, "inject_url": f.inject_url, "revisit_url": f.revisit_url, "confirmed": f.confirmed},
        tags=["xss", "stored", "persistent"],
    )


def _map_dom(f: DomFinding) -> Finding:
    return Finding(
        scanner=_SCANNER,
        type="dom_xss",
        severity=_sev(f),
        target=f.url,
        evidence=f.snippet or f"Source: {f.source} → Sink: {f.sink} (line {f.line})",
        title=f"DOM XSS — {f.source} → {f.sink}",
        description=f"DOM-based XSS: tainted data flows from '{f.source}' into '{f.sink}'.",
        confidence=0.80,
        extra={"source": f.source, "sink": f.sink, "line": f.line, "category": f.category},
        tags=["xss", "dom", f"sink:{f.sink}"],
    )


def _map_blind(f: BlindFinding) -> Finding:
    return Finding(
        scanner=_SCANNER,
        type="blind_xss",
        severity=_sev(f),
        target=f.url,
        evidence=f"Blind XSS payload injected via '{f.parameter}'. Callback: {f.callback}",
        title=f"Blind XSS — {f.parameter}",
        description="Blind XSS payload injected. Verify execution via out-of-band callback.",
        confidence=0.60,
        request=f"Parameter: {f.parameter}\nMethod: {f.method}\nPayload: {f.payload}",
        extra={"parameter": f.parameter, "method": f.method, "callback": f.callback},
        tags=["xss", "blind", "oob"],
    )


def _map_cors(f: CORSFinding) -> Finding:
    return Finding(
        scanner=_SCANNER,
        type="cors_misconfiguration",
        severity=_sev(f),
        target=f.url,
        evidence=f"{f.reason} — ACAO: {f.acao_received} for origin {f.origin_sent}",
        title="CORS Misconfiguration",
        description=f"CORS policy allows arbitrary origin. Credentials: {f.credentials}.",
        confidence=0.95,
        extra={"issue": f.issue, "origin_sent": f.origin_sent, "acao_received": f.acao_received, "credentials": f.credentials},
        tags=["cors", "misconfiguration"],
    )


def _map_clickjacking(f: ClickjackingFinding) -> Finding:
    return Finding(
        scanner=_SCANNER,
        type="clickjacking",
        severity=_sev(f),
        target=f.url,
        evidence=f.reason,
        title="Clickjacking — Missing Frame Protection",
        description="Page can be embedded in an iframe. No X-Frame-Options or CSP frame-ancestors.",
        confidence=0.95,
        extra={"xfo_header": f.xfo_header, "csp_header": f.csp_header},
        tags=["clickjacking", "headers"],
    )


def _map_redirect(f: OpenRedirectFinding) -> Finding:
    return Finding(
        scanner=_SCANNER,
        type="open_redirect",
        severity=_sev(f),
        target=f.url,
        evidence=f.reason,
        title=f"Open Redirect — {f.parameter}",
        description=f"Open redirect in parameter '{f.parameter}'. Redirects to: {f.location}",
        confidence=0.90,
        request=f"Parameter: {f.parameter}\nMethod: {f.method}\nPayload: {f.payload}",
        extra={"parameter": f.parameter, "location": f.location, "issue": f.issue},
        tags=["redirect", "open-redirect"],
    )


def _map_crlf(f: CRLFFinding) -> Finding:
    return Finding(
        scanner=_SCANNER,
        type="crlf_injection",
        severity=_sev(f),
        target=f.url,
        evidence=f.reason,
        title=f"CRLF Injection — {f.parameter}",
        description=f"CRLF injection via {f.vector} '{f.parameter}'. Injected header: {f.injected_header}",
        confidence=0.90,
        request=f"Parameter: {f.parameter}\nMethod: {f.method}\nPayload: {f.payload}\nVector: {f.vector}",
        extra={"parameter": f.parameter, "vector": f.vector, "injected_header": f.injected_header},
        tags=["crlf", "header-injection"],
    )


def _map_hsts(f: HstsFinding) -> Finding:
    return Finding(
        scanner=_SCANNER,
        type="hsts_misconfiguration",
        severity=_sev(f),
        target=f.url,
        evidence=f.reason,
        title=f"HSTS Issue — {f.issue}",
        description=f"HSTS header issue: {f.reason}. Header value: {f.header_value!r}",
        confidence=0.95,
        extra={"issue": f.issue, "header_value": f.header_value},
        tags=["hsts", "headers", "misconfiguration"],
    )


def _map_graphql(f: GraphqlFinding) -> Finding:
    return Finding(
        scanner=_SCANNER,
        type="graphql_xss",
        severity=_sev(f),
        target=f.endpoint,
        evidence=f.evidence or f"Payload reflected in GraphQL field '{f.field}'",
        title=f"GraphQL XSS — {f.field}",
        description=f"XSS via GraphQL {f.operation} field '{f.field}' at {f.endpoint}.",
        confidence=0.90 if f.confirmed else 0.65,
        extra={"endpoint": f.endpoint, "field": f.field, "operation": f.operation},
        tags=["xss", "graphql"],
    )


def _map_websocket(f: WebsocketFinding) -> Finding:
    return Finding(
        scanner=_SCANNER,
        type="websocket_xss",
        severity=_sev(f),
        target=f.url,
        evidence=f"Payload reflected in WebSocket response from {f.ws_url}",
        title="WebSocket XSS",
        description=f"XSS payload reflected in WebSocket frame from {f.ws_url}.",
        confidence=0.90 if f.confirmed else 0.65,
        extra={"ws_url": f.ws_url, "response": f.response[:300]},
        tags=["xss", "websocket"],
    )


def _map_xst(f: XSTFinding) -> Finding:
    return Finding(
        scanner=_SCANNER,
        type="xst",
        severity=_sev(f),
        target=f.url,
        evidence=f.reason,
        title="Cross-Site Tracing (XST)",
        description="HTTP TRACE method enabled. Can be used to steal cookies in legacy browsers.",
        confidence=0.95,
        extra={"method": f.method},
        tags=["xst", "http-methods"],
    )


# Generic fallback for types without a dedicated mapper (jsonp, mixed_content, vuln_libs, etc.)
def _map_generic(ftype: str, f: object) -> Finding | None:
    url = getattr(f, "url", "") or getattr(f, "endpoint", "")
    sev = _sev(f)
    evidence = getattr(f, "reason", "") or getattr(f, "evidence", "") or str(f)[:200]
    if not url:
        return None
    return Finding(
        scanner=_SCANNER,
        type=ftype,
        severity=sev,
        target=url,
        evidence=evidence,
        confidence=0.80,
        tags=["stingxss"],
    )


_TYPED_MAPPERS = {
    "reflected": _map_reflected,
    "stored": _map_stored,
    "dom": _map_dom,
    "blind": _map_blind,
    "cors": _map_cors,
    "clickjacking": _map_clickjacking,
    "redirects": _map_redirect,
    "crlf": _map_crlf,
    "hsts": _map_hsts,
    "graphql": _map_graphql,
    "websocket": _map_websocket,
    "xst": _map_xst,
}


def map_results(result: ScanResult) -> list[Finding]:
    """Convert a StingXSS ScanResult into a list of SDK Finding objects."""
    findings: list[Finding] = []
    for attr, ftype in _FINDING_LISTS:
        mapper = _TYPED_MAPPERS.get(attr)
        for native in getattr(result, attr, []):
            try:
                if mapper:
                    findings.append(mapper(native).validate())
                else:
                    f = _map_generic(ftype.value, native)
                    if f:
                        findings.append(f.validate())
            except Exception:
                pass
    return findings
