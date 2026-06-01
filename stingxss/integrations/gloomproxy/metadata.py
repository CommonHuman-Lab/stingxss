# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
from gloomproxy_sdk import PluginCapabilities

CAPABILITIES: PluginCapabilities = {
    "name": "stingxss",
    "modes": ["active"],
    "protocols": ["http", "https", "websocket"],
    "auth_required": False,
    "distributed_safe": True,
    "vuln_types": [
        "reflected_xss",
        "stored_xss",
        "dom_xss",
        "blind_xss",
        "cors",
        "clickjacking",
        "open_redirect",
        "crlf",
        "graphql_xss",
        "websocket_xss",
    ],
    "proxy_aware": True,
    "min_timeout": 30,
}
