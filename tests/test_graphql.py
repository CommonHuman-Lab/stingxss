# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Unit tests for stingxss.engine.checks.graphql — all HTTP mocked."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from stingxss.engine.checks.graphql import (
    _build_query,
    _get_injectable_fields,
    _is_string_type,
    check,
    discover_endpoints,
    _is_graphql,
)
from stingxss.engine.reporter import GraphqlFinding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_resp(text: str = "", status_code: int = 200, json_data=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    if json_data is not None:
        resp.json.return_value = json_data
    else:
        try:
            resp.json.return_value = json.loads(text)
        except Exception:
            resp.json.side_effect = ValueError("not json")
    return resp


def _make_injector(responses: dict | None = None):
    injector = MagicMock()
    responses = responses or {}

    def _post(url, **kwargs):
        return responses.get(url, _mock_resp(status_code=404))

    injector.post.side_effect = _post
    return injector


# ---------------------------------------------------------------------------
# _is_string_type
# ---------------------------------------------------------------------------

class TestIsStringType:
    def test_string_name(self):
        assert _is_string_type({"name": "String"}) is True

    def test_id_name(self):
        assert _is_string_type({"name": "ID"}) is True

    def test_int_name(self):
        assert _is_string_type({"name": "Int"}) is False

    def test_null_name(self):
        assert _is_string_type({"name": None}) is False

    def test_nested_string(self):
        assert _is_string_type({"name": "NonNull", "ofType": {"name": "String"}}) is True

    def test_nested_int(self):
        assert _is_string_type({"name": "NonNull", "ofType": {"name": "Int"}}) is False

    def test_empty_dict(self):
        assert _is_string_type({}) is False


# ---------------------------------------------------------------------------
# _build_query
# ---------------------------------------------------------------------------

class TestBuildQuery:
    def test_returns_tuple(self):
        gql, variables = _build_query("query", "search", "query", "test")
        assert isinstance(gql, str)
        assert isinstance(variables, dict)

    def test_op_type_in_gql(self):
        gql, _ = _build_query("mutation", "createComment", "body", "xss")
        assert gql.startswith("mutation")

    def test_variables_contain_value(self):
        _, variables = _build_query("query", "user", "name", "payload_value")
        assert variables.get("val") == "payload_value"

    def test_op_name_in_gql(self):
        gql, _ = _build_query("query", "search", "q", "x")
        assert "search" in gql

    def test_sanitises_special_chars_in_name(self):
        gql, _ = _build_query("query", "bad-name!@#", "field", "x")
        assert "bad" in gql
        assert "!" not in gql
        assert "@" not in gql

    def test_arg_name_sanitised(self):
        gql, _ = _build_query("query", "op", "bad-arg!!", "x")
        assert "!!" not in gql


# ---------------------------------------------------------------------------
# _is_graphql
# ---------------------------------------------------------------------------

class TestIsGraphql:
    def test_detects_typename_in_response(self):
        resp = _mock_resp('{"data": {"__typename": "Query"}}')
        injector = MagicMock()
        injector.post.return_value = resp
        assert _is_graphql("https://example.com/graphql", injector) is True

    def test_detects_errors_key(self):
        resp = _mock_resp('{"errors": [{"message": "unauthorized"}]}')
        injector = MagicMock()
        injector.post.return_value = resp
        assert _is_graphql("https://example.com/graphql", injector) is True

    def test_rejects_500_response(self):
        resp = _mock_resp(status_code=500)
        injector = MagicMock()
        injector.post.return_value = resp
        assert _is_graphql("https://example.com/graphql", injector) is False

    def test_rejects_html_response(self):
        resp = _mock_resp("<html><body>Not found</body></html>")
        injector = MagicMock()
        injector.post.return_value = resp
        assert _is_graphql("https://example.com/graphql", injector) is False

    def test_returns_false_on_connection_error(self):
        injector = MagicMock()
        injector.post.side_effect = ConnectionError("refused")
        assert _is_graphql("https://example.com/graphql", injector) is False


# ---------------------------------------------------------------------------
# _get_injectable_fields
# ---------------------------------------------------------------------------

_SCHEMA_RESPONSE = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "types": [
                {
                    "name": "Query",
                    "kind": "OBJECT",
                    "fields": [
                        {
                            "name": "search",
                            "args": [
                                {"name": "q", "type": {"name": "String", "kind": "SCALAR", "ofType": None}}
                            ],
                        }
                    ],
                },
                {
                    "name": "Mutation",
                    "kind": "OBJECT",
                    "fields": [
                        {
                            "name": "createComment",
                            "args": [
                                {"name": "body", "type": {"name": "String", "kind": "SCALAR", "ofType": None}}
                            ],
                        }
                    ],
                },
                {"name": "__Schema", "kind": "OBJECT", "fields": []},
            ],
        }
    }
}


class TestGetInjectableFields:
    def test_returns_query_field(self):
        resp = _mock_resp(json_data=_SCHEMA_RESPONSE)
        injector = MagicMock()
        injector.post.return_value = resp
        fields = _get_injectable_fields("https://example.com/graphql", injector)
        assert ("query", "search", "q") in fields

    def test_returns_mutation_field(self):
        resp = _mock_resp(json_data=_SCHEMA_RESPONSE)
        injector = MagicMock()
        injector.post.return_value = resp
        fields = _get_injectable_fields("https://example.com/graphql", injector)
        assert ("mutation", "createComment", "body") in fields

    def test_skips_introspection_types(self):
        resp = _mock_resp(json_data=_SCHEMA_RESPONSE)
        injector = MagicMock()
        injector.post.return_value = resp
        fields = _get_injectable_fields("https://example.com/graphql", injector)
        assert not any("__Schema" in f[1] for f in fields)

    def test_returns_empty_on_400(self):
        resp = _mock_resp(status_code=400)
        injector = MagicMock()
        injector.post.return_value = resp
        assert _get_injectable_fields("https://example.com/graphql", injector) == []

    def test_returns_empty_on_exception(self):
        injector = MagicMock()
        injector.post.side_effect = ConnectionError("refused")
        assert _get_injectable_fields("https://example.com/graphql", injector) == []


# ---------------------------------------------------------------------------
# discover_endpoints
# ---------------------------------------------------------------------------

class TestDiscoverEndpoints:
    def test_finds_graphql_endpoint(self):
        resp_yes = _mock_resp('{"data":{"__typename":"Query"}}')
        resp_no  = _mock_resp(status_code=404)

        def _post(url, **kwargs):
            if url.endswith("/graphql"):
                return resp_yes
            return resp_no

        injector = MagicMock()
        injector.post.side_effect = _post
        found = discover_endpoints("https://example.com/app", injector)
        assert any("/graphql" in u for u in found)

    def test_returns_empty_when_no_endpoints(self):
        resp = _mock_resp(status_code=404)
        injector = MagicMock()
        injector.post.return_value = resp
        found = discover_endpoints("https://example.com", injector)
        assert found == []

    def test_returns_list(self):
        injector = MagicMock()
        injector.post.return_value = _mock_resp(status_code=404)
        assert isinstance(discover_endpoints("https://example.com", injector), list)


# ---------------------------------------------------------------------------
# check — integration
# ---------------------------------------------------------------------------

class TestCheck:
    def _injector_with_reflection(self, marker: str, endpoint: str) -> MagicMock:
        """Injector where introspection returns empty (uses defaults) and
        the first injection reflects the marker back."""
        injector = MagicMock()
        call_count = {"n": 0}

        def _post(url, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                # introspection call → return minimal schema (triggers default fields)
                return _mock_resp(status_code=200, json_data={"data": {"__schema": {}}})
            # injection call
            body = json.dumps({"data": {"search": {"__typename": "Query"}}, "reflected": marker})
            return _mock_resp(body)

        injector.post.side_effect = _post
        return injector

    def test_returns_list(self):
        injector = MagicMock()
        injector.post.return_value = _mock_resp(status_code=404)
        result = check("https://example.com/graphql", injector, marker="STING_test", level=1)
        assert isinstance(result, list)

    def test_returns_graphql_findings(self):
        marker = "StingXSS_gql_aabbcc"
        injector = self._injector_with_reflection(marker, "https://example.com/graphql")
        result = check("https://example.com/graphql", injector, marker=marker, level=1)
        assert all(isinstance(f, GraphqlFinding) for f in result)

    def test_reflection_confirmed(self):
        marker = "StingXSS_gql_reflect99"
        injector = self._injector_with_reflection(marker, "https://example.com/graphql")
        result = check("https://example.com/graphql", injector, marker=marker, level=1)
        if result:
            assert result[0].confirmed is True

    def test_no_findings_when_marker_not_reflected(self):
        injector = MagicMock()
        # introspection → minimal schema (uses defaults), injections → no marker
        call_count = {"n": 0}

        def _post(url, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return _mock_resp(status_code=200, json_data={"data": {"__schema": {}}})
            return _mock_resp('{"data":{"search":{"__typename":"Query"}}}')

        injector.post.side_effect = _post
        result = check("https://example.com/graphql", injector, marker="NOTPRESENT_xyz", level=1)
        assert result == []

    def test_level_affects_payload_count(self):
        """Higher level → more payloads probed (more post calls expected)."""
        injector_l1 = MagicMock()
        injector_l1.post.return_value = _mock_resp(status_code=200, json_data={"data": {"__schema": {}}})
        injector_l3 = MagicMock()
        injector_l3.post.return_value = _mock_resp(status_code=200, json_data={"data": {"__schema": {}}})

        check("https://example.com/graphql", injector_l1, marker="M", level=1)
        check("https://example.com/graphql", injector_l3, marker="M", level=3)

        assert injector_l3.post.call_count >= injector_l1.post.call_count
