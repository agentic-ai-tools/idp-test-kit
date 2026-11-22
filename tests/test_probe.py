"""Probe a protected endpoint with a matrix of tokens.

The test server mimics the MCP Wizard generated server (401 for bad tokens, 403 for
the wrong client or scope), using idpkit's own verification and validator model.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from idpkit.inspect import inspect_token
from idpkit.probe import mock_cases, real_cases, run_probe
from idpkit.profiles import load_profile
from idpkit.validators import Requirements, validate


@pytest.fixture()
def protected(idp):
    req = Requirements(audiences=("api://mcp",), scopes=("mcp.read",))
    seen: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            return

        def do_POST(self):
            seen.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            auth = self.headers.get("Authorization", "")
            status = 401
            if auth.startswith("Bearer "):
                result = inspect_token(auth[7:], discovery_url=idp.discovery_url, allow_http=True)
                if result.signature_ok and not result.problems:
                    status = validate("mcp-wizard-0.6", result.claims, req).status
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/mcp", req, seen
    server.shutdown()


def test_mock_matrix_gets_the_expected_statuses(idp, protected):
    url, req, seen = protected
    cases = mock_cases(idp, load_profile("auth0").shape, req)
    names = {c.name for c in cases}
    assert {
        "valid",
        "no token",
        "wrong audience",
        "expired",
        "wrong issuer",
        "bad signature",
        "missing scope",
    } <= names
    outcomes = run_probe(url, cases)
    assert all(o.ok for o in outcomes), [(o.case.name, o.status) for o in outcomes]
    assert seen[0]["method"] == "initialize"


def test_wrong_client_case_only_when_clients_are_required(idp):
    shape = load_profile("cognito").shape
    with_clients = mock_cases(idp, shape, Requirements(clients=("c1",)))
    assert "wrong client" in {c.name for c in with_clients}
    assert next(c for c in with_clients if c.name == "wrong client").expect == 403
    assert "wrong client" not in {
        c.name for c in mock_cases(idp, shape, Requirements(audiences=("a",)))
    }


def test_a_mismatch_is_reported_not_raised(idp, protected):
    url, req, _ = protected
    lenient = [c for c in mock_cases(idp, load_profile("auth0").shape, req) if c.name == "valid"]
    lenient[0].expect = 401  # pretend we expected a rejection
    outcome = run_probe(url, lenient)[0]
    assert (outcome.status, outcome.ok) == (200, False)


def test_real_token_cases_cannot_forge_claims():
    cases = real_cases("aaa.bbb.ccc")
    assert [c.name for c in cases] == ["valid", "no token", "bad signature"]


def test_expectations_follow_the_validator_model(idp):
    """No `aud` in the shape: the audience check fails first, so even 'missing scope' is 401."""
    req = Requirements(audiences=("api://mcp",), scopes=("mcp.read",))
    cases = {c.name: c.expect for c in mock_cases(idp, load_profile("cognito").shape, req)}
    assert cases["valid"] == 401
    assert cases["missing scope"] == 401
    entra = {c.name: c.expect for c in mock_cases(idp, load_profile("entra").shape, req)}
    assert entra["valid"] == 403  # app roles are not scopes to the generated server
