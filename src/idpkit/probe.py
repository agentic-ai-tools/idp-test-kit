"""Send a matrix of tokens to a protected endpoint and compare the statuses.

With the mock issuer every case can be forged (wrong audience, expired, wrong issuer...).
With a real provider only a valid token, no token, and a tampered signature are possible.
Signature, expiry and issuer failures expect 401; claim-level cases expect what the
validator model (default: the MCP Wizard generated server) predicts.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

from idpkit.mock import MockIssuer
from idpkit.profiles import Shape
from idpkit.validators import Requirements, validate

MCP_INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "idpkit", "version": "0.1"},
    },
}


@dataclass
class Case:
    name: str
    token: str | None
    expect: int


@dataclass
class Outcome:
    case: Case
    status: int | None
    ok: bool
    error: str = ""


def tamper(token: str) -> str:
    """Change the signature's last characters so it no longer verifies."""
    head, _, sig = token.rpartition(".")
    swapped = "A" * 4 if not sig.endswith("AAAA") else "B" * 4
    return f"{head}.{sig[:-4]}{swapped}"


def mock_cases(
    issuer: MockIssuer, shape: Shape, req: Requirements, validator: str = "mcp-wizard-0.6"
) -> list[Case]:
    """Every case the mock can forge. Claim-level cases (valid, wrong audience/client,
    missing scope) expect what ``validator`` says about their claims, so a shape the
    server cannot accept (no ``aud``, scopes in another claim) is predicted, not assumed."""
    audience = req.audiences[0] if req.audiences else "api://idpkit"
    client = req.clients[0] if req.clients else "idpkit-client"
    scopes = req.scopes or ("mcp.read",)
    good = {"client_id": client, "audience": audience, "scopes": scopes}

    def judged(name: str, **changes: object) -> Case:
        claims = issuer.claims_for(shape, **{**good, **changes})
        return Case(name, issuer.sign(claims), validate(validator, claims, req).status)

    valid = judged("valid")
    cases = [
        valid,
        Case("no token", None, 401),
        Case("bad signature", tamper(valid.token or ""), 401),
        Case("expired", issuer.mint(shape, **good, exp=int(time.time()) - 3600), 401),
        Case("wrong issuer", issuer.mint(shape, **good, iss="https://wrong-issuer.example"), 401),
    ]
    if req.audiences and shape.audience:
        cases.append(judged("wrong audience", audience="api://other"))
    if req.clients:
        cases.append(judged("wrong client", client_id="someone-else"))
    if req.scopes:
        cases.append(judged("missing scope", scopes=("x",)))
    return cases


def real_cases(token: str) -> list[Case]:
    return [
        Case("valid", token, 200),
        Case("no token", None, 401),
        Case("bad signature", tamper(token), 401),
    ]


def run_probe(url: str, cases: list[Case], *, client: httpx.Client | None = None) -> list[Outcome]:
    own = client is None
    client = client or httpx.Client(timeout=20.0)
    outcomes: list[Outcome] = []
    try:
        for case in cases:
            headers = {"Accept": "application/json, text/event-stream"}
            if case.token is not None:
                headers["Authorization"] = f"Bearer {case.token}"
            try:
                response = client.post(url, json=MCP_INITIALIZE, headers=headers)
            except httpx.HTTPError as exc:
                outcomes.append(Outcome(case, None, False, str(exc)))
                continue
            outcomes.append(
                Outcome(case, response.status_code, response.status_code == case.expect)
            )
    finally:
        if own:
            client.close()
    return outcomes
