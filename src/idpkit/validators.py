"""Models of how real resource servers judge a token's claims.

Signature, issuer and expiry are checked by ``inspect``; these models answer the next
question: with these allowed audiences / clients / scopes, would this server accept it?
Each model cites the code or docs it follows. Statuses: 401 = rejected token,
403 = valid token without the right client or scope (where the server distinguishes).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Requirements:
    audiences: tuple[str, ...] = ()
    clients: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ()

    def check(self) -> None:
        if not (self.audiences or self.clients or self.scopes):
            raise ValueError("set at least one allowed audience, client or scope")


@dataclass(frozen=True)
class Verdict:
    validator: str
    accepted: bool
    status: int
    reason: str


def _audiences(claims: dict[str, Any]) -> set[str]:
    aud = claims.get("aud")
    if isinstance(aud, str):
        return {aud}
    if isinstance(aud, list):
        return {str(a) for a in aud}
    return set()


def _scopes(claims: dict[str, Any], names: tuple[str, ...]) -> set[str]:
    granted: set[str] = set()
    for name in names:
        value = claims.get(name)
        if isinstance(value, str):
            granted.update(value.split())
        elif isinstance(value, list):
            granted.update(str(v) for v in value)
    return granted


def _mcp_wizard(claims: dict[str, Any], req: Requirements) -> Verdict:
    """mcp-wizard-generators 0.6 generated server (plugins/python_mcp/auth_template.py)."""
    name = "mcp-wizard-0.6"
    if req.audiences and not _audiences(claims) & set(req.audiences):
        return Verdict(name, False, 401, "aud does not match an allowed audience")
    if req.clients:
        client = str(claims.get("client_id") or claims.get("azp") or "")
        if client not in req.clients:
            return Verdict(name, False, 403, "neither client_id nor azp is an allowed client")
    if req.scopes and not _scopes(claims, ("scope", "scp")) & set(req.scopes):
        return Verdict(name, False, 403, "no allowed scope in scope/scp")
    return Verdict(name, True, 200, "accepted")


def _agentcore(claims: dict[str, Any], req: Requirements) -> Verdict:
    """Bedrock AgentCore customJWTAuthorizer (allowedAudience -> aud, allowedClients ->
    client_id; both checked when both are set). Docs: CustomJWTAuthorizerConfiguration."""
    name = "agentcore"
    if req.audiences and not _audiences(claims) & set(req.audiences):
        return Verdict(name, False, 401, "aud does not match allowedAudience")
    if req.clients and str(claims.get("client_id") or "") not in req.clients:
        return Verdict(name, False, 401, "client_id does not match allowedClients")
    if req.scopes and not (req.audiences or req.clients):
        return Verdict(
            name, False, 401, "the authorizer has no scope check; set audience or clients"
        )
    return Verdict(name, True, 200, "accepted (scopes are not checked by this model)")


def _rfc9068(claims: dict[str, Any], req: Requirements) -> Verdict:
    """RFC 9068 JWT access token profile: aud, client_id, space-separated scope."""
    name = "rfc9068"
    if req.audiences and not _audiences(claims) & set(req.audiences):
        return Verdict(name, False, 401, "aud does not match")
    if req.clients and str(claims.get("client_id") or "") not in req.clients:
        return Verdict(name, False, 403, "client_id does not match")
    if req.scopes and not _scopes(claims, ("scope",)) & set(req.scopes):
        return Verdict(name, False, 403, "no allowed scope in scope")
    return Verdict(name, True, 200, "accepted")


VALIDATORS: dict[str, Callable[[dict[str, Any], Requirements], Verdict]] = {
    "mcp-wizard-0.6": _mcp_wizard,
    "agentcore": _agentcore,
    "rfc9068": _rfc9068,
}


def validate(name: str, claims: dict[str, Any], req: Requirements) -> Verdict:
    req.check()
    if name not in VALIDATORS:
        raise KeyError(f"no validator {name!r}; known: {', '.join(VALIDATORS)}")
    return VALIDATORS[name](claims, req)


def evaluate(claims: dict[str, Any], req: Requirements) -> list[Verdict]:
    req.check()
    return [model(claims, req) for model in VALIDATORS.values()]
