"""Decode a token, verify it against the provider's JWKS, and list its claims."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt

from idpkit.discovery import check_discovery

# Asymmetric only, like the resource servers this kit tests.
ALGORITHMS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"]
LEEWAY_SECONDS = 60

#: Claims that decide who accepts a token, shown first.
IDENTITY_CLAIMS = (
    "iss",
    "aud",
    "client_id",
    "azp",
    "cid",
    "appid",
    "sub",
    "scope",
    "scp",
    "roles",
    "gty",
    "token_use",
    "idtyp",
    "ver",
    "typ",
    "iat",
    "nbf",
    "exp",
)


@dataclass
class Inspection:
    header: dict[str, Any]
    claims: dict[str, Any]
    #: True/False after a JWKS check; None when no discovery URL was given.
    signature_ok: bool | None = None
    problems: list[str] = field(default_factory=list)


def inspect_token(
    token: str,
    *,
    discovery_url: str | None = None,
    client: httpx.Client | None = None,
    allow_http: bool = False,
) -> Inspection:
    try:
        header = jwt.get_unverified_header(token)
        claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.InvalidTokenError as exc:
        return Inspection({}, {}, False, [f"not a JWT: {exc}"])
    result = Inspection(header=header, claims=claims)
    if discovery_url is None:
        return result

    report = check_discovery(discovery_url, client=client, allow_http=allow_http)
    result.problems.extend(p for p in report.problems if "issuer" not in p)
    if not report.keys:
        result.signature_ok = False
        return result
    try:
        key = jwt.PyJWKSet.from_dict(report.jwks)[header.get("kid", "")]
    except (KeyError, jwt.PyJWKSetError):
        result.signature_ok = False
        result.problems.append("the token's kid is not in the provider's JWKS")
        return result
    try:
        jwt.decode(
            token,
            key.key,
            algorithms=ALGORITHMS,
            # Signature only: time claims are checked below, with leeway for clock skew.
            options={
                "verify_aud": False,
                "verify_exp": False,
                "verify_iss": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
        result.signature_ok = True
    except jwt.InvalidTokenError:
        result.signature_ok = False
        result.problems.append("the signature does not verify against the provider's JWKS")
        return result
    try:
        jwt.decode(
            token,
            key.key,
            algorithms=ALGORITHMS,
            issuer=report.issuer,
            leeway=LEEWAY_SECONDS,
            options={"verify_aud": False, "require": ["exp", "iss"]},
        )
    except jwt.ExpiredSignatureError:
        result.problems.append("the token has expired")
    except jwt.InvalidIssuerError:
        result.problems.append(
            f"the token's issuer {claims.get('iss')!r} is not the provider's {report.issuer!r}"
        )
    except jwt.InvalidTokenError as exc:
        result.problems.append(f"the token is not valid: {exc}")
    return result


def claim_rows(claims: dict[str, Any]) -> list[tuple[str, Any]]:
    """Identity claims first (in a fixed order), then the rest alphabetically."""
    first = [(name, claims[name]) for name in IDENTITY_CLAIMS if name in claims]
    rest = sorted((k, v) for k, v in claims.items() if k not in IDENTITY_CLAIMS)
    return first + rest
