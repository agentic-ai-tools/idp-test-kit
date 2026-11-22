"""Turn a real token's claims into a fixture that is safe to commit.

Identifiers (tenant, object, client, issuer, audience) become ``<name>`` placeholders,
one-time values are dropped, and times become relative (``iat`` 0, ``exp`` = lifetime),
so the fixture keeps the *shape* the provider issues and nothing that identifies a tenant.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MASK = {
    "sub",
    "oid",
    "tid",
    "client_id",
    "azp",
    "cid",
    "appid",
    "uid",
    "sid",
    "username",
    "preferred_username",
}
# One-time values and client network addresses (Keycloak clientAddress/clientHost).
DROP = {
    "jti",
    "uti",
    "rh",
    "aio",
    "xms_tcdt",
    "xms_ftd",
    "auth_time",
    "event_id",
    "origin_jti",
    "clientAddress",
    "clientHost",
}
PLACEHOLDER = {"iss": "<issuer>", "aud": "<audience>"}
TIMES = ("iat", "nbf", "exp")


def sanitize(claims: dict[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    base = claims.get("iat")
    for key, value in claims.items():
        if key in DROP:
            continue
        if key in PLACEHOLDER:
            clean[key] = (
                [PLACEHOLDER[key]] * len(value) if isinstance(value, list) else PLACEHOLDER[key]
            )
        elif key in MASK:
            clean[key] = f"<{key}>"
        elif key in TIMES and isinstance(value, int) and isinstance(base, int):
            clean[key] = value - base
        else:
            clean[key] = value
    return clean


def write_fixture(folder: str | Path, profile: str, name: str, claims: dict[str, Any]) -> Path:
    path = Path(folder) / profile / f"{name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sanitize(claims), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
