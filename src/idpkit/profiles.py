"""Provider profiles: where to get a client-credentials token, and what it looks like.

Each `profiles/<name>.toml` holds the URL templates, the token request style, the
expected claim shape (from docs until a real token confirms it: `verified`), and the
sources behind it. Template fields come from `IDPKIT_<PROFILE>_<FIELD>` (see env.py).
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from importlib import resources
from string import Formatter
from typing import Any, Literal


@dataclass(frozen=True)
class Shape:
    """Claims of a client-credentials access token from this provider."""

    #: Claim naming the client (``client_id``, ``azp``, ``cid``...), or None.
    client_claim: str | None
    #: Whether the token carries ``aud`` at all.
    audience: bool
    #: Further claims that repeat the client (Keycloak sets client_id and azp).
    also_client_claims: tuple[str, ...] = ()
    scope_claim: str = "scope"
    scope_format: Literal["string", "list"] = "string"
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Profile:
    name: str
    display: str
    discovery_url: str
    token_url: str
    #: basic = form + HTTP Basic; post = form with client_secret; json = JSON body.
    auth: Literal["basic", "post", "json"]
    fields: tuple[str, ...]
    params: dict[str, str]
    shape: Shape
    sources: tuple[str, ...]
    verified: bool = False
    verified_on: str | None = None
    notes: str = ""


def render(template: str, values: dict[str, str], *, profile: str = "profile") -> str:
    """Fill ``{field}`` placeholders; a missing value names its env var."""
    missing = [name for _, name, _, _ in Formatter().parse(template) if name and name not in values]
    if missing:
        names = ", ".join(f"IDPKIT_{profile.upper()}_{m.upper()}" for m in missing)
        raise KeyError(f"set {names}")
    return template.format_map(values)


def _from_toml(data: dict[str, Any]) -> Profile:
    shape = data["shape"]
    return Profile(
        name=data["name"],
        display=data["display"],
        discovery_url=data["discovery_url"],
        token_url=data["token_url"],
        auth=data["auth"],
        fields=tuple(data["fields"]),
        params=dict(data.get("params", {})),
        shape=Shape(
            client_claim=shape.get("client_claim"),
            audience=bool(shape["audience"]),
            also_client_claims=tuple(shape.get("also_client_claims", ())),
            scope_claim=shape.get("scope_claim", "scope"),
            scope_format=shape.get("scope_format", "string"),
            extra=dict(shape.get("extra", {})),
        ),
        sources=tuple(data["sources"]),
        verified=bool(data.get("verified", False)),
        verified_on=data.get("verified_on"),
        notes=data.get("notes", ""),
    )


def all_profiles() -> list[Profile]:
    folder = resources.files("idpkit") / "profiles"
    return [
        _from_toml(tomllib.loads(item.read_text(encoding="utf-8")))
        for item in sorted(folder.iterdir(), key=lambda i: i.name)
        if item.name.endswith(".toml")
    ]


def load_profile(name: str) -> Profile:
    for profile in all_profiles():
        if profile.name == name:
            return profile
    raise KeyError(f"no profile {name!r}; known: {', '.join(p.name for p in all_profiles())}")
