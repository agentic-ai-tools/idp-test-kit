"""Fetch and check an OIDC discovery document the way strict resource servers do."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

WELL_KNOWN = "/.well-known/openid-configuration"
TIMEOUT = httpx.Timeout(10.0)


@dataclass
class DiscoveryReport:
    url: str
    document: dict[str, Any] = field(default_factory=dict)
    jwks: dict[str, Any] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)

    @property
    def issuer(self) -> str | None:
        return self.document.get("issuer")

    @property
    def keys(self) -> int:
        return len(self.jwks.get("keys") or [])


def _get_json(client: httpx.Client, url: str) -> dict[str, Any]:
    response = client.get(url, follow_redirects=False)
    response.raise_for_status()
    body = response.json()
    if not isinstance(body, dict):
        raise ValueError(f"{url} did not return a JSON object")
    return body


def check_discovery(
    url: str, *, client: httpx.Client | None = None, allow_http: bool = False
) -> DiscoveryReport:
    """Return the document, its JWKS, and every problem found (never raises for them)."""
    report = DiscoveryReport(url=url)
    if not url.startswith("https://") and not allow_http:
        report.problems.append("the discovery URL must use https")
    if not url.endswith(WELL_KNOWN):
        report.problems.append(f"the discovery URL must end with {WELL_KNOWN}")
    own = client is None
    client = client or httpx.Client(timeout=TIMEOUT)
    try:
        try:
            report.document = _get_json(client, url)
        except (httpx.HTTPError, ValueError) as exc:
            report.problems.append(f"could not read the discovery document: {exc}")
            return report
        issuer, jwks_uri = report.issuer, report.document.get("jwks_uri")
        expected = url[: -len(WELL_KNOWN)] if url.endswith(WELL_KNOWN) else None
        if not isinstance(issuer, str):
            report.problems.append("the document has no issuer")
        elif expected is not None and issuer.rstrip("/") != expected.rstrip("/"):
            report.problems.append(
                f"issuer {issuer!r} does not match the discovery URL ({expected!r}); "
                "tokens are checked against the issuer"
            )
        if not isinstance(jwks_uri, str):
            report.problems.append("the document has no jwks_uri")
            return report
        if not jwks_uri.startswith("https://") and not allow_http:
            report.problems.append("jwks_uri must use https")
        try:
            report.jwks = _get_json(client, jwks_uri)
        except (httpx.HTTPError, ValueError) as exc:
            report.problems.append(f"could not read the JWKS: {exc}")
            return report
        if report.keys == 0:
            report.problems.append("the JWKS has no keys")
    finally:
        if own:
            client.close()
    return report
