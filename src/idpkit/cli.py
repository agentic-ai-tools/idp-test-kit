"""``idpkit``: inspect real IdP tokens, mock issuers, probe protected endpoints."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Annotated

import httpx
import typer

from idpkit.capture import write_fixture
from idpkit.discovery import check_discovery
from idpkit.env import load_env, profile_values
from idpkit.inspect import claim_rows, inspect_token
from idpkit.mock import MockIssuer
from idpkit.probe import mock_cases, real_cases, run_probe
from idpkit.profiles import all_profiles, load_profile, render
from idpkit.tokens import TokenCache, TokenResult, request_device_token, request_token
from idpkit.validators import Requirements, evaluate

app = typer.Typer(help=__doc__, no_args_is_help=True, add_completion=False)

EnvFile = Annotated[Path, typer.Option("--env-file", help="Tenant settings (IDPKIT_*).")]
AllowHttp = Annotated[bool, typer.Option("--allow-http", help="Accept http:// (local mocks only).")]
Audience = Annotated[list[str], typer.Option("--aud", help="Allowed audience (repeatable).")]
Client = Annotated[list[str], typer.Option("--client", help="Allowed client (repeatable).")]
Scope = Annotated[list[str], typer.Option("--scope", help="Required scope (repeatable).")]
Device = Annotated[
    bool,
    typer.Option("--device", help="Device flow: approve in a browser (user token, no M2M)."),
]
MOCK_KEY = Path(".idpkit/mock-key.pem")


def _prompt(uri: str, code: str) -> None:
    typer.echo(f"Open {uri}")
    typer.echo(f"and confirm the code {code}. Waiting for approval...")


def _get_token(
    profile_name: str, env_file: Path, *, device: bool = False, allow_http: bool = False
) -> tuple[TokenResult, str]:
    """(token, discovery URL) for a profile, from the cache or the provider."""
    profile = load_profile(profile_name)
    values = profile_values(profile.name, load_env(env_file))
    discovery = render(profile.discovery_url, values, profile=profile.name)
    if not device:
        return request_token(profile, values, cache=TokenCache()), discovery
    report = check_discovery(discovery, allow_http=allow_http)
    result = request_device_token(
        profile, values, discovery=report.document, on_prompt=_prompt, cache=TokenCache()
    )
    return result, discovery


def _token_for(
    profile_name: str, env_file: Path, *, device: bool = False, allow_http: bool = False
) -> tuple[str, str]:
    result, discovery = _get_token(profile_name, env_file, device=device, allow_http=allow_http)
    return result.access_token, discovery


@app.command()
def profiles() -> None:
    """List provider profiles and whether a real token confirmed them."""
    for p in all_profiles():
        status = f"verified {p.verified_on}" if p.verified else "unverified"
        typer.echo(f"{p.name:10} {status:22} {p.display}")


@app.command()
def discover(url: str, allow_http: AllowHttp = False) -> None:
    """Check a discovery document (https, issuer match, JWKS)."""
    report = check_discovery(url, allow_http=allow_http)
    typer.echo(f"issuer:   {report.issuer}")
    typer.echo(f"jwks_uri: {report.document.get('jwks_uri')} ({report.keys} keys)")
    typer.echo(f"token:    {report.document.get('token_endpoint')}")
    for problem in report.problems:
        typer.echo(f"PROBLEM:  {problem}")
    raise typer.Exit(1 if report.problems else 0)


@app.command()
def token(
    profile: str,
    env_file: EnvFile = Path(".env"),
    show_token: Annotated[bool, typer.Option("--show-token")] = False,
    device: Device = False,
    allow_http: AllowHttp = False,
) -> None:
    """Get a token (client credentials, or --device), cached until near expiry."""
    result, _ = _get_token(profile, env_file, device=device, allow_http=allow_http)
    left = int(result.expires_at - time.time())
    kind = "device" if device else "client-credentials"
    state = "cached" if result.from_cache else "new"
    typer.echo(f"{profile}: {state} {kind} token, {left}s left")
    if show_token:
        typer.echo(result.access_token)


@app.command()
def inspect(
    token: Annotated[str | None, typer.Argument(help="A JWT; or use --profile.")] = None,
    profile: Annotated[str | None, typer.Option(help="Get a token from this profile.")] = None,
    discovery: Annotated[str | None, typer.Option(help="Verify against this issuer.")] = None,
    env_file: EnvFile = Path(".env"),
    allow_http: AllowHttp = False,
    aud: Audience = [],  # noqa: B006 - typer reads the default
    client: Client = [],  # noqa: B006
    scope: Scope = [],  # noqa: B006
    device: Device = False,
) -> None:
    """Show a token's claims and which validators would accept it."""
    if token is None and profile is None:
        raise typer.BadParameter("pass a token or --profile")
    if token is None:
        token, discovery = _token_for(profile or "", env_file, device=device, allow_http=allow_http)
    result = inspect_token(token, discovery_url=discovery, allow_http=allow_http)
    width = max((len(k) for k, _ in claim_rows(result.claims)), default=0)
    for name, value in claim_rows(result.claims):
        typer.echo(f"  {name:<{width}}  {json.dumps(value)}")
    if result.signature_ok is not None:
        typer.echo(f"signature: {'ok' if result.signature_ok else 'INVALID'}")
    for problem in result.problems:
        typer.echo(f"PROBLEM: {problem}")
    req = Requirements(tuple(aud), tuple(client), tuple(scope))
    if aud or client or scope:
        for verdict in evaluate(result.claims, req):
            mark = "accept" if verdict.accepted else f"REJECT ({verdict.status})"
            typer.echo(f"{verdict.validator}: {mark} - {verdict.reason}")


@app.command()
def capture(
    profile: str,
    name: Annotated[str, typer.Option(help="Fixture file name.")] = "client-credentials",
    out: Annotated[Path, typer.Option(help="Fixture folder.")] = Path("fixtures/claims"),
    env_file: EnvFile = Path(".env"),
    allow_http: AllowHttp = False,
    device: Device = False,
) -> None:
    """Save a sanitized claim set from a real token as a committed fixture."""
    token, discovery = _token_for(profile, env_file, device=device, allow_http=allow_http)
    result = inspect_token(token, discovery_url=discovery, allow_http=allow_http)
    if not result.signature_ok or result.problems:
        typer.echo(f"refusing to capture an unverified token: {result.problems}")
        raise typer.Exit(1)
    typer.echo(f"wrote {write_fixture(out, profile, name, result.claims)}")


@app.command()
def mock(
    shape: Annotated[str, typer.Option(help="Profile whose token shape to mint.")] = "auth0",
    port: int = 8099,
    public_url: Annotated[str | None, typer.Option(help="https URL in front (a tunnel).")] = None,
    audience: str = "api://idpkit",
) -> None:
    """Run a mock issuer in the foreground (Ctrl+C to stop)."""
    issuer = MockIssuer(public_url=public_url, port=port, key_path=MOCK_KEY)
    issuer.token_shape = load_profile(shape).shape
    issuer.token_audience = audience
    issuer.start()
    typer.echo(f"discovery: {issuer.discovery_url}")
    typer.echo(f"token:     POST {issuer.issuer}/token (grant_type=client_credentials)")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        issuer.stop()


@app.command()
def probe(
    url: str,
    profile: Annotated[str | None, typer.Option(help="Use a real token from this profile.")] = None,
    mock_shape: Annotated[
        str | None, typer.Option("--mock", help="Forge every case with `idpkit mock`'s key.")
    ] = None,
    issuer_url: Annotated[
        str, typer.Option(help="The running mock's issuer URL (with --mock).")
    ] = "http://127.0.0.1:8099",
    env_file: EnvFile = Path(".env"),
    aud: Audience = [],  # noqa: B006
    client: Client = [],  # noqa: B006
    scope: Scope = [],  # noqa: B006
) -> None:
    """Call an MCP endpoint with a token matrix and check each status."""
    if (profile is None) == (mock_shape is None):
        raise typer.BadParameter("pass exactly one of --profile or --mock")
    if mock_shape is not None:
        issuer = MockIssuer(public_url=issuer_url, key_path=MOCK_KEY)
        req = Requirements(tuple(aud), tuple(client), tuple(scope))
        cases = mock_cases(issuer, load_profile(mock_shape).shape, req)
    else:
        cases = real_cases(_token_for(profile or "", env_file)[0])
    failed = 0
    for outcome in run_probe(url, cases):
        failed += not outcome.ok
        got = outcome.status if outcome.status is not None else outcome.error
        mark = "ok  " if outcome.ok else "FAIL"
        typer.echo(f"{mark} {outcome.case.name:15} expected {outcome.case.expect}, got {got}")
    raise typer.Exit(1 if failed else 0)


def main() -> None:
    """Console entry point: expected failures print one line, not a traceback."""
    try:
        app()
    except (httpx.HTTPError, RuntimeError, ValueError, KeyError) as exc:
        message = exc.args[0] if isinstance(exc, KeyError) and exc.args else exc
        typer.echo(f"error: {message}", err=True)
        if isinstance(exc, httpx.ConnectError):
            typer.echo("check the domain/region values in .env", err=True)
        raise SystemExit(1) from None
