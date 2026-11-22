"""Probe an MCP Wizard generated server's JWT checks against the mock issuer ($0, no Docker).

The generated server accepts an http:// discovery URL on loopback (for tests), so this
runs it as a plain process next to an in-process mock issuer and sends the full token
matrix for each provider shape.

    python scenarios/mcp-wizard-local/run.py PROJECT_DIR PYTHON [--port 8765]

PROJECT_DIR is a generated docker+jwt project (pip-installed into PYTHON's environment);
PYTHON runs it. Exit status 0 means every case got the status the shape predicts.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

from idpkit.mock import MockIssuer
from idpkit.probe import mock_cases, run_probe
from idpkit.profiles import load_profile
from idpkit.validators import Requirements

REQ = Requirements(audiences=("api://mcp",), scopes=("mcp.read",))
SHAPES = ("auth0", "cognito", "entra", "keycloak", "okta")


def wait_for(url: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            httpx.post(url, json={}, timeout=2.0)
            return
        except httpx.HTTPError:
            time.sleep(0.3)
    raise SystemExit(f"server did not start at {url}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("project", type=Path)
    parser.add_argument("python")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    failures = 0
    with MockIssuer() as issuer:
        env = {
            **os.environ,
            "MCP_TRANSPORT": "streamable-http",
            "MCP_HOST": "127.0.0.1",
            "MCP_PORT": str(args.port),
            "MCP_AUTH": "jwt",
            "MCP_JWT_DISCOVERY_URL": issuer.discovery_url,
            "MCP_JWT_AUDIENCES": ",".join(REQ.audiences),
            "MCP_JWT_CLIENTS": "",
            "MCP_JWT_SCOPES": ",".join(REQ.scopes),
            "API_BASE_URL": "https://api.example.com",
        }
        package = next((args.project / "src").iterdir()).name
        server = subprocess.Popen(
            [args.python, "-m", package],
            cwd=args.project,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        url = f"http://127.0.0.1:{args.port}/mcp"
        try:
            wait_for(url)
            for name in SHAPES:
                shape = load_profile(name).shape
                cases = mock_cases(issuer, shape, REQ)
                print()
                print(f"{name} (model predicts {cases[0].expect} for a well-formed token)")
                for outcome in run_probe(url, cases):
                    failures += not outcome.ok
                    mark = "ok  " if outcome.ok else "FAIL"
                    print(
                        f"  {mark} {outcome.case.name:15} expected {outcome.case.expect},"
                        f" got {outcome.status}"
                    )
        finally:
            server.terminate()
            server.wait(timeout=10)
    print(f"\n{'all cases matched' if not failures else f'{failures} mismatches'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
