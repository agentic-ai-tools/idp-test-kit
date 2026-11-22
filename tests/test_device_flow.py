"""OIDC Device Authorization (RFC 8628): a person approves in a browser, the CLI polls.

Used when a provider cannot issue machine tokens (Okta Integrator Free) or to inspect
user-delegated tokens.
"""

from __future__ import annotations

from urllib.parse import parse_qs

import httpx
import pytest

from idpkit.profiles import load_profile
from idpkit.tokens import TokenCache, request_device_token

DISCOVERY = {
    "issuer": "https://acme.okta.com/oauth2/default",
    "device_authorization_endpoint": "https://acme.okta.com/oauth2/default/v1/device/authorize",
    "token_endpoint": "https://acme.okta.com/oauth2/default/v1/token",
}
VALUES = {
    "domain": "acme.okta.com",
    "auth_server": "default",
    "client_id": "0oaNative",
    "scope": "mcp.read",
    "device_scope": "openid mcp.read",
}


def provider(token_replies: list[dict], calls: list[httpx.Request]):
    replies = iter(token_replies)

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.url.path.endswith("/device/authorize"):
            return httpx.Response(
                200,
                json={
                    "device_code": "dev-123",
                    "user_code": "WXYZ-1234",
                    "verification_uri": "https://acme.okta.com/activate",
                    "verification_uri_complete": "https://acme.okta.com/activate?user_code=WXYZ-1234",
                    "interval": 5,
                    "expires_in": 600,
                },
            )
        reply = next(replies)
        status = 200 if "access_token" in reply else 400
        return httpx.Response(status, json=reply)

    return httpx.MockTransport(handler)


def run(replies, *, values=VALUES, cache=None):
    calls: list[httpx.Request] = []
    prompts: list[tuple[str, str]] = []
    sleeps: list[float] = []
    with httpx.Client(transport=provider(replies, calls)) as client:
        result = request_device_token(
            load_profile("okta"),
            values,
            discovery=DISCOVERY,
            client=client,
            cache=cache,
            on_prompt=lambda uri, code: prompts.append((uri, code)),
            sleep=sleeps.append,
        )
    return result, calls, prompts, sleeps


def test_shows_the_code_then_polls_until_approved():
    result, calls, prompts, sleeps = run(
        [{"error": "authorization_pending"}, {"access_token": "user-tok", "expires_in": 3600}]
    )
    assert result.access_token == "user-tok"
    assert prompts == [("https://acme.okta.com/activate?user_code=WXYZ-1234", "WXYZ-1234")]
    assert sleeps == [5, 5]
    device = parse_qs(calls[0].content.decode())
    assert device == {"client_id": ["0oaNative"], "scope": ["openid mcp.read"]}
    poll = parse_qs(calls[1].content.decode())
    assert poll["grant_type"] == ["urn:ietf:params:oauth:grant-type:device_code"]
    assert poll["device_code"] == ["dev-123"]
    assert "client_secret" not in poll  # public (native) client


def test_slow_down_waits_longer():
    _, _, _, sleeps = run([{"error": "slow_down"}, {"access_token": "t", "expires_in": 60}])
    assert sleeps == [5, 10]


def test_denied_or_expired_stops_with_a_clear_error():
    for error in ("access_denied", "expired_token"):
        with pytest.raises(RuntimeError, match=error):
            run([{"error": error}])


def test_confidential_clients_send_their_secret():
    _, calls, _, _ = run(
        [{"access_token": "t", "expires_in": 60}],
        values={**VALUES, "client_secret": "s3cret"},
    )
    assert parse_qs(calls[1].content.decode())["client_secret"] == ["s3cret"]


def test_falls_back_to_the_scope_and_needs_a_device_endpoint():
    values = {k: v for k, v in VALUES.items() if k != "device_scope"}
    _, calls, _, _ = run([{"access_token": "t", "expires_in": 60}], values=values)
    assert parse_qs(calls[0].content.decode())["scope"] == ["mcp.read"]
    with pytest.raises(RuntimeError, match="device_authorization_endpoint"):
        request_device_token(
            load_profile("okta"),
            VALUES,
            discovery={"issuer": "x", "token_endpoint": "y"},
            on_prompt=lambda *a: None,
        )


def test_device_tokens_are_cached_apart_from_machine_tokens(tmp_path):
    cache = TokenCache(tmp_path)
    run([{"access_token": "user-tok", "expires_in": 3600}], cache=cache)
    again, calls, prompts, _ = run([], cache=cache)
    assert (again.access_token, again.from_cache, prompts, calls) == ("user-tok", True, [], [])
    assert all("device" in p.name for p in tmp_path.iterdir())
