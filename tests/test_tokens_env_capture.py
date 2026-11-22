from __future__ import annotations

import base64
import json
import time
from urllib.parse import parse_qs

import httpx
import pytest

from idpkit.capture import sanitize
from idpkit.env import load_env, profile_values
from idpkit.profiles import load_profile
from idpkit.tokens import TokenCache, request_token


def _transport(calls: list[httpx.Request], expires_in: int = 3600):
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"access_token": "tok-1", "expires_in": expires_in})

    return httpx.MockTransport(handler)


def test_env_file_and_environment(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# comment\nIDPKIT_OKTA_DOMAIN=acme.okta.com\nIDPKIT_OKTA_CLIENT_ID='0oa1'\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("IDPKIT_OKTA_CLIENT_SECRET", "s3cret")
    env = load_env(env_file)
    values = profile_values("okta", env)
    assert values == {"domain": "acme.okta.com", "client_id": "0oa1", "client_secret": "s3cret"}


def test_basic_auth_profile_posts_form_with_basic_header(tmp_path):
    calls: list[httpx.Request] = []
    values = {
        "domain": "acme.okta.com",
        "auth_server": "default",
        "client_id": "id",
        "client_secret": "sec",
        "scope": "mcp.read",
    }
    with httpx.Client(transport=_transport(calls)) as client:
        result = request_token(load_profile("okta"), values, client=client)
    assert result.access_token == "tok-1"
    request = calls[0]
    assert str(request.url) == "https://acme.okta.com/oauth2/default/v1/token"
    assert request.headers["authorization"] == "Basic " + base64.b64encode(b"id:sec").decode()
    form = parse_qs(request.content.decode())
    assert form["grant_type"] == ["client_credentials"]
    assert form["scope"] == ["mcp.read"]
    assert "client_secret" not in form


def test_json_profile_sends_audience_in_the_body():
    calls: list[httpx.Request] = []
    values = {
        "domain": "acme.us.auth0.com",
        "client_id": "id",
        "client_secret": "sec",
        "audience": "https://api.example.com",
    }
    with httpx.Client(transport=_transport(calls)) as client:
        request_token(load_profile("auth0"), values, client=client)
    body = json.loads(calls[0].content)
    assert body["audience"] == "https://api.example.com"
    assert body["client_secret"] == "sec"


def test_cache_reuses_a_token_until_a_minute_before_expiry(tmp_path):
    calls: list[httpx.Request] = []
    cache = TokenCache(tmp_path)
    values = {"domain": "d.auth0.com", "client_id": "i", "client_secret": "s", "audience": "a"}
    profile = load_profile("auth0")
    with httpx.Client(transport=_transport(calls, expires_in=3600)) as client:
        first = request_token(profile, values, client=client, cache=cache)
        second = request_token(profile, values, client=client, cache=cache)
        later = request_token(
            profile, values, client=client, cache=cache, now=time.time() + 3600 - 30
        )
    assert (first.from_cache, second.from_cache, later.from_cache) == (False, True, False)
    assert len(calls) == 2


def test_token_errors_never_echo_the_secret():
    def handler(request):
        return httpx.Response(401, json={"error": "invalid_client"})

    values = {"domain": "d.auth0.com", "client_id": "i", "client_secret": "s3cret", "audience": "a"}
    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as client,
        pytest.raises(RuntimeError) as err,
    ):
        request_token(load_profile("auth0"), values, client=client)
    assert "invalid_client" in str(err.value)
    assert "s3cret" not in str(err.value)


def test_capture_masks_identifiers_and_keeps_the_shape():
    claims = {
        "iss": "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0",
        "aud": "66666666-7777-8888-9999-000000000000",
        "azp": "abcd",
        "tid": "11111111-2222-3333-4444-555555555555",
        "oid": "x",
        "sub": "x",
        "jti": "drop-me",
        "uti": "drop-me",
        "scp": "pets.read",
        "ver": "2.0",
        "iat": 1000,
        "exp": 4600,
    }
    clean = sanitize(claims)
    assert clean["iss"] == "<issuer>"
    assert clean["aud"] == "<audience>"
    assert clean["azp"] == "<azp>"
    assert clean["tid"] == "<tid>"
    assert "jti" not in clean and "uti" not in clean
    assert clean["scp"] == "pets.read"
    assert clean["ver"] == "2.0"
    assert (clean["iat"], clean["exp"]) == (0, 3600)


def test_capture_drops_client_addresses_and_masks_usernames():
    clean = sanitize(
        {
            "preferred_username": "service-account-idpkit-m2m",
            "clientAddress": "172.19.0.1",
            "clientHost": "172.19.0.1",
        }
    )
    assert clean == {"preferred_username": "<preferred_username>"}


def test_domain_tolerates_a_pasted_url():
    env = {"IDPKIT_COGNITO_DOMAIN": "https://pool.auth.us-east-1.amazoncognito.com/"}
    assert profile_values("cognito", env)["domain"] == "pool.auth.us-east-1.amazoncognito.com"
