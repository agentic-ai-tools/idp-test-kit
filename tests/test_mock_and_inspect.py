from __future__ import annotations

import time

import httpx

from idpkit.discovery import check_discovery
from idpkit.inspect import claim_rows, inspect_token
from idpkit.profiles import load_profile


def test_mock_serves_discovery_and_jwks(idp):
    report = check_discovery(idp.discovery_url, allow_http=True)
    assert report.problems == []
    assert report.issuer == idp.issuer
    assert report.keys == 1


def test_discovery_flags_http_and_issuer_mismatch(idp):
    assert any("https" in p for p in check_discovery(idp.discovery_url).problems)
    doc = httpx.get(idp.discovery_url).json()
    doc["issuer"] = "https://someone-else.example"
    with idp.override_discovery(doc):
        problems = check_discovery(idp.discovery_url, allow_http=True).problems
    assert any("issuer" in p for p in problems)


def test_minted_token_verifies_against_the_mock(idp):
    token = idp.mint(load_profile("okta").shape, client_id="app-1", audience="api://default")
    result = inspect_token(token, discovery_url=idp.discovery_url, allow_http=True)
    assert result.signature_ok
    assert result.problems == []
    assert result.claims["cid"] == "app-1"
    assert result.claims["aud"] == "api://default"
    assert "client_id" not in result.claims


def test_shapes_follow_each_profile(idp):
    entra = idp.claims_for(load_profile("entra").shape, client_id="c", scopes=("a", "b"))
    assert entra["azp"] == "c"
    assert entra["roles"] == ["a", "b"]
    cognito = idp.claims_for(load_profile("cognito").shape, client_id="c", scopes=("a",))
    assert "aud" not in cognito
    assert cognito["client_id"] == "c"
    assert cognito["scope"] == "a"


def test_inspect_reports_problems_instead_of_raising(idp):
    shape = load_profile("auth0").shape
    expired = idp.mint(shape, exp=int(time.time()) - 3600)
    assert any(
        "expired" in p
        for p in inspect_token(expired, discovery_url=idp.discovery_url, allow_http=True).problems
    )
    good = idp.mint(shape)
    tampered = good[:-4] + ("AAAA" if not good.endswith("AAAA") else "BBBB")
    result = inspect_token(tampered, discovery_url=idp.discovery_url, allow_http=True)
    assert not result.signature_ok
    wrong_iss = idp.mint(shape, iss="https://evil.example")
    assert any(
        "issuer" in p
        for p in inspect_token(wrong_iss, discovery_url=idp.discovery_url, allow_http=True).problems
    )


def test_inspect_without_discovery_only_decodes(idp):
    result = inspect_token(idp.mint(load_profile("keycloak").shape))
    assert result.signature_ok is None
    assert result.claims["azp"]


def test_claim_rows_put_identity_claims_first():
    rows = claim_rows({"zzz": 1, "aud": "a", "iss": "i", "azp": "c"})
    names = [name for name, _ in rows]
    assert names.index("iss") < names.index("zzz")
    assert names.index("azp") < names.index("zzz")


def test_a_key_file_lets_two_processes_share_one_issuer(tmp_path):
    from idpkit.mock import MockIssuer

    key = tmp_path / "mock-key.pem"
    url = "http://127.0.0.1:9"  # never contacted: only the signing key is shared
    first = MockIssuer(public_url=url, key_path=key)
    second = MockIssuer(public_url=url, key_path=key)
    assert key.is_file()
    assert first.kid == second.kid
    assert first.jwks() == second.jwks()


def test_shapes_can_name_the_client_in_several_claims(idp):
    claims = idp.claims_for(load_profile("keycloak").shape, client_id="kc")
    assert (claims["client_id"], claims["azp"]) == ("kc", "kc")
