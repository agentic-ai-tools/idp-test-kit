from __future__ import annotations

import pytest

from idpkit.profiles import all_profiles, load_profile, render

PROVIDERS = {"cognito", "okta", "auth0", "entra", "keycloak"}


def test_every_provider_has_a_profile_with_sources():
    profiles = {p.name: p for p in all_profiles()}
    assert set(profiles) >= PROVIDERS
    for profile in profiles.values():
        assert profile.sources, profile.name
        assert profile.discovery_url.endswith("/.well-known/openid-configuration")
        # Nothing is verified until a real token was captured (AGENTS.md).
        if profile.verified:
            assert profile.verified_on, profile.name


def test_client_claims_match_the_research():
    assert load_profile("cognito").shape.client_claim == "client_id"
    assert load_profile("okta").shape.client_claim == "cid"
    assert load_profile("entra").shape.client_claim == "azp"
    # App-only (client credentials) tokens carry app roles, not delegated scp.
    assert load_profile("entra").shape.scope_claim == "roles"
    assert load_profile("cognito").shape.audience is False


def test_render_names_the_missing_env_var():
    assert render("https://{domain}/x", {"domain": "acme.okta.com"}) == "https://acme.okta.com/x"
    with pytest.raises(KeyError, match="IDPKIT_OKTA_DOMAIN"):
        render("https://{domain}/x", {}, profile="okta")


def test_unknown_profile():
    with pytest.raises(KeyError, match="nope"):
        load_profile("nope")


def test_keycloak_shape_was_confirmed_with_a_real_token():
    keycloak = load_profile("keycloak")
    assert keycloak.verified and keycloak.verified_on
    assert keycloak.shape.client_claim == "client_id"
    assert keycloak.shape.also_client_claims == ("azp",)
    assert keycloak.shape.audience is True
