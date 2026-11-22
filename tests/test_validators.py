"""Models of real validators, so `inspect` can say who would accept a token."""

from __future__ import annotations

import pytest

from idpkit.profiles import load_profile
from idpkit.validators import Requirements, evaluate, validate


def verdicts(claims, req):
    return {v.validator: v for v in evaluate(claims, req)}


def test_okta_cid_is_never_an_allowed_client_for_mcp_wizard_or_agentcore(idp):
    claims = idp.claims_for(load_profile("okta").shape, client_id="0oa1")
    result = verdicts(claims, Requirements(clients=("0oa1",)))
    assert not result["mcp-wizard-0.6"].accepted
    assert result["mcp-wizard-0.6"].status == 403
    assert not result["agentcore"].accepted


def test_entra_azp_passes_the_generated_server_but_not_agentcore(idp):
    claims = idp.claims_for(load_profile("entra").shape, client_id="app-guid")
    result = verdicts(claims, Requirements(clients=("app-guid",)))
    assert result["mcp-wizard-0.6"].accepted
    assert not result["agentcore"].accepted


def test_cognito_client_id_passes_both_but_has_no_audience(idp):
    claims = idp.claims_for(load_profile("cognito").shape, client_id="c1")
    assert all(v.accepted for v in evaluate(claims, Requirements(clients=("c1",))))
    by_aud = verdicts(claims, Requirements(audiences=("c1",)))
    assert not by_aud["mcp-wizard-0.6"].accepted
    assert not by_aud["agentcore"].accepted


def test_audience_matches_any_value_in_a_list(idp):
    claims = idp.claims_for(load_profile("auth0").shape, audience=["api://a", "api://b"])
    assert verdicts(claims, Requirements(audiences=("api://b",)))["agentcore"].accepted


def test_scopes_read_scope_string_and_scp_list():
    req = Requirements(scopes=("pets.read",))
    assert validate("mcp-wizard-0.6", {"scope": "openid pets.read"}, req).accepted
    assert validate("mcp-wizard-0.6", {"scp": ["pets.read"]}, req).accepted
    missing = validate("mcp-wizard-0.6", {"scope": "openid"}, req)
    assert (missing.accepted, missing.status) == (False, 403)


def test_requirements_need_at_least_one_restriction():
    with pytest.raises(ValueError, match="audience, client or scope"):
        validate("mcp-wizard-0.6", {}, Requirements())


def test_unknown_validator():
    with pytest.raises(KeyError):
        validate("nope", {}, Requirements(audiences=("a",)))


def test_entra_app_roles_are_not_scopes_to_the_generated_server(idp):
    """Client-credentials tokens from Entra put permissions in `roles`, not `scp`."""
    claims = idp.claims_for(load_profile("entra").shape, scopes=("mcp.read",))
    result = validate("mcp-wizard-0.6", claims, Requirements(scopes=("mcp.read",)))
    assert (result.accepted, result.status) == (False, 403)
