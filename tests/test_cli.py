from __future__ import annotations

from typer.testing import CliRunner

from idpkit.cli import app
from idpkit.profiles import load_profile

runner = CliRunner()


def test_profiles_lists_every_provider_and_its_status():
    result = runner.invoke(app, ["profiles"])
    assert result.exit_code == 0, result.output
    for name in ("cognito", "okta", "auth0", "entra", "keycloak"):
        assert name in result.output
    assert "unverified" in result.output


def test_discover_exits_non_zero_on_problems(idp):
    ok = runner.invoke(app, ["discover", idp.discovery_url, "--allow-http"])
    assert ok.exit_code == 0, ok.output
    assert "issuer" in ok.output
    strict = runner.invoke(app, ["discover", idp.discovery_url])
    assert strict.exit_code == 1
    assert "https" in strict.output


def test_inspect_prints_claims_and_who_accepts_the_token(idp):
    token = idp.mint(load_profile("okta").shape, client_id="0oa1", audience="api://default")
    result = runner.invoke(
        app,
        [
            "inspect",
            token,
            "--discovery",
            idp.discovery_url,
            "--allow-http",
            "--client",
            "0oa1",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "cid" in result.output
    assert "signature: ok" in result.output
    assert "mcp-wizard-0.6: REJECT (403)" in result.output
    assert "agentcore: REJECT" in result.output
    # The raw token is never echoed.
    assert token not in result.output


def test_inspect_needs_a_token_or_a_profile():
    result = runner.invoke(app, ["inspect"])
    assert result.exit_code == 2


def test_token_hides_the_token_unless_asked(monkeypatch, tmp_path):
    from idpkit import cli
    from idpkit.tokens import TokenResult

    monkeypatch.setattr(
        cli, "request_token", lambda *a, **k: TokenResult("secret-token", 9e9, from_cache=True)
    )
    env = tmp_path / ".env"
    env.write_text("IDPKIT_AUTH0_DOMAIN=x\n", encoding="utf-8")
    hidden = runner.invoke(app, ["token", "auth0", "--env-file", str(env)])
    assert hidden.exit_code == 0, hidden.output
    assert "secret-token" not in hidden.output
    assert "cached" in hidden.output
    shown = runner.invoke(app, ["token", "auth0", "--env-file", str(env), "--show-token"])
    assert "secret-token" in shown.output


def test_token_device_flow_prompts_and_hides_the_token(monkeypatch, tmp_path):
    from idpkit import cli
    from idpkit.discovery import DiscoveryReport
    from idpkit.tokens import TokenResult

    def fake_device(profile, values, *, discovery, on_prompt, **kwargs):
        assert discovery["token_endpoint"] == "https://idp/token"
        on_prompt("https://idp/activate?user_code=AB-12", "AB-12")
        return TokenResult("user-token", 9e9, from_cache=False)

    report = DiscoveryReport(
        url="u", document={"issuer": "https://idp", "token_endpoint": "https://idp/token"}
    )
    monkeypatch.setattr(cli, "check_discovery", lambda *a, **k: report)
    monkeypatch.setattr(cli, "request_device_token", fake_device)
    env = tmp_path / ".env"
    env.write_text(
        "IDPKIT_OKTA_DOMAIN=idp\nIDPKIT_OKTA_AUTH_SERVER=default\nIDPKIT_OKTA_CLIENT_ID=c\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["token", "okta", "--device", "--env-file", str(env)])
    assert result.exit_code == 0, result.output
    assert "https://idp/activate?user_code=AB-12" in result.output
    assert "AB-12" in result.output
    assert "user-token" not in result.output


def test_main_prints_one_line_errors(monkeypatch, capsys):
    import httpx
    import pytest

    from idpkit import cli

    def boom():
        raise httpx.ConnectError("getaddrinfo failed")

    monkeypatch.setattr(cli, "app", boom)
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    assert exit_info.value.code == 1
    err = capsys.readouterr().err
    assert "error: getaddrinfo failed" in err and ".env" in err
