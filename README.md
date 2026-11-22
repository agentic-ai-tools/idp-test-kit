# idp-test-kit

Test JWT auth against **real identity providers** without standing up infrastructure.
`idpkit` answers two questions for any JWT-protected service:

1. **What does this provider's token really contain?** (`inspect`, `capture`)
2. **Does this resource server accept it, and reject the bad ones?** (`probe`)

Providers: Amazon Cognito, Okta, Auth0, Microsoft Entra ID, Keycloak, and any OIDC issuer.
Everything runs on free tiers or locally; nothing here holds secrets.

## Install

```bash
python -m pip install -e ".[dev]"     # Python 3.11+
cp .env.example .env                  # tenant settings, never committed
```

## Commands

| Command | What it does |
|---|---|
| `idpkit profiles` | Provider profiles and whether a real token confirmed them |
| `idpkit discover URL` | Checks a discovery document: https, issuer match, JWKS |
| `idpkit token PROFILE` | Client-credentials token, cached until a minute before expiry |
| `idpkit inspect [TOKEN] [--profile P] --aud A --client C --scope S` | Claims, signature check, and which validators would accept it |
| `idpkit capture PROFILE` | Sanitized claim set -> `fixtures/claims/PROFILE/` (identifiers masked) |
| `idpkit mock --shape P` | Local issuer minting tokens shaped like provider P |
| `idpkit probe URL --mock P` / `--profile P` | Sends a token matrix to an MCP endpoint and checks every status |

Raw tokens are never printed unless you pass `--show-token`.

## Validator models

`inspect` and `probe` judge claims with small, cited models of real validators
(`src/idpkit/validators.py`):

- `mcp-wizard-0.6`: the MCP Wizard generated server (client in `client_id` or `azp`,
  scopes in `scope` or `scp`; 401 for a bad token, 403 for the wrong client or scope).
- `agentcore`: Bedrock AgentCore's JWT authorizer (`allowedAudience` vs `aud`,
  `allowedClients` vs `client_id` only).
- `rfc9068`: the JWT access token profile.

## What it has found so far

| Provider | Client claim | `aud` | Scopes | Status |
|---|---|---|---|---|
| Keycloak 26.4 | `client_id` + `azp` | `account` (+ mapper value) | `scope` | **verified** |
| Cognito | `client_id` | none on plain M2M tokens | `scope` | from docs |
| Okta | `cid` | auth server Audience | `scp` | from docs |
| Auth0 | `azp` | API identifier | `scope` | from docs |
| Entra ID v2 | `azp` | API client ID | `roles` (app-only) | from docs |

So "allowed clients" cannot match Okta tokens on the MCP Wizard server, or Okta, Auth0 and
Entra tokens on AgentCore. Plain Cognito M2M tokens have no audience to allow. Entra app
roles are not scopes to the MCP Wizard server.
`scenarios/mcp-wizard-local` confirms the model against a real generated server.

## Layout

- `src/idpkit/` CLI and library; `profiles/*.toml` provider facts with sources
- `fixtures/claims/` sanitized real claim sets
- `stacks/keycloak/` local Keycloak realm (+ optional cloudflared https tunnel)
- `scenarios/mcp-wizard-local/` probe an MCP Wizard generated server ($0, no Docker)
- `docs/providers.md` free-tier setup for each provider

## License

MIT
