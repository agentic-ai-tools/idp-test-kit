# Provider setup (free tiers)

Each provider needs one **machine-to-machine (client credentials) client** and one
**API / audience** it can request tokens for. Put the values in `.env` (see
`.env.example`), then:

```bash
idpkit discover <discovery URL>             # https, issuer match, JWKS
idpkit inspect --profile <name> --aud <audience> --client <client-id>
idpkit capture <name>                       # sanitized fixture -> fixtures/claims/<name>/
```

Mark a profile `verified = true` (with `verified_on`) only after `capture` wrote a fixture.

## Keycloak (local, $0) — verified

`docker compose -f stacks/keycloak/compose.yml up -d keycloak`. The realm `idpkit` has two
service-account clients (secret `idpkit-local-test-secret`, test-only):
`idpkit-m2m` (an Audience mapper adds `api://mcp`) and `idpkit-m2m-no-audience`.
For an https issuer add `--profile tunnel` and read the `trycloudflare.com` URL from
`docker compose ... logs tunnel`. Stop the tunnel when done: it is public.

## Amazon Cognito

1. Create a user pool and a **domain** (Cognito or custom).
2. Add a **resource server** (identifier e.g. `mcp`) with a scope (e.g. `read`).
3. Add a **confidential app client** with the client-credentials flow and scope `mcp/read`.
4. `.env`: region, pool ID, domain host, client ID/secret, `IDPKIT_COGNITO_SCOPE=mcp/read`.

Cost: M2M token requests are billed per successful request. `idpkit` caches tokens.

## Okta (Integrator Free Plan)

1. Sign up at developer.okta.com and pick **Integrator** (not Trial).
2. Security > API > Authorization Servers > `default`: note the **Audience**
   (`api://default`), add a scope (e.g. `mcp.read`), and an access policy rule that
   allows the client-credentials grant for your app.
3. Applications > Create App Integration > **API Services**: copy client ID/secret.
4. `.env`: domain, `IDPKIT_OKTA_AUTH_SERVER=default`, client ID/secret, scope.

## Auth0 (Free)

1. Applications > APIs > Create API: the **identifier** is the audience.
2. Create a **Machine to Machine** application authorized for that API (grant a scope).
3. `.env`: tenant domain, client ID/secret, `IDPKIT_AUTH0_AUDIENCE=<identifier>`.

Quota: 1,000 M2M tokens a month on Free; reuse cached tokens.

## Microsoft Entra ID

1. App registration **API**: Expose an API (Application ID URI, e.g. `api://<app-id>`),
   add an **app role** allowed for applications (e.g. `mcp.read`), and set
   `accessTokenAcceptedVersion` to `2` in the manifest (otherwise tokens are v1).
2. App registration **client**: add a client secret, API permissions > the API's app
   role (application permission) > grant admin consent.
3. `.env`: tenant ID, client ID/secret, `IDPKIT_ENTRA_SCOPE=api://<api-app-id>/.default`.

App-only tokens carry the role in `roles` (not `scp`) and the client in `azp`.
