# Provider setup guide

This guide is for someone setting up a provider **for the first time**. Each section says
what to create, with example values, what a correct token looks like, and how to fix the
usual errors. Console menus change often. If a label differs slightly, look for the same
idea nearby.

> All IDs, domains and secrets below are **made-up examples**. Use your own, and put them
> only in `.env` (git-ignored), never in a commit.

## First: the two things you register everywhere

Every provider needs the same two registrations. They just name them differently.

1. **The API**: the thing that *checks* tokens. In the MCP Wizard case, that is your
   generated MCP server. Registering it gives you an **audience**, the value tokens
   carry in their `aud` claim to say "this token is meant for that API". You can also
   define **scopes** (or roles): named permissions such as `mcp.read`.
2. **The caller**: the program that *asks for* tokens, for example an agent or a CI job
   calling your MCP server. It has no human user. It logs in as itself with a
   **client ID** and **client secret**. This is called the **client credentials** flow, or
   "machine-to-machine" (M2M). Providers call the caller an *application*, *app
   integration*, *app client* or *client*.

Then you **connect them**: allow the caller to get tokens for the API, with certain
scopes. Most "why is my token rejected" problems are a missing connection.

| | The API (checks tokens) | The caller (gets tokens) | Connecting them |
|---|---|---|---|
| **Keycloak** | (none needed) audience via an Audience mapper | Client with *service accounts* on | the mapper on the client |
| **Cognito** | Resource server (+ custom scopes) | App client, type *Machine-to-machine* | tick the scopes on the app client |
| **Okta** | Authorization server (`default`) + scope | App integration, type *API Services* | access policy + rule on the authorization server |
| **Auth0** | API (its *identifier* is the audience) | Application, type *Machine to Machine* | authorize the application for the API |
| **Entra ID** | App registration that *exposes an API* + app role | Second app registration with a secret | API permission (application) + admin consent |

Other words you will see:

- **Issuer / discovery URL**: the provider's address. The discovery URL ends in
  `/.well-known/openid-configuration` and tells servers where the signing keys are.
- **Claims**: the fields inside a token (`iss`, `aud`, `scope`...). `idpkit inspect`
  shows them.

## The same four commands for every provider

```bash
cp .env.example .env            # once; then fill in one provider's block
idpkit discover <discovery URL> # is the provider reachable and well-formed?
idpkit token <profile>          # can the caller get a token? (cached; hidden)
idpkit inspect --profile <profile> --aud <audience> --client <client-id> --scope <scope>
idpkit capture <profile>        # when it looks right: masked fixture for the repo
```

`inspect` ends with one line per validator, for example:

```
mcp-wizard-0.6: accept - accepted
agentcore: REJECT (401) - client_id does not match allowedClients
rfc9068: accept - accepted
```

A REJECT there is not necessarily a mistake in your setup. It may be a fact about the
provider, and that is exactly what the kit is for. The "What to enter in MCP Wizard"
part of each section says which settings work.

---

## Keycloak (local, free, 10 minutes) — verified

Best first provider: no account, runs on your machine.

**Start it**

```bash
docker compose -f stacks/keycloak/compose.yml up -d keycloak
idpkit discover http://127.0.0.1:8180/realms/idpkit/.well-known/openid-configuration --allow-http
```

The realm `idpkit` is imported with two callers, both with secret
`idpkit-local-test-secret` (test-only, public in this repo):

- `idpkit-m2m`: an **Audience mapper** adds `api://mcp` to its tokens.
- `idpkit-m2m-no-audience`: Keycloak's default shape, with `aud` = `account` only.

The admin console is at http://127.0.0.1:8180 (`admin` / `admin`) if you want to look.

**`.env`** (already in `.env.example`)

```
IDPKIT_KEYCLOAK_BASE_URL=http://127.0.0.1:8180
IDPKIT_KEYCLOAK_REALM=idpkit
IDPKIT_KEYCLOAK_CLIENT_ID=idpkit-m2m
IDPKIT_KEYCLOAK_CLIENT_SECRET=idpkit-local-test-secret
```

**Check**: `idpkit inspect --profile keycloak --allow-http --aud api://mcp`

**A correct token contains** (Keycloak 26.4):

```json
{
  "iss": "http://127.0.0.1:8180/realms/idpkit",
  "aud": ["api://mcp", "account"],
  "client_id": "idpkit-m2m",
  "azp": "idpkit-m2m",
  "scope": "profile email"
}
```

**An https issuer**: some servers, including the MCP Wizard server for anything except
`127.0.0.1`, refuse `http://`. Start the tunnel and use its URL as `IDPKIT_KEYCLOAK_BASE_URL`:

```bash
docker compose -f stacks/keycloak/compose.yml --profile tunnel up -d
docker compose -f stacks/keycloak/compose.yml logs tunnel | grep trycloudflare
```

The tunnel is public. Stop everything when done:
`docker compose -f stacks/keycloak/compose.yml down`.

**Your own Keycloak**: create a client with *Client authentication* **on** and
*Service accounts roles* **on** (that enables client credentials). Then on the client's
*Client scopes* > *dedicated* scope > *Add mapper* > *By configuration* > **Audience**, set
*Included Custom Audience* to your API's audience, with *Add to access token* on. Use the
custom audience field rather than the client picker; the picker can insert the client's
internal ID.

**What to enter in MCP Wizard** (preset *Keycloak*): base URL + realm; allowed audience
`api://mcp` (the mapper's value). Allowed clients also work: tokens carry `client_id`.

---

## Amazon Cognito (AWS account, 20 minutes, cents)

**Before you start**: you need an AWS account and console access to Cognito. The user pool
itself costs nothing at this scale. Machine-to-machine token requests are billed **per
successful request**: `idpkit` caches tokens, so a session costs cents.

**1. Create a user pool.** Console > Amazon Cognito > *User pools* > *Create user pool*.
Any sign-in options are fine: nobody signs in, only machines.
Note the **pool ID**, e.g. `us-east-1_AbC123xyz` (its prefix is the region).

**2. Create the API (a "resource server").** In the pool, find *Resource servers*
(under *App integration* or *Branding/Domain*, depending on the console version) >
*Create resource server*:
- Name `MCP server`, identifier **`mcp`**
- Custom scope **`read`**. The full scope name becomes **`mcp/read`**.

**3. Create a domain.** *Domain* > *Create Cognito domain*, e.g. prefix `idpkit-test-4821`.
The token endpoint lives on it: `idpkit-test-4821.auth.us-east-1.amazoncognito.com`.

**4. Create the caller (an "app client").** *App clients* > *Create app client* > application
type **Machine-to-machine application**, name `idpkit-caller`. Select the custom scope
`mcp/read`. Machine-to-machine clients get a **client secret** and the client credentials
grant. Copy the **client ID** and **client secret** from the client's page.

**`.env`**

```
IDPKIT_COGNITO_REGION=us-east-1
IDPKIT_COGNITO_POOL_ID=us-east-1_AbC123xyz
IDPKIT_COGNITO_DOMAIN=idpkit-test-4821.auth.us-east-1.amazoncognito.com
IDPKIT_COGNITO_CLIENT_ID=4f8example1clientid2abc
IDPKIT_COGNITO_CLIENT_SECRET=...
IDPKIT_COGNITO_SCOPE=mcp/read
```

**Check**: `idpkit inspect --profile cognito --client 4f8example1clientid2abc --scope mcp/read`

**Expected** (from the docs, until captured): `client_id` names the caller,
`scope` is `"mcp/read"`, `token_use` is `"access"`, and **there is no `aud`** on a plain
machine-to-machine token.

**What to enter in MCP Wizard** (preset *Amazon Cognito — existing user pool*): region +
pool ID; **allowed clients** = the app client ID. Do not rely on an audience: the token
has none. (The *create a new user pool* preset makes Terraform build all of this for
AgentCore.)

**Common errors**

| Error | Fix |
|---|---|
| `invalid_client` | wrong client ID/secret, or the client has no secret (recreate it as Machine-to-machine) |
| `unauthorized_client` | client credentials not enabled on the app client |
| `invalid_scope` | scope not ticked on the app client, or typo (`mcp/read`, with the slash) |
| connection error | `IDPKIT_COGNITO_DOMAIN` must be the domain host, without `https://` |

---

## Auth0 (free account, 15 minutes)

**Before you start**: sign up at auth0.com; you get a tenant domain such as
`dev-abc123.us.auth0.com`. The Free plan allows **1,000 machine-to-machine tokens a month**.
`idpkit` reuses a cached token until a minute before it expires.

**1. Create the API.** Dashboard > *Applications* > *APIs* > *Create API*:
- Name `MCP server`
- **Identifier** `https://mcp.example.com`. It is only a label, so it doesn't need to
  resolve. **This identifier is the audience.**
- Under *Permissions*, add `mcp.read`.

**2. Create the caller.** *Applications* > *Applications* > *Create Application* > type
**Machine to Machine Applications**, name `idpkit-caller`. When asked which API it may call,
pick **MCP server** and tick **`mcp.read`** > *Authorize*. That is the connection.
Copy the **Client ID** and **Client Secret** from the application's *Settings*.

**`.env`**

```
IDPKIT_AUTH0_DOMAIN=dev-abc123.us.auth0.com
IDPKIT_AUTH0_CLIENT_ID=Xy7exampleClientId
IDPKIT_AUTH0_CLIENT_SECRET=...
IDPKIT_AUTH0_AUDIENCE=https://mcp.example.com
```

**Check**: `idpkit inspect --profile auth0 --aud https://mcp.example.com --scope mcp.read`

**Expected** (until captured): `aud` = your identifier, `azp` = the client ID,
`gty` = `client-credentials`, `scope` = `"mcp.read"`.

**What to enter in MCP Wizard** (preset *Auth0*): tenant domain; **allowed audience** = the
API identifier; scopes `mcp.read` optional. Allowed clients work on the Docker target
(`azp`), but not on AgentCore, which only reads `client_id`.

**Common errors**

| Error | Fix |
|---|---|
| `access_denied` … "not authorized to access resource server" | the application was not authorized for the API (step 2), or the audience is mistyped |
| `invalid_client` | wrong client ID/secret |
| `too_many_requests` / quota | monthly M2M quota used up; wait for the reset or reuse cached tokens |

---

## Microsoft Entra ID (Microsoft account, 25 minutes)

**Before you start**: you need an Entra tenant where you can register apps and grant
admin consent. A personal Azure free account creates one. Note the **tenant ID** (a GUID)
on the Entra admin center *Overview* page.

Entra registers **both** the API and the caller as "app registrations".

**1. Register the API.** Entra admin center > *App registrations* > *New registration*,
name `MCP server`, single tenant. Then:
- *Expose an API* > *Application ID URI* > *Add*: accept `api://<api-app-id>`.
- *App roles* > *Create app role*: display name `MCP read`, allowed member types
  **Applications**, value **`mcp.read`**. Machine callers get **app roles**, not scopes.
- *Manifest*: set the access token version to **2**. In the editor this key is called
  `accessTokenAcceptedVersion` (newer format: `api.requestedAccessTokenVersion`). Without
  it, tokens are v1, with issuer `sts.windows.net` and `appid` instead of `azp`, and
  servers expecting `login.microsoftonline.com` reject them.

**2. Register the caller.** *New registration*, name `idpkit-caller`. Then:
- *Certificates & secrets* > *New client secret*. Copy the **value** now (it is shown
  once). Copy the caller's **Application (client) ID** from *Overview*.
- *API permissions* > *Add a permission* > *My APIs* > **MCP server** > **Application
  permissions** > tick `mcp.read` > *Add*.
- **Grant admin consent** for the tenant. Without it the token has no `roles`.

**`.env`**

```
IDPKIT_ENTRA_TENANT=11111111-2222-3333-4444-555555555555
IDPKIT_ENTRA_CLIENT_ID=<caller application (client) ID>
IDPKIT_ENTRA_CLIENT_SECRET=...
IDPKIT_ENTRA_SCOPE=api://<api-app-id>/.default
```

The scope for client credentials is always the API's ID URI plus **`/.default`**. It means
"every application permission granted to me".

**Check**: `idpkit inspect --profile entra --aud <api-app-id> --client <caller-client-id>`

**Expected** (until captured): `iss` = `https://login.microsoftonline.com/<tenant>/v2.0`,
`aud` = the **API's** client ID (a GUID), `azp` = the **caller's** client ID,
`roles` = `["mcp.read"]`, `ver` = `"2.0"`, `idtyp` = `"app"`. There is **no `scp`** on app-only
tokens.

**What to enter in MCP Wizard** (preset *Microsoft Entra ID*): tenant ID; **allowed
audience** = the API app's client ID. Do not use allowed scopes: the permission is in
`roles`, which the generated server does not read as scopes, so it answers 403. Allowed
clients work on Docker (`azp`), not on AgentCore.

**Common errors**

| Error | Fix |
|---|---|
| `AADSTS7000215` invalid client secret | you copied the secret's ID, not its value; create a new secret |
| `AADSTS70011` invalid scope | the scope must end with `/.default` |
| `AADSTS500011` resource not found | the Application ID URI in the scope is wrong |
| token has no `roles` | admin consent not granted, or the permission was added as *Delegated* instead of *Application* |
| `iss` is `sts.windows.net/...` | the API's manifest still asks for v1 tokens (step 1) |

---

## Okta (free account — read the warning first)

> **Warning: client credentials may not be available on Okta's free plan.** Okta's help
> says the *Client Credentials* option in authorization-server access policies only
> appears for orgs with an "NHI Authentication Token" subscription bought or renewed on
> or after 2026-08-14. Integrator Free users report the option is missing. If you can't
> select *Client Credentials* in step 4, the free plan can't issue machine tokens. Use
> `idpkit mock --shape okta` to test the token shape until you have a paid or trial org.

**Before you start**: sign up at developer.okta.com and choose **Integrator Free Plan**
(not *Trial*). Your org domain looks like `integrator-1234567.okta.com`.

**1. The API is the authorization server.** Admin console > *Security* > *API* >
*Authorization Servers* > **default**. Note its **Audience** (`api://default` unless
you change it). That is the value tokens carry in `aud`.

**2. Add a scope.** On the `default` server > *Scopes* > *Add Scope*, name **`mcp.read`**.

**3. Create the caller ("app integration").** *Applications* > *Applications* > *Create App
Integration* > **API Services**, name `idpkit-caller`. API Services is Okta's type for
machine callers. Copy the **Client ID** and **Client secret** from its *General* tab.

**4. Connect them (the "access policy").** This is the step that tells the authorization
server *which callers may get tokens, and how*. Back on the `default` server > *Access
Policies* > *Add Policy*:
- Name `idpkit machine callers`, **Assign to**: *The following clients* > `idpkit-caller`
  (the app you made in step 3).
- Inside the policy > *Add Rule*: name `client credentials`, *Grant type*: tick
  **Client Credentials**. *User is*: leave the default; machine callers have no user.
  Scopes: **`mcp.read`** (or *Any scopes*). Save.

Without a matching policy and rule, the token request fails, even with a correct ID and
secret. Okta applies the **first** policy and rule that match, in order.

**`.env`**

```
IDPKIT_OKTA_DOMAIN=integrator-1234567.okta.com
IDPKIT_OKTA_AUTH_SERVER=default
IDPKIT_OKTA_CLIENT_ID=0oaExampleClientId
IDPKIT_OKTA_CLIENT_SECRET=...
IDPKIT_OKTA_SCOPE=mcp.read
```

**Check**: `idpkit inspect --profile okta --aud api://default --client 0oaExampleClientId --scope mcp.read`

**Expected** (until captured): `aud` = `api://default`, **`cid`** = the client ID (Okta's own
claim name, not `client_id` or `azp`), `scp` = `["mcp.read"]`.

**What to enter in MCP Wizard** (preset *Okta*): domain + authorization server; **allowed
audience** `api://default`; scopes work (`scp`). Do **not** use allowed clients: neither
the generated server nor AgentCore reads `cid`, so the token is always refused.

**Common errors**

| Error | Fix |
|---|---|
| `access_denied` "Policy evaluation failed" / no matching policy | step 4 missing, or the policy isn't assigned to this client |
| `unauthorized_client` "not authorized to use the provided grant type" | the rule doesn't tick Client Credentials, or the option is unavailable on this plan (see the warning) |
| `invalid_scope` | the scope isn't on the authorization server, or the rule doesn't grant it |
| 404 on the token URL | `IDPKIT_OKTA_DOMAIN` must be the org host only (no `https://`, no `-admin`) |

---

## After a provider works

1. `idpkit capture <profile>` writes `fixtures/claims/<profile>/client-credentials.json`.
   Identifiers become placeholders and times become relative.
2. Open the file and check that nothing identifies your tenant.
3. In `src/idpkit/profiles/<profile>.toml`, set `verified = true` and `verified_on`, and
   fix anything the real token showed differently from the docs. Open a PR with both.
