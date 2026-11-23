"""Client-credentials tokens from a real provider, cached on disk until near expiry.

The cache keeps quota-limited tenants (Auth0 Free: 1,000 M2M tokens a month) and
per-request billing (Cognito M2M) cheap. It lives in ``.idpkit/`` (git-ignored).
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import httpx

from idpkit.profiles import Profile, render

REFRESH_MARGIN_SECONDS = 60


@dataclass(frozen=True)
class TokenResult:
    access_token: str
    expires_at: float
    from_cache: bool


class TokenCache:
    def __init__(self, folder: str | Path = ".idpkit/tokens"):
        self.folder = Path(folder)

    def _path(self, key: str) -> Path:
        return self.folder / f"{key}.json"

    def get(self, key: str, now: float) -> TokenResult | None:
        path = self._path(key)
        if not path.is_file():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        if data["expires_at"] - REFRESH_MARGIN_SECONDS <= now:
            return None
        return TokenResult(data["access_token"], data["expires_at"], from_cache=True)

    def put(self, key: str, result: TokenResult) -> None:
        self.folder.mkdir(parents=True, exist_ok=True)
        body = {"access_token": result.access_token, "expires_at": result.expires_at}
        self._path(key).write_text(json.dumps(body), encoding="utf-8")


def _cache_key(profile: Profile, values: dict[str, str]) -> str:
    # Only the request settings identify the token (not ALLOWED_* checks); never the secret.
    request = {*profile.fields, "device_scope"} - {"client_secret"}
    public = {k: v for k, v in sorted(values.items()) if k in request}
    digest = hashlib.sha256(json.dumps(public).encode()).hexdigest()[:16]
    return f"{profile.name}-{digest}"


def request_token(
    profile: Profile,
    values: dict[str, str],
    *,
    client: httpx.Client | None = None,
    cache: TokenCache | None = None,
    now: float | None = None,
) -> TokenResult:
    now = time.time() if now is None else now
    key = _cache_key(profile, values)
    if cache is not None and (cached := cache.get(key, now)) is not None:
        return cached

    url = render(profile.token_url, values, profile=profile.name)
    params = {k: render(v, values, profile=profile.name) for k, v in profile.params.items()}
    client_id = render("{client_id}", values, profile=profile.name)
    secret = render("{client_secret}", values, profile=profile.name)
    body = {"grant_type": "client_credentials", **params}
    kwargs: dict = {}
    if profile.auth == "basic":
        kwargs = {"data": body, "auth": (client_id, secret)}
    elif profile.auth == "post":
        kwargs = {"data": {**body, "client_id": client_id, "client_secret": secret}}
    else:
        kwargs = {"json": {**body, "client_id": client_id, "client_secret": secret}}

    own = client is None
    client = client or httpx.Client(timeout=20.0)
    try:
        response = client.post(url, **kwargs)
    finally:
        if own:
            client.close()
    if response.status_code != 200:
        try:
            detail = response.json()
            error = f"{detail.get('error')}: {detail.get('error_description', '')}".strip(": ")
        except ValueError:
            error = response.text[:200]
        raise RuntimeError(f"{profile.name} token request failed ({response.status_code}): {error}")
    data = response.json()
    result = TokenResult(
        access_token=data["access_token"],
        expires_at=now + float(data.get("expires_in", 300)),
        from_cache=False,
    )
    if cache is not None:
        cache.put(key, result)
    return result


DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


def request_device_token(
    profile: Profile,
    values: dict[str, str],
    *,
    discovery: dict,
    on_prompt: Callable[[str, str], None],
    client: httpx.Client | None = None,
    cache: TokenCache | None = None,
    sleep: Callable[[float], None] = time.sleep,
    now: float | None = None,
) -> TokenResult:
    """OIDC Device Authorization (RFC 8628): ``on_prompt(uri, user_code)`` asks a person
    to approve in a browser while this polls the token endpoint.

    Scope: ``device_scope`` if set (Okta wants ``openid`` too), else the profile's scope.
    A ``client_secret`` is sent only when configured (native apps are public clients).
    """
    now = time.time() if now is None else now
    key = _cache_key(profile, values).replace(f"{profile.name}-", f"{profile.name}-device-", 1)
    if cache is not None and (cached := cache.get(key, now)) is not None:
        return cached
    device_url = discovery.get("device_authorization_endpoint")
    token_url = discovery.get("token_endpoint")
    if not isinstance(device_url, str) or not isinstance(token_url, str):
        raise RuntimeError(
            f"{profile.name}: the discovery document has no device_authorization_endpoint "
            "(this provider or authorization server does not offer the device flow)"
        )
    client_id = render("{client_id}", values, profile=profile.name)
    secret = {"client_secret": values["client_secret"]} if values.get("client_secret") else {}
    params: dict[str, str] = {}
    for name, template in profile.params.items():
        try:
            params[name] = render(template, values, profile=profile.name)
        except KeyError:
            continue  # optional for the device flow (e.g. no M2M scope configured)
    if values.get("device_scope"):
        params["scope"] = values["device_scope"]

    own = client is None
    client = client or httpx.Client(timeout=20.0)
    try:
        start = client.post(device_url, data={"client_id": client_id, **params, **secret})
        if start.status_code != 200:
            raise RuntimeError(f"{profile.name} device authorization failed: {start.text[:200]}")
        grant = start.json()
        on_prompt(
            grant.get("verification_uri_complete") or grant["verification_uri"], grant["user_code"]
        )
        interval = float(grant.get("interval", 5))
        deadline = time.monotonic() + float(grant.get("expires_in", 600))
        while time.monotonic() < deadline:
            sleep(interval)
            reply = client.post(
                token_url,
                data={
                    "grant_type": DEVICE_GRANT,
                    "device_code": grant["device_code"],
                    "client_id": client_id,
                    **secret,
                },
            )
            body = reply.json()
            if reply.status_code == 200 and "access_token" in body:
                result = TokenResult(
                    body["access_token"],
                    now + float(body.get("expires_in", 300)),
                    from_cache=False,
                )
                if cache is not None:
                    cache.put(key, result)
                return result
            error = body.get("error")
            if error == "authorization_pending":
                continue
            if error == "slow_down":
                interval += 5
                continue
            raise RuntimeError(
                f"{profile.name} device flow stopped: {error}: {body.get('error_description', '')}"
            )
        raise RuntimeError(f"{profile.name} device flow timed out before approval")
    finally:
        if own:
            client.close()
