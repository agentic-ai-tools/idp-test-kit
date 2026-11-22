"""Client-credentials tokens from a real provider, cached on disk until near expiry.

The cache keeps quota-limited tenants (Auth0 Free: 1,000 M2M tokens a month) and
per-request billing (Cognito M2M) cheap. It lives in ``.idpkit/`` (git-ignored).
"""

from __future__ import annotations

import hashlib
import json
import time
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
    # Settings identify the token; the secret is never part of the key or the file name.
    public = {k: v for k, v in sorted(values.items()) if k != "client_secret"}
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
