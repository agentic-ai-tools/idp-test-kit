"""A local OIDC issuer that mints tokens shaped like a real provider's.

Serves the discovery document, JWKS and a client-credentials ``/token`` endpoint from a
thread on 127.0.0.1. Tests use it in-process; ``idpkit mock`` runs it in the
foreground (put an https tunnel in front when the resource server requires https).
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import threading
import time
import uuid
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from idpkit.profiles import Shape

WELL_KNOWN = "/.well-known/openid-configuration"


def _load_or_create_key(path: Path | None) -> rsa.RSAPrivateKey:
    """A fresh key, or the one in ``path`` (created there on first use)."""
    if path is not None and path.is_file():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        assert isinstance(key, rsa.RSAPrivateKey)
        return key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        path.write_bytes(pem)
    return key


def _b64(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class MockIssuer:
    def __init__(
        self,
        public_url: str | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
        key_path: str | Path | None = None,
    ):
        self._key = _load_or_create_key(Path(key_path) if key_path else None)
        public = self._key.public_key().public_numbers()
        self.kid = hashlib.sha256(_b64(public.n).encode()).hexdigest()[:16]
        self._public_url = public_url.rstrip("/") if public_url else None
        self._host, self._port = host, port
        self._server: ThreadingHTTPServer | None = None
        self._discovery_override: dict[str, Any] | None = None
        #: Shape used by POST /token (``idpkit mock --shape``).
        self.token_shape = Shape(client_claim="client_id", audience=True)
        self.token_audience = "api://idpkit"

    # ------------------------------------------------------------------ urls

    @property
    def issuer(self) -> str:
        if self._public_url:
            return self._public_url
        if self._server is None:
            raise RuntimeError("start the issuer first")
        return f"http://{self._host}:{self._server.server_port}"

    @property
    def discovery_url(self) -> str:
        return self.issuer + WELL_KNOWN

    def discovery(self) -> dict[str, Any]:
        if self._discovery_override is not None:
            return self._discovery_override
        return {
            "issuer": self.issuer,
            "jwks_uri": self.issuer + "/jwks",
            "token_endpoint": self.issuer + "/token",
            "grant_types_supported": ["client_credentials"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }

    def jwks(self) -> dict[str, Any]:
        public = self._key.public_key().public_numbers()
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": self.kid,
                    "n": _b64(public.n),
                    "e": _b64(public.e),
                }
            ]
        }

    @contextlib.contextmanager
    def override_discovery(self, document: dict[str, Any]) -> Iterator[None]:
        self._discovery_override = document
        try:
            yield
        finally:
            self._discovery_override = None

    # ------------------------------------------------------------------ tokens

    def claims_for(
        self,
        shape: Shape,
        *,
        client_id: str = "idpkit-client",
        audience: str | list[str] = "api://idpkit",
        scopes: tuple[str, ...] = ("mcp.read",),
        lifetime: int = 300,
        **overrides: Any,
    ) -> dict[str, Any]:
        """Claims a provider with this shape would issue; ``key=None`` removes a claim."""
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": client_id,
            "iat": now,
            "nbf": now,
            "exp": now + lifetime,
            "jti": uuid.uuid4().hex,
        }
        for name in (shape.client_claim, *shape.also_client_claims):
            if name:
                claims[name] = client_id
        if shape.audience:
            claims["aud"] = audience
        if scopes:
            value = " ".join(scopes) if shape.scope_format == "string" else list(scopes)
            claims[shape.scope_claim] = value
        claims.update(shape.extra)
        for key, value in overrides.items():
            if value is None:
                claims.pop(key, None)
            else:
                claims[key] = value
        return claims

    def sign(self, claims: dict[str, Any]) -> str:
        return jwt.encode(claims, self._key, algorithm="RS256", headers={"kid": self.kid})

    def mint(self, shape: Shape, **kwargs: Any) -> str:
        return self.sign(self.claims_for(shape, **kwargs))

    # ------------------------------------------------------------------ server

    def start(self) -> MockIssuer:
        issuer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                return

            def _json(self, status: int, body: dict[str, Any]) -> None:
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:
                if self.path == WELL_KNOWN:
                    self._json(200, issuer.discovery())
                elif self.path == "/jwks":
                    self._json(200, issuer.jwks())
                else:
                    self._json(404, {"error": "not_found"})

            def do_POST(self) -> None:
                if self.path != "/token":
                    self._json(404, {"error": "not_found"})
                    return
                length = int(self.headers.get("Content-Length") or 0)
                form = parse_qs(self.rfile.read(length).decode())
                if form.get("grant_type") != ["client_credentials"]:
                    self._json(400, {"error": "unsupported_grant_type"})
                    return
                client_id = (form.get("client_id") or ["idpkit-client"])[0]
                scopes = tuple((form.get("scope") or [""])[0].split())
                token = issuer.mint(
                    issuer.token_shape,
                    client_id=client_id,
                    audience=issuer.token_audience,
                    scopes=scopes,
                )
                body = {"access_token": token, "token_type": "Bearer", "expires_in": 300}
                self._json(200, body)

        self._server = ThreadingHTTPServer((self._host, self._port), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def __enter__(self) -> MockIssuer:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()
