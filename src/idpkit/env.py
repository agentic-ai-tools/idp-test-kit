"""Tenant settings from ``.env`` and the environment: ``IDPKIT_<PROFILE>_<FIELD>``."""

from __future__ import annotations

import os
from pathlib import Path


def load_env(path: str | Path = ".env") -> dict[str, str]:
    """The process environment, with values from ``path`` (if it exists) underneath."""
    values: dict[str, str] = {}
    file = Path(path)
    if file.is_file():
        for raw in file.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            values[key.strip()] = value
    values.update({k: v for k, v in os.environ.items() if k.startswith("IDPKIT_")})
    return values


def profile_values(profile: str, env: dict[str, str]) -> dict[str, str]:
    prefix = f"IDPKIT_{profile.upper()}_"
    return {k[len(prefix) :].lower(): v for k, v in env.items() if k.startswith(prefix) and v}
