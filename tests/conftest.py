from __future__ import annotations

import pytest

from idpkit.mock import MockIssuer


@pytest.fixture()
def idp():
    with MockIssuer() as issuer:
        yield issuer
