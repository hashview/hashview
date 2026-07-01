"""Regression: unauthorized API requests must redirect to /v1/not_authorized.

Two routes (/v1/error and /v1/hashes/import/<hash_type>) redirected to
"/vi/not_authorized" — a typo. That path has no route, so an unauthorized
caller got a 404 instead of the intended not-authorized response. Every
other route in this blueprint uses the correct "/v1/not_authorized".
"""

import pytest


@pytest.mark.parametrize(
    "method, path",
    [
        ("post", "/v1/error"),
        ("post", "/v1/hashes/import/1000"),
    ],
)
def test_unauthorized_redirects_to_v1_not_authorized(client, method, path):
    # No auth cookie -> is_authorized() is falsy -> redirect.
    resp = getattr(client, method)(path)
    assert resp.status_code in (301, 302)
    assert resp.headers["Location"].endswith("/v1/not_authorized")
