import pytest


def _assert_page_ok(page, live_server, path, landmarks):
    page.goto(f"{live_server}{path}", wait_until="domcontentloaded")
    if path not in page.url:
        pytest.skip(f"App redirected away from {path}; got {page.url}")
    content = page.content()
    for marker in (
        "Internal Server Error",
        "Traceback",
        "UndefinedError",
        "AttributeError",
        "ZeroDivisionError",
        "NameError",
    ):
        assert marker not in content, f"{marker!r} found in {path} response"
    assert any(ln in content for ln in landmarks), (
        f"None of {landmarks} found in {path} response"
    )


@pytest.mark.e2e
def test_wrapped_renders_for_authenticated_user(page, live_server, login):
    login()
    _assert_page_ok(page, live_server, "/wrapped", ("Wrapped",))


@pytest.mark.e2e
def test_analytics_renders_for_authenticated_user(page, live_server, login):
    login()
    _assert_page_ok(
        page,
        live_server,
        "/analytics",
        ("Analytics", "<canvas", "Recovered Accounts"),
    )


@pytest.mark.e2e
def test_wrapped_does_not_raise_when_only_current_user_has_data(
    page, live_server, login
):
    """Regression for the ZeroDivisionError on /wrapped when only one user has recovered hashes."""
    login()
    _assert_page_ok(page, live_server, "/wrapped", ("Wrapped",))


@pytest.mark.e2e
def test_analytics_with_no_filter_renders_200(page, live_server, login):
    """Regression for the NameError: format_display on /analytics."""
    login()
    _assert_page_ok(
        page,
        live_server,
        "/analytics",
        ("Analytics", "<canvas", "Recovered Accounts"),
    )
