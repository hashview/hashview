import os
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import pytest

TEST_USER_EMAIL = "admin@example.com"
TEST_USER_PASSWORD = "supersecretpassword"
_SETUP_COMPLETED = False


def _get_setup_value(key: str, fallback: str) -> str:
    value = os.getenv(key)
    if value is None or value == "":
        return fallback
    return value


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        if key and key not in os.environ:
            os.environ[key] = value


load_dotenv(Path(__file__).resolve().parents[1] / ".env.test")


def build_test_config(db_path: Path):
    return {
        "SECRET_KEY": "test-secret-key",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_path}",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "SQLALCHEMY_ENGINE_OPTIONS": {
            "connect_args": {"check_same_thread": False},
        },
        "MAIL_SUPPRESS_SEND": True,
        "HASHVIEW_SKIP_SETUP": True,
        "HASHVIEW_SKIP_GUI_SETUP": True,
        "HASHVIEW_DISABLE_SCHEDULER": True,
    }


@pytest.fixture(scope="session")
def app_config(tmp_path_factory):
    db_path_env = os.getenv("HASHVIEW_E2E_DB_PATH")
    if db_path_env:
        db_path = Path(db_path_env).expanduser().resolve()
        db_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        db_path = tmp_path_factory.mktemp("data") / "hashview_test.db"
    return build_test_config(db_path)


@pytest.fixture(scope="session")
def live_server():
    base_url = os.getenv("HASHVIEW_E2E_BASE_URL")
    if not base_url:
        pytest.skip("Set HASHVIEW_E2E_BASE_URL to run e2e tests against a live host.")
    base_url = base_url.rstrip("/")
    try:
        with urlopen(f"{base_url}/login", timeout=2):
            pass
    except URLError:
        pytest.skip(
            "External server not reachable; start it or check HASHVIEW_E2E_BASE_URL."
        )
    yield base_url


@pytest.fixture(autouse=True)
def ensure_setup(page, live_server, request):
    if not request.node.get_closest_marker("e2e"):
        return
    if request.node.get_closest_marker("agent_sim"):
        return

    global _SETUP_COMPLETED
    if _SETUP_COMPLETED:
        return

    page.goto(f"{live_server}/login", wait_until="domcontentloaded")

    if "/setup/admin-pass" in page.url:
        first_name = _get_setup_value("HASHVIEW_E2E_SETUP_FIRST_NAME", "Admin")
        last_name = _get_setup_value("HASHVIEW_E2E_SETUP_LAST_NAME", "User")
        email = _get_setup_value("HASHVIEW_E2E_SETUP_EMAIL", TEST_USER_EMAIL)
        password = _get_setup_value(
            "HASHVIEW_E2E_SETUP_PASSWORD",
            _get_setup_value("HASHVIEW_E2E_PASSWORD", TEST_USER_PASSWORD),
        )

        page.get_by_label("First Name").fill(first_name)
        page.get_by_label("Last Name").fill(last_name)
        page.get_by_label("Email").fill(email)
        page.locator("#password").fill(password)
        page.locator("#confirm_password").fill(password)
        page.get_by_role("button", name="Update").click()
        page.wait_for_load_state("domcontentloaded")

    if "/setup/settings" in page.url:
        retention = _get_setup_value("HASHVIEW_E2E_SETUP_RETENTION_PERIOD", "30")
        max_tasks = _get_setup_value("HASHVIEW_E2E_SETUP_MAX_RUNTIME_TASKS", "0")
        max_jobs = _get_setup_value("HASHVIEW_E2E_SETUP_MAX_RUNTIME_JOBS", "0")

        page.get_by_label("Retention Period").fill(retention)
        page.get_by_label("Max Runtime Tasks").fill(max_tasks)
        page.get_by_label("Max Runtime Jobs").fill(max_jobs)
        page.get_by_role("button", name="Save").click()
        page.wait_for_load_state("domcontentloaded")

    page.goto(f"{live_server}/login", wait_until="domcontentloaded")
    if "/setup/" in page.url:
        pytest.skip(
            "Live host is in setup flow; complete setup before running e2e tests."
        )

    _SETUP_COMPLETED = True


@pytest.fixture(scope="session")
def test_user_credentials():
    email = os.getenv("HASHVIEW_E2E_EMAIL", TEST_USER_EMAIL)
    password = os.getenv("HASHVIEW_E2E_PASSWORD", TEST_USER_PASSWORD)
    return {"email": email, "password": password}


@pytest.fixture()
def login(page, live_server, test_user_credentials):
    def _login():
        page.goto(f"{live_server}/login", wait_until="domcontentloaded")
        # The first-run setup flow auto-logs-in the admin, and GET /login
        # redirects an already-authenticated user straight to the dashboard, so
        # there may be no form to fill. Detect that and short-circuit.
        if page.get_by_role("link", name="Jobs").is_visible():
            return page
        # Target the login form's fields by id (not get_by_label("Email"), which
        # also matches the hidden "Email address" field in the account-settings
        # panel that the layout renders on authenticated pages).
        page.locator("#email").fill(test_user_credentials["email"])
        page.locator("#password").fill(test_user_credentials["password"])
        page.get_by_role("button", name="Crack the planet!").click()
        if not page.get_by_role("link", name="Jobs").is_visible():
            pytest.skip(
                "Login failed against external server; set HASHVIEW_E2E_EMAIL/PASSWORD."
            )
        return page

    return _login


@pytest.fixture(autouse=True)
def configure_page(page):
    page.set_default_timeout(5000)
    page.set_default_navigation_timeout(10000)
    return page
