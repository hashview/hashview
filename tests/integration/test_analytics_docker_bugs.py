"""Bug-hunting tests for /analytics against the local docker stack.

These run over real HTTP against a running ``docker compose up`` stack and seed
their fixture data straight into the MySQL container, because the bugs they
target only show up with a real (many-to-many) dataset: a hash that lives in two
hashfiles, ``$HEX[...]`` plaintexts, domain-qualified usernames, and the card /
download-endpoint pairs that are supposed to agree with each other.

Opt-in: they only run when ``HASHVIEW_DOCKER_BASE_URL`` is set, so a plain
``pytest tests/`` on a dev box never writes to a live database.

    HASHVIEW_DOCKER_BASE_URL=http://127.0.0.1:5000 \
    HASHVIEW_DOCKER_DB_PORT=3307 \
    .venv/bin/python -m pytest tests/integration/test_analytics_docker_bugs.py -v

Each test asserts what the page *should* say, so a failure is a bug in the app
rather than in the test. The five that currently fail carry a strict xfail
naming the issue they document (#385-#389); when a fix lands, the strict marker
turns the XPASS into a failure so the marker gets removed with it.
"""
import os
import re
import zipfile
from datetime import UTC, datetime, timedelta
from io import BytesIO

import pytest

pytestmark = pytest.mark.docker_analytics

requests = pytest.importorskip("requests")
mysql_connector = pytest.importorskip("mysql.connector")
bcrypt = pytest.importorskip("bcrypt")

BASE_URL = (os.getenv("HASHVIEW_DOCKER_BASE_URL") or "").rstrip("/")
DB_CONFIG = {
    "host": os.getenv("HASHVIEW_DOCKER_DB_HOST", "127.0.0.1"),
    "port": int(os.getenv("HASHVIEW_DOCKER_DB_PORT", "3307")),
    "user": os.getenv("HASHVIEW_DOCKER_DB_USER", "hashview"),
    "password": os.getenv("HASHVIEW_DOCKER_DB_PASSWORD", "hashview"),
    "database": os.getenv("HASHVIEW_DOCKER_DB_NAME", "hashview"),
}

# Everything this module creates is named with this prefix so teardown can
# delete exactly its own rows and nothing else in the developer's database.
TAG = "zz-analytics-bugtest"
LOGIN_EMAIL = "zz-analytics-bugtest@example.com"
LOGIN_PASSWORD = "bugtest-password-123"

# The seeded corpus (customer A). ``accounts`` is a list of (hashfile, username)
# pairs -- more than one pair means the same hash is reachable through more than
# one account row, which is exactly the shape that trips the counting bugs.
#   alice  : one account, same hash in BOTH hashfiles (dup join rows)
#   bob    : different hash, same plaintext as alice (shared password)
#   carol/dave : share a hash whose plaintext is $HEX-encoded
#   eve    : username == password, exact case
#   frank  : username == password, differing case
#   greg   : one account in both hashfiles, hash NOT cracked
#   hank/ivan  : share a hash with a blank plaintext
#   xss    : hostile plaintext + username
CORPUS = [
    ("h_alice", 1, "ExampleFixturePass1!", [("a", "CORP\\alice"), ("b", "CORP\\alice")]),
    ("h_bob", 1, "ExampleFixturePass1!", [("a", "CORP\\bob")]),
    ("h_hex", 1, "$HEX[686578706c61696e31]", [("a", "CORP\\carol"), ("a", "CORP\\dave")]),
    ("h_eve", 1, "eve", [("a", "CORP\\eve")]),
    ("h_frank", 1, "frank", [("a", "CORP\\Frank")]),
    ("h_greg", 0, None, [("a", "CORP\\greg"), ("b", "CORP\\greg")]),
    ("h_blank", 1, "", [("a", "CORP\\hank"), ("a", "CORP\\ivan")]),
    ("h_xss", 1, "<script>alert(1)</script>", [("a", '<img src=x onerror=alert(2)>')]),
]

# Distinct (hash, account) pairs whose hash is cracked. alice's hash reaching
# two hashfiles is still ONE account with ONE recovered password.
EXPECTED_CRACKED_ACCOUNTS = 9

# Shared-password groups the card should report: ExampleFixturePass1! (alice+bob),
# hexplain1 (carol+dave), blank (hank+ivan). greg's shared *hash* is uncracked and
# belongs to a single account, so it is not a shared password.
EXPECTED_SHARED_GROUPS = 3
EXPECTED_SHARED_USERS = {"alice", "bob", "carol", "dave", "hank", "ivan"}

# Accounts whose password equals their username: eve (exact) and Frank (case
# differs -- still the same credential to an attacker).
EXPECTED_USER_EQ_PASS = {"eve", "Frank"}

# Customer B exists only to exercise the shared-card render cap.
BULK_GROUPS = 105
PREVIEW_LIMIT = 100


def _local(username):
    """DOMAIN\\user -> user, matching the page's own display normalisation."""
    return username.split("\\")[-1] if "\\" in username else username


def _connect():
    return mysql_connector.connect(**DB_CONFIG)


@pytest.fixture(scope="module")
def stack_url():
    if not BASE_URL:
        pytest.skip("Set HASHVIEW_DOCKER_BASE_URL to run the docker analytics tests.")
    try:
        requests.get(f"{BASE_URL}/login", timeout=5)
    except requests.RequestException as exc:
        pytest.skip(f"Docker stack not reachable at {BASE_URL}: {exc}")
    return BASE_URL


@pytest.fixture(scope="module")
def seeded(stack_url):
    """Create the fixture corpus, yield its ids, then delete every seeded row."""
    conn = _connect()
    conn.autocommit = False
    cur = conn.cursor()
    ids = {"hash_ids": [], "hashfile_ids": []}
    try:
        pw_hash = bcrypt.hashpw(LOGIN_PASSWORD.encode(), bcrypt.gensalt()).decode()
        cur.execute("DELETE FROM users WHERE email_address = %s", (LOGIN_EMAIL,))
        cur.execute(
            "INSERT INTO users (first_name, last_name, email_address, password, admin,"
            " auth_source, theme) VALUES (%s, %s, %s, %s, 1, 'local', 'auto')",
            ("Bug", "Test", LOGIN_EMAIL, pw_hash),
        )
        ids["user_id"] = cur.lastrowid

        cur.execute("INSERT INTO customers (name) VALUES (%s)", (TAG + "-a",))
        ids["customer_a"] = cur.lastrowid
        cur.execute("INSERT INTO customers (name) VALUES (%s)", (TAG + "-b",))
        ids["customer_b"] = cur.lastrowid

        uploaded = datetime.now(UTC) - timedelta(hours=2)
        hashfiles = {}
        for key, customer in (("a", "customer_a"), ("b", "customer_a"), ("bulk", "customer_b")):
            cur.execute(
                "INSERT INTO hashfiles (name, uploaded_at, runtime, customer_id, owner_id,"
                " hex_salt) VALUES (%s, %s, 60, %s, %s, 0)",
                (f"{TAG}-{key}", uploaded, ids[customer], ids["user_id"]),
            )
            hashfiles[key] = cur.lastrowid
            ids["hashfile_ids"].append(cur.lastrowid)
        ids["hashfiles"] = hashfiles

        cur.execute(
            "INSERT INTO tasks (name, hc_attackmode, owner_id, loopback)"
            " VALUES (%s, 0, %s, 0)",
            (TAG + "-task", ids["user_id"]),
        )
        ids["task_id"] = cur.lastrowid

        recovered = datetime.now(UTC) - timedelta(hours=1)
        for stub, cracked, plaintext, accounts in CORPUS:
            cur.execute(
                "INSERT INTO hashes (sub_ciphertext, ciphertext, cracked, plaintext,"
                " hash_type, recovered_at, task_id, recovered_by)"
                " VALUES (%s, %s, %s, %s, 1000, %s, %s, %s)",
                (
                    f"{stub}"[:32],
                    f"{TAG}:{stub}:ciphertext",
                    cracked,
                    plaintext,
                    recovered if cracked else None,
                    ids["task_id"] if cracked else None,
                    ids["user_id"] if cracked else None,
                ),
            )
            hash_id = cur.lastrowid
            ids["hash_ids"].append(hash_id)
            for hashfile_key, username in accounts:
                cur.execute(
                    "INSERT INTO hashfile_hashes (hash_id, username, hashfile_id)"
                    " VALUES (%s, %s, %s)",
                    (hash_id, username, hashfiles[hashfile_key]),
                )

        # Customer B: BULK_GROUPS shared-password groups of two accounts each.
        for index in range(BULK_GROUPS):
            cur.execute(
                "INSERT INTO hashes (sub_ciphertext, ciphertext, cracked, plaintext,"
                " hash_type, recovered_at, task_id, recovered_by)"
                " VALUES (%s, %s, 1, %s, 1000, %s, %s, %s)",
                (
                    f"bulk{index}"[:32],
                    f"{TAG}:bulk{index}:ciphertext",
                    f"ExampleFixtureBulk{index}!",
                    recovered,
                    ids["task_id"],
                    ids["user_id"],
                ),
            )
            hash_id = cur.lastrowid
            ids["hash_ids"].append(hash_id)
            for suffix in ("x", "y"):
                cur.execute(
                    "INSERT INTO hashfile_hashes (hash_id, username, hashfile_id)"
                    " VALUES (%s, %s, %s)",
                    (hash_id, f"BULK\\user{index}{suffix}", hashfiles["bulk"]),
                )
        conn.commit()
    except Exception:
        conn.rollback()
        cur.close()
        conn.close()
        raise

    yield ids

    try:
        if ids["hash_ids"]:
            placeholders = ",".join(["%s"] * len(ids["hash_ids"]))
            cur.execute(
                f"DELETE FROM hashfile_hashes WHERE hash_id IN ({placeholders})",
                ids["hash_ids"],
            )
            cur.execute(f"DELETE FROM hashes WHERE id IN ({placeholders})", ids["hash_ids"])
        if ids["hashfile_ids"]:
            placeholders = ",".join(["%s"] * len(ids["hashfile_ids"]))
            cur.execute(f"DELETE FROM hashfiles WHERE id IN ({placeholders})", ids["hashfile_ids"])
        cur.execute("DELETE FROM tasks WHERE id = %s", (ids["task_id"],))
        cur.execute(
            "DELETE FROM customers WHERE id IN (%s, %s)",
            (ids["customer_a"], ids["customer_b"]),
        )
        cur.execute("DELETE FROM users WHERE id = %s", (ids["user_id"],))
        conn.commit()
    finally:
        cur.close()
        conn.close()


@pytest.fixture(scope="module")
def client(stack_url, seeded):
    """A logged-in HTTP session for the seeded test user."""
    session = requests.Session()
    login_page = session.get(f"{stack_url}/login", timeout=10)
    token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', login_page.text)
    payload = {"email": LOGIN_EMAIL, "password": LOGIN_PASSWORD, "submit": "Crack the planet!"}
    if token:
        payload["csrf_token"] = token.group(1)
    response = session.post(f"{stack_url}/login", data=payload, timeout=10)
    assert "/login" not in response.url, "login failed for the seeded test user"
    return session


def _analytics(client, stack_url, **params):
    response = client.get(f"{stack_url}/analytics", params=params, timeout=60)
    assert response.status_code == 200, f"/analytics returned {response.status_code}"
    return response.text


def _scope_a(seeded):
    return {"customer_id": seeded["customer_a"]}


def _number(pattern, html, what):
    match = re.search(pattern, html)
    assert match, f"could not find {what} in the analytics page"
    return int(match.group(1).replace(",", ""))


# ---------------------------------------------------------------------------
# Counting: a hash reachable through two hashfiles is still one account.
# ---------------------------------------------------------------------------


@pytest.mark.xfail(strict=True, reason=(
    "BUG (issue #385): the /analytics corpus counts hashfile_hashes join rows, so an "
    "account whose hash belongs to two hashfiles is counted twice in total_cracked and "
    "in every plaintext-derived chart. Remove this marker once the corpus is per-hash."))
def test_cracked_total_counts_each_account_once(client, stack_url, seeded):
    """The 'of N cracked' corpus size must not double-count an account whose
    hash appears in two hashfiles."""
    html = _analytics(client, stack_url, **_scope_a(seeded))
    total = _number(r">of ([\d,]+) cracked<", html, "the cracked corpus total")
    assert total == EXPECTED_CRACKED_ACCOUNTS


def test_shared_password_card_counts_distinct_accounts(client, stack_url, seeded):
    """Shared-password groups are per distinct account, not per join row."""
    html = _analytics(client, stack_url, **_scope_a(seeded))
    groups = _number(r">(\d+) groups<", html, "the shared-password group count")
    assert groups == EXPECTED_SHARED_GROUPS


def test_username_equals_password_card_counts_distinct_accounts(client, stack_url, seeded):
    """The username=password card counts eve and Frank once each."""
    html = _analytics(client, stack_url, **_scope_a(seeded))
    accounts = _number(r">(\d+) accounts<", html, "the username=password count")
    assert accounts == len(EXPECTED_USER_EQ_PASS)


# ---------------------------------------------------------------------------
# Card / download parity: every download must serve what its card describes.
# ---------------------------------------------------------------------------


@pytest.mark.xfail(strict=True, reason=(
    "BUG (issue #386): the card decodes $HEX[...] before rendering the download form, but "
    "analytics_download_shared matches the posted plaintext against the still-encoded "
    "stored value, so the file is empty. Remove this marker once both sides decode."))
def test_shared_download_finds_the_plaintext_the_card_displays(client, stack_url, seeded):
    """The card decodes $HEX[...] before displaying a group, so the download
    button next to it must resolve that same decoded plaintext."""
    response = client.post(
        f"{stack_url}/analytics/download/shared",
        data={"plaintext": "hexplain1", "customer_id": seeded["customer_a"]},
        timeout=30,
    )
    assert response.status_code == 200
    served = {_local(line.strip()) for line in response.text.splitlines()[2:] if line.strip()}
    assert served == {"carol", "dave"}


def test_blank_password_download_returns_its_group(client, stack_url, seeded):
    """The 'Blank (unset)' group's download button posts an empty plaintext and
    must still return the accounts sharing it."""
    response = client.post(
        f"{stack_url}/analytics/download/shared",
        data={"plaintext": "", "customer_id": seeded["customer_a"]},
        timeout=30,
    )
    assert response.status_code == 200
    served = {_local(line.strip()) for line in response.text.splitlines()[2:] if line.strip()}
    assert served == {"hank", "ivan"}


def test_shared_zip_contains_one_file_per_group_on_the_card(client, stack_url, seeded):
    """The zip is the 'download them all' escape hatch for the capped card, so
    it must hold exactly the groups the card counted."""
    response = client.get(
        f"{stack_url}/analytics/download/shared_zip",
        params=_scope_a(seeded),
        timeout=60,
    )
    assert response.status_code == 200
    with zipfile.ZipFile(BytesIO(response.content)) as archive:
        names = archive.namelist()
    assert len(names) == EXPECTED_SHARED_GROUPS


@pytest.mark.xfail(strict=True, reason=(
    "BUG (issue #387): fig9 groups hashfile_hashes rows by hash_id with COUNT(*) > 1 and no "
    "cracked filter, so it invents accounts that only share a hash across hashfiles and drops "
    "accounts that share a password under different hashes. Remove this marker once fig9 "
    "serves _shared_groups()."))
def test_fig9_download_lists_the_accounts_that_share_a_password(client, stack_url, seeded):
    """The shared-accounts download must agree with the shared-password card:
    same accounts, no uncracked/one-account-in-two-files false positives."""
    response = client.get(
        f"{stack_url}/analytics/download/fig9", params=_scope_a(seeded), timeout=60
    )
    assert response.status_code == 200
    served = {_local(line.strip()) for line in response.text.splitlines() if line.strip()}
    assert served == EXPECTED_SHARED_USERS


@pytest.mark.xfail(strict=True, reason=(
    "BUG (issue #388): the username=password card compares case-insensitively while the fig8 "
    "download compares exactly, so the card counts accounts the file omits. Remove this marker "
    "once fig8 reuses _local_part() and the card's comparison."))
def test_fig8_download_matches_the_username_equals_password_card(client, stack_url, seeded):
    """The username=password download must contain every account the card counts,
    including the case-differing one."""
    response = client.get(
        f"{stack_url}/analytics/download/fig8", params=_scope_a(seeded), timeout=60
    )
    assert response.status_code == 200
    served = {line.strip() for line in response.text.splitlines() if line.strip()}
    assert served == EXPECTED_USER_EQ_PASS


# ---------------------------------------------------------------------------
# Input handling and rendering.
# ---------------------------------------------------------------------------


@pytest.mark.xfail(strict=True, reason=(
    "BUG (issue #389): /analytics/download builds redirect('/analytics') for an unknown ?type "
    "and never returns it, so the request scans every hash and serves an empty attachment. "
    "Remove this marker once the redirect (or abort) is returned before the queries."))
def test_unknown_download_type_does_not_serve_a_file(client, stack_url, seeded):
    """?type=bogus is not 'found' or 'left'; the route must bail out rather than
    fall through and serve an empty attachment."""
    response = client.get(
        f"{stack_url}/analytics/download",
        params={"type": "bogus", "customer_id": seeded["customer_a"]},
        allow_redirects=False,
        timeout=30,
    )
    assert "attachment" not in response.headers.get("Content-Disposition", ""), (
        "an unknown download type still produced a file download"
    )


def test_non_numeric_scope_ids_are_rejected_not_crashed(client, stack_url):
    """The download routes 400 on a non-numeric id; the page itself must not
    500 on the same input."""
    response = client.get(
        f"{stack_url}/analytics", params={"customer_id": "abc"}, timeout=60
    )
    assert response.status_code < 500, "non-numeric customer_id crashed /analytics"


def test_hostile_plaintext_and_username_are_escaped(client, stack_url, seeded):
    """Recovered plaintexts and usernames are attacker-controlled data."""
    html = _analytics(client, stack_url, **_scope_a(seeded))
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x onerror=alert(2)>" not in html


def test_shared_card_caps_rendered_rows_but_reports_the_true_total(client, stack_url, seeded):
    """Regression for the 50MB analytics response: the card renders at most
    PREVIEW_LIMIT rows while still reporting every group."""
    html = _analytics(client, stack_url, customer_id=seeded["customer_b"])
    groups = _number(r">(\d+) groups<", html, "the shared-password group count")
    assert groups == BULK_GROUPS
    rendered = len(re.findall(r'name="plaintext"', html))
    assert rendered <= PREVIEW_LIMIT, f"card rendered {rendered} shared rows"
    assert len(html) < 5_000_000, f"analytics response is {len(html)} bytes"
