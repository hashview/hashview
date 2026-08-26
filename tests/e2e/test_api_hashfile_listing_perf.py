"""Performance e2e tests for the /v1 hashfile listing routes.

Companion to ``test_job_creation_perf.py``, which covers the job wizard. Both
run against the volume fixture from ``tests/seed_perf_db.py`` and both skip when
it is absent, so an unseeded stack reports "skipped" rather than a bogus pass.

These are API tests, so they use a Playwright request context authenticated with
the ``uuid`` cookie rather than a browser session -- there is no page to render
and no login to perform.

**Why the assertion is a ratio, not a millisecond budget.** Both listing routes
compute cracked/total counts per hashfile, and the defect is that they do it one
hashfile at a time. Measured against the default fixture (31 hashfiles of
``hash_type`` 1000 holding 110k hashes, MySQL 8 in Docker on an M3 Max):

    GET /v1/hashfiles/hash_type/1000    1001 ms   3 queries per hashfile
    GET /v1/hashfiles/hash_type/22000    288 ms   <- no matching hashfiles
    GET /v1/customers/1/hashfiles        487 ms   1 query per hashfile

The second row is the floor: a request to the *same route* for a hash type no
hashfile has. It pays the whole authenticated request pipeline and the route's
own initial query, and never enters the per-hashfile loop -- and it measures the
same as ``/v1/customers`` (287 ms), which confirms it is fixed overhead.
Subtracting it isolates the loop.

An absolute budget would be wrong here, because replacing the loop with one
grouped query does *not* make the route free -- the grouped query still walks
every ``hashfile_hashes`` row of that type. Patching in the ``GROUP BY`` and
re-measuring on the same stack gave 553 ms, i.e. 1.8x, not 100x. So the two
regimes are only 1.8x apart in absolute terms, which is too narrow to pin on
hardware that is not this hardware. Above the floor, though, they separate
cleanly and the ratio is hardware-normalised, since both terms move together:

                  loop cost / floor      per-hashfile loop cost
    N+1 (today)     2.04x - 2.65x           23 - 29 ms
    GROUP BY        0.92x - 1.00x            9 - 11 ms

Those are the spreads actually observed over several runs, not one sample --
the machine was not otherwise idle, which is the honest condition to calibrate
under. ``MAX_LOOP_COST_RATIO = 1.5`` sits between them: today's code exceeds it
by 1.4x at worst, and the grouped version clears it by 1.5x at worst. Both
margins are real but neither is enormous, so
``HASHVIEW_PERF_MAX_LOOP_COST_RATIO`` exists for hardware where they are not.

This was verified in both directions rather than assumed: patching the
``GROUP BY`` into a running stack turned the xfail below into an XPASS, which
under ``strict=True`` fails the suite. That is the signal to delete the marker,
and it has been confirmed to fire.

Note the ratio understates production. On a real instance with 7.85M hashes of
one type the same endpoint takes 549 s, far worse than scaling this fixture
linearly by row count predicts -- so treat these numbers as a floor on the
defect's cost, not an estimate of it.
"""

import json
import os
import statistics
import time

import pytest

# The hash type the perf seeder writes everything as. Not a free choice: the
# fixture has no hashes of any other type, so this is the only type whose
# listing exercises the loop.
SEEDED_HASH_TYPE = 1000

# A hash type the fixture deliberately has no hashes of, used as the floor.
# WPA-PBKDF2-PMKID+EAPOL; the seeder only ever writes SEEDED_HASH_TYPE.
UNUSED_HASH_TYPE = 22000

# Below this the perf fixture was never seeded, so the numbers would measure an
# empty database and prove nothing. Matches MIN_HASHFILES in the job-wizard
# suite; the seeder's default is 30 plus one big file.
MIN_HASHFILES = 10

# Ceiling on (loop cost / floor cost). See the module docstring for how this is
# derived and why it is a ratio. Override for slower or faster hardware with
# HASHVIEW_PERF_MAX_LOOP_COST_RATIO.
MAX_LOOP_COST_RATIO = 1.5

# The customer-scoped route's own ceiling, deliberately looser. It is a
# regression guard on a route that passes today, not a pin on a defect, and it
# measured 0.63x-1.10x across runs -- the spread is real, because under load the
# floor and the loop do not scale together perfectly. 2.5 keeps that spread
# clear of the ceiling while still catching a regression to the by-hash-type
# route's three-queries-per-hashfile shape, which measures 2.59x.
MAX_CUSTOMER_LOOP_COST_RATIO = 2.5

REPEATS = 5


def max_loop_cost_ratio() -> float:
    override = os.getenv("HASHVIEW_PERF_MAX_LOOP_COST_RATIO")
    return float(override) if override else MAX_LOOP_COST_RATIO


def max_customer_loop_cost_ratio() -> float:
    override = os.getenv("HASHVIEW_PERF_MAX_CUSTOMER_LOOP_COST_RATIO")
    return float(override) if override else MAX_CUSTOMER_LOOP_COST_RATIO


def time_get(api, path: str, repeats: int = REPEATS):
    """GET ``path`` ``repeats`` + 1 times; return (median_ms, samples, body).

    The first call is discarded as a warmup: a cold SQLAlchemy pool and a cold
    InnoDB buffer pool make it consistently the slowest sample and it is not
    what any subsequent caller experiences.
    """
    samples = []
    body = None
    for _ in range(repeats + 1):
        start = time.perf_counter()
        response = api.get(path)
        body = response.body()
        samples.append((time.perf_counter() - start) * 1000)
        assert response.ok, f"GET {path} returned {response.status}"
    return statistics.median(samples[1:]), samples[1:], body


def report(label: str, median_ms: float, samples, extra: str = ""):
    spread = "/".join(f"{s:.0f}" for s in samples)
    print(f"[perf] {label:<34} median={median_ms:8.1f}ms samples=[{spread}] {extra}")


@pytest.fixture(scope="module")
def api(playwright, live_server):
    """A request context authenticated as the admin via the ``uuid`` cookie."""
    api_key = os.getenv("HASHVIEW_E2E_API_KEY")
    if not api_key:
        pytest.skip("Set HASHVIEW_E2E_API_KEY to run the API perf tests.")
    context = playwright.request.new_context(
        base_url=live_server, extra_http_headers={"Cookie": f"uuid={api_key}"}
    )
    yield context
    context.dispose()


@pytest.fixture(scope="module")
def seeded_hashfiles(api):
    """Number of hashfiles the fixture seeded at ``SEEDED_HASH_TYPE``, or skip.

    Counted off the route under test, which is the only unpaginated view of it
    available to the e2e suite -- it has no database access, and the HTML list
    pages paginate at 20 rows.
    """
    response = api.get(f"/v1/hashfiles/hash_type/{SEEDED_HASH_TYPE}")
    assert response.ok, f"listing returned {response.status}"
    hashfiles = json.loads(response.body()).get("hashfiles", [])
    if len(hashfiles) < MIN_HASHFILES:
        pytest.skip(
            f"Perf fixture not seeded (saw {len(hashfiles)} hashfiles of type "
            f"{SEEDED_HASH_TYPE}, need {MIN_HASHFILES}). Run "
            "tests/seed_perf_db.py inside the app container first."
        )
    return len(hashfiles)


@pytest.mark.perf
def test_empty_hash_type_listing_is_fast(api, seeded_hashfiles):
    """The floor measurement must itself be cheap, or the ratio means nothing.

    A hash type with no hashfiles never enters the per-hashfile loop, so this is
    request overhead plus the route's initial query. If this is ever slow, the
    problem is upstream of anything the loop does and the ratio test below would
    be comparing two large numbers.
    """
    median, samples, body = time_get(api, f"/v1/hashfiles/hash_type/{UNUSED_HASH_TYPE}")
    report(f"floor: hash_type/{UNUSED_HASH_TYPE}", median, samples)
    assert json.loads(body).get("hashfiles") == [], (
        f"hash_type {UNUSED_HASH_TYPE} was expected to have no hashfiles; the "
        "perf seeder writes only type "
        f"{SEEDED_HASH_TYPE}, so this is no longer a valid floor."
    )
    floor_budget = int(os.getenv("HASHVIEW_PERF_BUDGET_LISTING_FLOOR", "2000"))
    assert median <= floor_budget, (
        f"An empty hash-type listing took {median:.0f}ms (budget "
        f"{floor_budget}ms). That is per-request overhead, not listing work."
    )


@pytest.mark.perf
@pytest.mark.xfail(
    strict=True,
    reason="Issue #228: /v1/hashfiles/hash_type/<t> resolves each matching "
    "hashfile with its own ORM get plus two count queries, so the work above "
    "the fixed request cost grows with the number of matching hashfiles "
    "instead of being one grouped query.",
)
def test_hash_type_listing_loop_cost_is_bounded(api, seeded_hashfiles):
    """Isolate the per-hashfile loop from fixed request overhead.

    Both measurements hit the same route with the same auth, so everything
    except the loop cancels: one hash type has every seeded hashfile, the other
    has none.
    """
    floor_ms, _, _ = time_get(api, f"/v1/hashfiles/hash_type/{UNUSED_HASH_TYPE}")
    median, samples, body = time_get(api, f"/v1/hashfiles/hash_type/{SEEDED_HASH_TYPE}")

    loop_ms = median - floor_ms
    ratio = loop_ms / floor_ms if floor_ms else float("inf")
    per_hashfile = loop_ms / seeded_hashfiles
    report(
        f"hash_type/{SEEDED_HASH_TYPE}",
        median,
        samples,
        extra=(
            f"floor={floor_ms:.0f}ms loop={loop_ms:.0f}ms ratio={ratio:.2f}x "
            f"({per_hashfile:.1f}ms/hashfile over {seeded_hashfiles}, "
            f"body={len(body) // 1024}KB)"
        ),
    )

    assert ratio <= max_loop_cost_ratio(), (
        f"Listing {seeded_hashfiles} hashfiles of type {SEEDED_HASH_TYPE} cost "
        f"{loop_ms:.0f}ms above the {floor_ms:.0f}ms floor ({ratio:.2f}x, "
        f"{per_hashfile:.1f}ms per hashfile) to return "
        f"{len(body) // 1024}KB. Suspect one query per hashfile rather than a "
        "single grouped aggregate."
    )


@pytest.mark.perf
def test_customer_hashfile_listing_loop_cost_is_bounded(api, seeded_hashfiles):
    """A regression guard, deliberately NOT an xfail -- this route passes today.

    ``/v1/customers/<id>/hashfiles`` also loops over hashfiles, so it is the
    same shape of defect as the route above and was written the same way. It is
    not marked ``xfail`` because at fixture volume it measures 0.68x, i.e. under
    the ceiling, and the reason is worth writing down: it runs **one** combined
    ``count``/``sum``/``min`` aggregate per hashfile, where the by-hash-type
    route runs an ORM ``Hashfiles.query.get()`` plus **two** separate counts.
    One query per hashfile instead of three puts it at ~6ms per hashfile,
    close enough to a single grouped query (~9ms) that there is nothing to pin.

    It is still O(hashfiles) round trips, so a customer with several hundred
    files would show it. That makes this a guard rather than a marker: it fails
    if someone makes the loop heavier, and it does not claim a defect the
    numbers do not support.

    The floor is borrowed from the by-hash-type route: same blueprint, same
    auth, same "no rows to loop over" shape, which is what makes it a
    fixed-cost baseline rather than a comparison between endpoints.
    """
    customer_id = os.getenv("HASHVIEW_E2E_CUSTOMER_ID")
    if not customer_id:
        pytest.skip("Set HASHVIEW_E2E_CUSTOMER_ID to run this test.")

    floor_ms, _, _ = time_get(api, f"/v1/hashfiles/hash_type/{UNUSED_HASH_TYPE}")
    median, samples, body = time_get(api, f"/v1/customers/{customer_id}/hashfiles")

    hashfiles = json.loads(body).get("hashfiles", [])
    loop_ms = median - floor_ms
    ratio = loop_ms / floor_ms if floor_ms else float("inf")
    report(
        f"customers/{customer_id}/hashfiles",
        median,
        samples,
        extra=(
            f"floor={floor_ms:.0f}ms loop={loop_ms:.0f}ms ratio={ratio:.2f}x "
            f"over {len(hashfiles)} hashfiles"
        ),
    )

    assert ratio <= max_customer_loop_cost_ratio(), (
        f"Listing customer {customer_id}'s {len(hashfiles)} hashfiles cost "
        f"{loop_ms:.0f}ms above the {floor_ms:.0f}ms floor ({ratio:.2f}x, "
        f"ceiling {max_customer_loop_cost_ratio()}x). This route runs one "
        "combined aggregate per hashfile; anything heavier than that, or an "
        "extra query added to the loop, shows up here."
    )
