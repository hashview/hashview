"""Performance e2e tests for the job-creation wizard.

These are latency and payload regression guards, not correctness tests — the
functional walk of the wizard lives in ``test_job_creation.py``.

They only mean something against a database with volume in it. Run
``tests/seed_perf_db.py`` inside the app container first (see TESTING.md); the
``perf_fixture`` fixture skips the whole module when that data is absent, so an
empty dev stack reports "skipped", never a bogus pass.

Marked ``perf``, not ``e2e``, so ``pytest -m e2e`` does not collect them. CI runs
the e2e suite under ``HASHVIEW_E2E_STRICT`` with a cap on skipped results, and
these would skip there (CI never seeds the perf fixture) and trip that cap. Run
them with ``pytest -m perf``.

Two kinds of assertion here, because they fail for different reasons:

* **Latency budgets** — wall-clock against localhost Docker, deliberately loose.
  They catch an order-of-magnitude regression, not a 50ms drift. Override any of
  them with the matching ``HASHVIEW_PERF_BUDGET_*`` env var on slower hardware.
* **Payload budgets** — response body size. These are machine-independent and so
  are the stronger guard: a page whose HTML grows with a whole table rather than
  with a page of results will blow a size budget identically on every host.

The payload tests carry strict ``xfail`` markers against **issue #422**: they
document scaling defects that exist today, and will fail loudly (XPASS) the
moment one is fixed, which is the signal to drop that marker. The numbering in
each ``reason`` matches the numbered sections of that issue.
"""
import os
import re
import statistics
import time

import pytest
from playwright.sync_api import expect

# Row counts below these mean the perf fixture was never seeded, so the numbers
# would measure an empty database and prove nothing.
MIN_TASKS = 100
MIN_HASHFILES = 10

# Default budgets in milliseconds. Each is the median of REPEATS samples.
DEFAULT_BUDGETS = {
    "jobs_add": 1000,
    "hashfile_picker": 2000,
    # Deliberately loose: this endpoint already measures ~2.9s at the default
    # fixture volume. The defect is pinned precisely by the payload test below,
    # so a tight latency budget here would only add flake.
    "cracked_hashes": 6000,
    "task_library": 2000,
    "assign_task": 3000,
    "summary": 2000,
}

# Median of several samples, so one unlucky GC pause or cold page cache doesn't
# fail the run. The first sample is discarded as a warmup.
REPEATS = 5


def budget(name: str) -> int:
    """Budget in ms for ``name``, overridable via HASHVIEW_PERF_BUDGET_<NAME>."""
    override = os.getenv(f"HASHVIEW_PERF_BUDGET_{name.upper()}")
    if override:
        return int(override)
    return DEFAULT_BUDGETS[name]


def time_get(page, url: str, repeats: int = REPEATS):
    """GET ``url`` ``repeats`` times; return (median_ms, samples, last_response).

    Uses ``page.request`` rather than ``page.goto`` so the measurement is the
    server's response time, not the browser's render of it. The APIRequestContext
    shares the page's cookie jar, so the session survives.
    """
    samples = []
    response = None
    # repeats + 1: the first call is a warmup (cold SQLAlchemy pool, cold InnoDB
    # buffer pool) and is discarded.
    for _ in range(repeats + 1):
        start = time.perf_counter()
        response = page.request.get(url)
        body = response.body()
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert response.ok, f"GET {url} returned {response.status}"
        samples.append(elapsed_ms)
    samples = samples[1:]
    return statistics.median(samples), samples, (response, body)


def report(label: str, median_ms: float, samples, budget_ms: int, extra: str = ""):
    """Print a one-line result so `pytest -s` output is a readable timing table."""
    spread = "/".join(f"{s:.0f}" for s in samples)
    status = "OK " if median_ms <= budget_ms else "SLOW"
    print(
        f"[perf] {status} {label:<24} median={median_ms:7.1f}ms "
        f"budget={budget_ms:5d}ms samples=[{spread}] {extra}"
    )


@pytest.fixture(scope="module")
def perf_env():
    job_id = os.getenv("HASHVIEW_E2E_JOB_ID")
    customer_id = os.getenv("HASHVIEW_E2E_CUSTOMER_ID")
    if not job_id or not customer_id:
        pytest.skip("Set HASHVIEW_E2E_JOB_ID and HASHVIEW_E2E_CUSTOMER_ID.")
    return {"job_id": job_id, "customer_id": customer_id}


@pytest.fixture(scope="module")
def fixture_counts(playwright, perf_env):
    """Row counts for the seeded perf data, read via the /v1 API.

    The API is used rather than the HTML list pages because those paginate (20
    rows), which would undercount the fixture and skip the whole module. The
    e2e suite has no database access, so the API is the only unpaginated view.
    Authenticates with the api_key as the ``uuid`` cookie, in its own request
    context so the browser session is untouched.
    """
    base_url = os.getenv("HASHVIEW_E2E_BASE_URL", "").rstrip("/")
    api_key = os.getenv("HASHVIEW_E2E_API_KEY")
    if not api_key:
        pytest.skip("Set HASHVIEW_E2E_API_KEY to count the perf fixture.")

    api = playwright.request.new_context(
        base_url=base_url, extra_http_headers={"Cookie": f"uuid={api_key}"}
    )
    try:
        tasks = api.get("/v1/tasks")
        assert tasks.ok, f"GET /v1/tasks returned {tasks.status}"
        perf_tasks = len(re.findall(r"perf-task-\d+", tasks.text()))

        hashfiles = api.get(f"/v1/customers/{perf_env['customer_id']}/hashfiles")
        assert hashfiles.ok, f"customer hashfiles returned {hashfiles.status}"
        perf_hashfiles = len(re.findall(r"perf-hashfile-\d+", hashfiles.text()))
    finally:
        api.dispose()

    return {"perf_tasks": perf_tasks, "perf_hashfiles": perf_hashfiles}


@pytest.fixture()
def perf_fixture(page, live_server, login, perf_env, fixture_counts):
    """Log in and confirm the volume fixture is present, else skip."""
    login()
    perf_tasks = fixture_counts["perf_tasks"]
    perf_hashfiles = fixture_counts["perf_hashfiles"]

    if perf_tasks < MIN_TASKS or perf_hashfiles < MIN_HASHFILES:
        pytest.skip(
            "Perf fixture not seeded (saw "
            f"{perf_tasks} perf tasks, {perf_hashfiles} perf hashfiles). "
            "Run tests/seed_perf_db.py inside the app container first."
        )
    return {**perf_env, "perf_tasks": perf_tasks, "perf_hashfiles": perf_hashfiles}


@pytest.mark.perf
def test_jobs_add_step_is_fast(page, live_server, perf_fixture):
    """Step 1 of the wizard is a name + customer form; it should be near-free.

    This doubles as the floor for the other measurements: whatever this costs is
    the per-request overhead (nav counts, session, template base) that every
    other step also pays.
    """
    median, samples, _ = time_get(page, f"{live_server}/jobs/add")
    report("GET /jobs/add", median, samples, budget("jobs_add"))
    assert median <= budget("jobs_add"), (
        f"GET /jobs/add took {median:.0f}ms (budget {budget('jobs_add')}ms). "
        "Step 1 renders a two-field form; anything slow here is per-request "
        "overhead paid by every other wizard step too."
    )


@pytest.mark.perf
def test_hashfile_picker_does_not_scale_with_hashfile_count(
    page, live_server, perf_fixture
):
    """The 'Assign Hashes' step must not aggregate every hashfile on every load.

    The picker lists the customer's hashfiles with a cracked/total count each. If
    those counts are computed one query per hashfile, this page's cost is
    (hashfiles x hashes-per-hashfile) and it degrades as the customer accumulates
    files — which is exactly the growth pattern real engagements have.
    """
    job_id = perf_fixture["job_id"]
    url = f"{live_server}/jobs/{job_id}/assigned_hashfile/"
    median, samples, (_, body) = time_get(page, url)
    report(
        "GET assigned_hashfile/",
        median,
        samples,
        budget("hashfile_picker"),
        extra=f"hashfiles={perf_fixture['perf_hashfiles']} body={len(body) // 1024}KB",
    )
    assert median <= budget("hashfile_picker"), (
        f"Hashfile picker took {median:.0f}ms with "
        f"{perf_fixture['perf_hashfiles']} hashfiles "
        f"(budget {budget('hashfile_picker')}ms). Suspect a per-hashfile "
        "aggregate query rather than one grouped query."
    )


@pytest.mark.perf
def test_task_library_does_not_scale_with_task_table(page, live_server, perf_fixture):
    """The task-library step must not render the entire tasks table.

    The 'Add Task' drawer is collapsed on load, but the server pays for it
    regardless: if it emits one form per task in the whole table, both the
    response size and the render time grow with the task library rather than
    with the job. This is the page the wizard returns to after every single task
    the user adds, so the cost is paid repeatedly.
    """
    job_id = perf_fixture["job_id"]
    url = f"{live_server}/jobs/{job_id}/tasks"
    median, samples, (_, body) = time_get(page, url)
    kb = len(body) / 1024
    report(
        "GET jobs/<id>/tasks",
        median,
        samples,
        budget("task_library"),
        extra=f"tasks={perf_fixture['perf_tasks']} body={kb:.0f}KB",
    )
    assert median <= budget("task_library"), (
        f"Task library took {median:.0f}ms with {perf_fixture['perf_tasks']} "
        f"tasks (budget {budget('task_library')}ms). The page is re-rendered "
        "after every task the user adds, so this cost is paid N times per job."
    )


@pytest.mark.perf
def test_cracked_hashes_view_is_bounded(page, live_server, perf_fixture):
    """Viewing a hashfile's cracked hashes must not load the whole result set.

    Opened from the hashfile picker. With no pagination, a hashfile with tens of
    thousands of already-cracked hashes renders one table row per hash.
    """
    job_id = perf_fixture["job_id"]
    live = f"{live_server}/jobs/{job_id}/assigned_hashfile/"
    picker = page.request.get(live)
    assert picker.ok, f"GET {live} returned {picker.status}"

    # Find the big seeded hashfile's id from the picker markup so the test does
    # not hardcode an id the seeder happened to assign.
    match = re.search(
        r"name=['\"]hashfile_id['\"][^>]*value=['\"](\d+)['\"](?=(?:(?!<tr)[\s\S])*"
        r"perf-big-hashfile)",
        picker.text(),
    )
    if not match:
        pytest.skip("perf-big-hashfile not present in the picker; seed it first.")
    big_id = match.group(1)

    url = f"{live_server}/jobs/{job_id}/assigned_hashfile/{big_id}"
    median, samples, (_, body) = time_get(page, url, repeats=3)
    kb = len(body) / 1024
    report(
        "GET cracked hashes",
        median,
        samples,
        budget("cracked_hashes"),
        extra=f"hashfile={big_id} body={kb:.0f}KB",
    )
    assert median <= budget("cracked_hashes"), (
        f"Cracked-hash view took {median:.0f}ms and returned {kb:.0f}KB "
        f"(budget {budget('cracked_hashes')}ms). Suspect an unpaginated load of "
        "every cracked hash in the file."
    )


@pytest.mark.perf
def test_assigning_a_task_is_fast(page, live_server, login, perf_fixture):
    """Adding one task to a job should cost one insert, not a full re-render.

    Measures the whole user-visible action: the POST plus the redirect back to
    the task library. A user building a 10-task job pays this ten times, so a
    slow task library compounds here.
    """
    login()
    job_id = perf_fixture["job_id"]

    page.goto(f"{live_server}/jobs/{job_id}/tasks", wait_until="domcontentloaded")
    expect(page.get_by_role("heading", name="Task Library")).to_be_visible()

    # Pick a task that is not already in this job's queue. Assigning an
    # already-queued task is allowed (the queue can hold duplicates), but then
    # the post-assignment assertion below matches two cards and fails on strict
    # mode rather than on latency.
    queued_ids = set(
        page.locator("#task-queue .tq-item").evaluate_all(
            "els => els.map(e => e.dataset.taskId)"
        )
    )
    assignable = page.locator("form[action*='/assign_task/']").evaluate_all(
        "els => els.map(e => e.getAttribute('action'))"
    )
    task_id = None
    for action in assignable:
        candidate = action.rsplit("/", 1)[-1]
        if candidate.isdigit() and candidate not in queued_ids:
            task_id = candidate
            break
    if task_id is None:
        pytest.skip("No unassigned task available in the library.")

    assign_action = f"/jobs/{job_id}/assign_task/{task_id}"
    assign_form = page.locator(f"form[action='{assign_action}']")

    # The form lives in a collapsed <details>; open it before submitting.
    page.locator(f"details:has(form[action='{assign_action}'])").evaluate(
        "el => { el.open = true; }"
    )

    start = time.perf_counter()
    assign_form.locator("button[type=submit]").first.click()
    page.wait_for_load_state("domcontentloaded")
    elapsed_ms = (time.perf_counter() - start) * 1000

    report("POST assign_task", elapsed_ms, [elapsed_ms], budget("assign_task"))
    queued = page.locator(f"#task-queue .tq-item[data-task-id='{task_id}']")
    expect(queued).to_be_visible()
    assert elapsed_ms <= budget("assign_task"), (
        f"Assigning one task took {elapsed_ms:.0f}ms "
        f"(budget {budget('assign_task')}ms). The POST itself is one insert; the "
        "cost is the redirect re-rendering the whole task library."
    )


@pytest.mark.perf
def test_job_summary_is_fast(page, live_server, perf_fixture):
    """The final review step aggregates the hashfile and resolves task names."""
    job_id = perf_fixture["job_id"]
    url = f"{live_server}/jobs/{job_id}/summary"
    median, samples, (_, body) = time_get(page, url)
    report(
        "GET jobs/<id>/summary",
        median,
        samples,
        budget("summary"),
        extra=f"body={len(body) // 1024}KB",
    )
    assert median <= budget("summary"), (
        f"Job summary took {median:.0f}ms (budget {budget('summary')}ms)."
    )


# --------------------------------------------------------------------------
# Scaling tests.
#
# The latency tests above pass at the fixture's current volume — the wizard is
# not slow on a small install. What these pin is the *shape* of the cost curve:
# each of these endpoints does work proportional to a whole table rather than to
# what the page shows, so the latency budgets above only hold until a customer
# accumulates enough data. Payload size is used as the proxy because it is
# deterministic and identical on every machine, unlike wall-clock.
# --------------------------------------------------------------------------

# Response-size ceilings in KB. Each is set to roughly 2x what the page needs at
# the fixture's volume, so passing means "renders a page of results", not
# "renders the table".
PAYLOAD_BUDGET_KB = {
    "task_library": 400,
    "cracked_hashes": 2048,
    "summary": 300,
}

# Per-hashfile latency cost on the picker, above the per-request floor. One
# grouped aggregate query would make this ~0; a per-hashfile query makes it
# grow with the customer's file count.
MAX_MS_PER_HASHFILE = 1.0


@pytest.mark.perf
@pytest.mark.xfail(
    strict=True,
    reason="Issue #422 (3): task library renders one form + CSRF token per row "
    "of the whole tasks table, inside a drawer that is collapsed on load. "
    "Payload grows with the task library instead of with the job.",
)
def test_task_library_payload_does_not_scale_with_task_table(
    page, live_server, perf_fixture
):
    job_id = perf_fixture["job_id"]
    response = page.request.get(f"{live_server}/jobs/{job_id}/tasks")
    assert response.ok, f"GET tasks returned {response.status}"
    kb = len(response.body()) / 1024
    per_task = kb / max(perf_fixture["perf_tasks"], 1)
    print(
        f"[perf] payload task_library {kb:.0f}KB "
        f"({per_task:.2f}KB/task, {perf_fixture['perf_tasks']} tasks) "
        f"budget={PAYLOAD_BUDGET_KB['task_library']}KB"
    )
    assert kb <= PAYLOAD_BUDGET_KB["task_library"], (
        f"Task library returned {kb:.0f}KB for {perf_fixture['perf_tasks']} "
        f"tasks ({per_task:.2f}KB per task). This page is re-rendered after "
        "every task the user adds to a job."
    )


@pytest.mark.perf
@pytest.mark.xfail(
    strict=True,
    reason="Issue #422 (1): cracked-hash view loads and renders every cracked "
    "hash in the hashfile with no pagination.",
)
def test_cracked_hashes_payload_is_bounded(page, live_server, perf_fixture):
    job_id = perf_fixture["job_id"]
    picker = page.request.get(f"{live_server}/jobs/{job_id}/assigned_hashfile/")
    assert picker.ok, f"picker returned {picker.status}"
    match = re.search(
        r"name=['\"]hashfile_id['\"][^>]*value=['\"](\d+)['\"](?=(?:(?!<tr)[\s\S])*"
        r"perf-big-hashfile)",
        picker.text(),
    )
    if not match:
        pytest.skip("perf-big-hashfile not present in the picker; seed it first.")

    response = page.request.get(
        f"{live_server}/jobs/{job_id}/assigned_hashfile/{match.group(1)}"
    )
    assert response.ok, f"cracked view returned {response.status}"
    kb = len(response.body()) / 1024
    print(
        f"[perf] payload cracked_hashes {kb:.0f}KB "
        f"budget={PAYLOAD_BUDGET_KB['cracked_hashes']}KB"
    )
    assert kb <= PAYLOAD_BUDGET_KB["cracked_hashes"], (
        f"Cracked-hash view returned {kb:.0f}KB. It renders one table row per "
        "cracked hash with no pagination, so the payload is a function of how "
        "well the crack went."
    )


@pytest.mark.perf
@pytest.mark.xfail(
    strict=True,
    reason="Issue #422 (4): job summary resolves each assigned task's name "
    "with a nested template loop over the entire tasks table. Non-matching "
    "iterations still emit their indentation, so the payload is mostly "
    "whitespace and grows as assigned x total_tasks.",
)
def test_summary_payload_does_not_scale_with_task_table(
    page, live_server, perf_fixture
):
    job_id = perf_fixture["job_id"]
    response = page.request.get(f"{live_server}/jobs/{job_id}/summary")
    assert response.ok, f"summary returned {response.status}"
    kb = len(response.body()) / 1024
    print(
        f"[perf] payload summary {kb:.0f}KB "
        f"({perf_fixture['perf_tasks']} tasks) "
        f"budget={PAYLOAD_BUDGET_KB['summary']}KB"
    )
    assert kb <= PAYLOAD_BUDGET_KB["summary"], (
        f"Job summary returned {kb:.0f}KB with "
        f"{perf_fixture['perf_tasks']} tasks in the library."
    )


@pytest.mark.perf
@pytest.mark.xfail(
    strict=True,
    reason="Issue #422 (2): hashfile picker issues one cracked/total aggregate "
    "query per hashfile, so its latency grows linearly with the customer's "
    "file count.",
)
def test_hashfile_picker_cost_per_hashfile_is_bounded(
    page, live_server, perf_fixture
):
    """Isolate the picker's marginal cost per hashfile from fixed overhead.

    ``/jobs/add`` is the floor: it is the same authenticated request pipeline
    (session, nav counts, base template) rendering a two-field form. Subtracting
    it leaves the picker's own work, which is then divided by the hashfile count.
    """
    job_id = perf_fixture["job_id"]
    hashfiles = perf_fixture["perf_hashfiles"]

    floor_ms, _, _ = time_get(page, f"{live_server}/jobs/add")
    picker_ms, samples, _ = time_get(
        page, f"{live_server}/jobs/{job_id}/assigned_hashfile/"
    )
    marginal_ms = picker_ms - floor_ms
    per_hashfile = marginal_ms / max(hashfiles, 1)
    print(
        f"[perf] scaling hashfile_picker floor={floor_ms:.0f}ms "
        f"picker={picker_ms:.0f}ms marginal={marginal_ms:.0f}ms over "
        f"{hashfiles} hashfiles = {per_hashfile:.2f}ms/hashfile "
        f"budget={MAX_MS_PER_HASHFILE}ms/hashfile"
    )
    assert per_hashfile <= MAX_MS_PER_HASHFILE, (
        f"Hashfile picker costs {per_hashfile:.2f}ms per hashfile "
        f"({marginal_ms:.0f}ms over {hashfiles} files, floor {floor_ms:.0f}ms). "
        "A single grouped aggregate would make this roughly constant."
    )
