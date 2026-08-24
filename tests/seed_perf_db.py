"""Volume seeder for the job-creation performance e2e suite.

Run inside the app container, AFTER ``seed_e2e_db.py``. Idempotent: every block
checks for its own marker rows first, so re-running is a no-op.

An empty database hides the job wizard's scaling problems — the hotspots are
N+1 loops and full-table renders whose cost is a function of row counts, not of
page size. This seeder adds volume in exactly the three places the wizard reads:

* ``HASHFILES_PER_CUSTOMER`` hashfiles owned by the e2e customer, each holding
  ``HASHES_PER_HASHFILE`` hashes — drives the per-hashfile aggregate loop on the
  "Assign Hashes" step.
* one large hashfile (``BIG_HASHFILE_HASHES`` hashes, ``BIG_CRACKED_RATIO``
  already cracked) — drives the cracked-hash listing.
* ``EXTRA_TASKS`` rows in ``tasks`` — drives the task library render, which
  emits one form + CSRF token per task in the whole table.

Volumes are overridable by env var so the same seeder can produce a quick
smoke-sized fixture or a realistic one.
"""
import os
import sys

from flask import Flask

from hashview.config import Config
from hashview.models import (
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    Tasks,
    Users,
    Wordlists,
    db,
)

# Marker prefixes. Every row this seeder creates is named with one of these, so
# the idempotency checks (and any manual cleanup) can find them unambiguously.
HASHFILE_PREFIX = "perf-hashfile-"
BIG_HASHFILE_NAME = "perf-big-hashfile"
TASK_PREFIX = "perf-task-"

# Bulk-insert chunk size. Large enough to amortize round-trips, small enough to
# stay well inside MySQL's max_allowed_packet on the widest row here.
CHUNK = 5000


def _env_int(key: str, default: int) -> int:
    raw = os.getenv(key)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


def build_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    return app


def _bulk_insert(model, rows):
    """Insert ``rows`` (list of dicts) in chunks, committing per chunk."""
    for start in range(0, len(rows), CHUNK):
        db.session.bulk_insert_mappings(model, rows[start : start + CHUNK])
        db.session.commit()


def _make_hashes(count: int, cracked_count: int, hash_type: int, tag: str):
    """Create ``count`` Hashes rows and return their ids, in insertion order.

    ``sub_ciphertext`` is capped at 32 chars by the schema, so the tag is
    truncated from the left to keep the numeric suffix (the part that makes each
    value unique) intact.
    """
    rows = []
    for i in range(count):
        suffix = f"{i:012d}"
        prefix = f"{tag}"[: 32 - len(suffix)]
        digest = f"{prefix}{suffix}"
        rows.append(
            {
                "sub_ciphertext": digest,
                "ciphertext": digest,
                "hash_type": hash_type,
                "cracked": i < cracked_count,
                "plaintext": f"pw{i}" if i < cracked_count else None,
            }
        )
    _bulk_insert(Hashes, rows)

    # bulk_insert_mappings does not populate primary keys, so read the ids back
    # by the unique sub_ciphertext prefix we just wrote.
    prefix_like = f"{tag}%"
    return [
        row.id
        for row in Hashes.query.with_entities(Hashes.id)
        .filter(Hashes.sub_ciphertext.like(prefix_like))
        .order_by(Hashes.id)
        .all()
    ]


def seed_many_hashfiles(customer_id: int, owner_id: int, count: int, per_file: int):
    existing = Hashfiles.query.filter(
        Hashfiles.name.like(f"{HASHFILE_PREFIX}%")
    ).count()
    if existing >= count:
        print(f"seed_perf_db: {existing} perf hashfiles already present, skipping")
        return

    for n in range(existing, count):
        name = f"{HASHFILE_PREFIX}{n:03d}"
        hashfile = Hashfiles(name=name, customer_id=customer_id, owner_id=owner_id)
        db.session.add(hashfile)
        db.session.commit()

        # Half cracked, so the picker's SUM(CASE cracked) aggregate has real work.
        hash_ids = _make_hashes(
            per_file, per_file // 2, hash_type=1000, tag=f"hf{n:03d}"
        )
        _bulk_insert(
            HashfileHashes,
            [
                {
                    "hash_id": hid,
                    "username": f"user{i}",
                    "hashfile_id": hashfile.id,
                }
                for i, hid in enumerate(hash_ids)
            ],
        )
        print(f"seed_perf_db: hashfile {name} -> {len(hash_ids)} hashes")


def seed_big_hashfile(customer_id: int, owner_id: int, total: int, cracked_ratio: float):
    if Hashfiles.query.filter_by(name=BIG_HASHFILE_NAME).first() is not None:
        print("seed_perf_db: big hashfile already present, skipping")
        return

    hashfile = Hashfiles(
        name=BIG_HASHFILE_NAME, customer_id=customer_id, owner_id=owner_id
    )
    db.session.add(hashfile)
    db.session.commit()

    cracked = int(total * cracked_ratio)
    hash_ids = _make_hashes(total, cracked, hash_type=1000, tag="big")
    _bulk_insert(
        HashfileHashes,
        [
            {"hash_id": hid, "username": f"biguser{i}", "hashfile_id": hashfile.id}
            for i, hid in enumerate(hash_ids)
        ],
    )
    print(
        f"seed_perf_db: big hashfile -> {len(hash_ids)} hashes "
        f"({cracked} cracked), id={hashfile.id}"
    )


def seed_tasks(owner_id: int, count: int):
    existing = Tasks.query.filter(Tasks.name.like(f"{TASK_PREFIX}%")).count()
    if existing >= count:
        print(f"seed_perf_db: {existing} perf tasks already present, skipping")
        return

    wordlist = Wordlists.query.first()
    if wordlist is None:
        raise RuntimeError(
            "No wordlist found. The app creates defaults on boot; seed after boot."
        )

    _bulk_insert(
        Tasks,
        [
            {
                "name": f"{TASK_PREFIX}{n:04d}",
                "hc_attackmode": 0,
                "owner_id": owner_id,
                "wl_id": wordlist.id,
            }
            for n in range(existing, count)
        ],
    )
    print(f"seed_perf_db: tasks -> {count} total perf tasks")


def seed(app: Flask) -> None:
    customer_id = int(os.environ["HASHVIEW_E2E_CUSTOMER_ID"])

    hashfiles_per_customer = _env_int("HASHVIEW_PERF_HASHFILES", 30)
    hashes_per_hashfile = _env_int("HASHVIEW_PERF_HASHES_PER_HASHFILE", 2000)
    big_hashfile_hashes = _env_int("HASHVIEW_PERF_BIG_HASHFILE_HASHES", 50000)
    cracked_ratio = float(os.getenv("HASHVIEW_PERF_BIG_CRACKED_RATIO", "0.6"))
    extra_tasks = _env_int("HASHVIEW_PERF_TASKS", 400)

    with app.app_context():
        admin = db.session.get(Users, 1)
        if admin is None:
            raise RuntimeError("Admin user (id=1) not found; app must finish booting.")
        if db.session.get(Customers, customer_id) is None:
            raise RuntimeError(
                f"Customer id={customer_id} not found; run seed_e2e_db.py first."
            )

        seed_many_hashfiles(
            customer_id, admin.id, hashfiles_per_customer, hashes_per_hashfile
        )
        seed_big_hashfile(customer_id, admin.id, big_hashfile_hashes, cracked_ratio)
        seed_tasks(admin.id, extra_tasks)

        print(
            "seed_perf_db: totals -> "
            f"hashfiles={Hashfiles.query.count()} "
            f"hashes={Hashes.query.count()} "
            f"hashfile_hashes={HashfileHashes.query.count()} "
            f"tasks={Tasks.query.count()}"
        )


def main() -> int:
    if not os.getenv("HASHVIEW_E2E_CUSTOMER_ID"):
        print("seed_perf_db: missing HASHVIEW_E2E_CUSTOMER_ID", file=sys.stderr)
        return 2
    seed(build_app())
    print("seed_perf_db: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
