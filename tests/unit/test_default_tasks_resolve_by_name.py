"""The seeded starter tasks must point at the wordlist and rule they are named for.

Issue #396. The ids were written in as literals -- wl_id '2' and '3', rule_id
'1' -- which were correct when three dynamic wordlists were seeded ahead of
Rockyou. _DYNAMIC_WORDLISTS yields nine rows today (four canonical plus five
length buckets from dynamic_password_length_wordlists), so Rockyou seeds at id
10 and the two tasks named after it pointed at "(DYNAMIC) All Usernames" and
"(DYNAMIC) All Customers": empty placeholders on a fresh install. The first
thing a new user is invited to run therefore completed successfully having
tried nothing, and reported success.

Every assertion below is on a NAME, never on an id. Asserting `wl_id == 10`
would pin exactly the brittleness that caused this -- it would pass today and
break silently the next time a dynamic wordlist is added, which is precisely
what happened to the literals.
"""
import gzip

import pytest

from hashview import setup as setup_mod
from hashview.models import Rules, Tasks, Wordlists, db
from hashview.setup import (
    BEST64_RULE_NAME,
    ROCKYOU_WORDLIST_NAME,
    add_admin_user,
    add_default_dynamic_wordlists,
    add_default_rules,
    add_default_static_wordlist,
    add_default_tasks,
    default_tasks_need_added,
)
from hashview.users.routes import bcrypt


@pytest.fixture
def fresh_install(app, tmp_path, monkeypatch):
    """A private control/ tree and tiny stand-ins for the shipped seed archives."""
    root = tmp_path / "hvroot"
    (root / "control").mkdir(parents=True)
    monkeypatch.setattr(app, "root_path", str(root))
    install = tmp_path / "install"
    install.mkdir()
    rule_gz = install / "best64.rule.gz"
    with gzip.open(rule_gz, "wb") as fh:
        fh.write(b":\nu\nl\n")
    wordlist_gz = install / "rockyou.txt.gz"
    with gzip.open(wordlist_gz, "wb") as fh:
        fh.write(b"password\n123456\n")
    monkeypatch.setattr(setup_mod, "SEED_RULE_GZ", str(rule_gz))
    monkeypatch.setattr(setup_mod, "SEED_WORDLIST_GZ", str(wordlist_gz))
    return {"rule_gz": rule_gz, "wordlist_gz": wordlist_gz}


def _seed_everything():
    """The order create_app uses in setup_defaults_if_needed."""
    add_admin_user(db, bcrypt)
    add_default_dynamic_wordlists(db)
    add_default_static_wordlist(db)
    add_default_rules(db)
    add_default_tasks(db)


def _task(name):
    return Tasks.query.filter_by(name=name).one()


def _wordlist_of(task):
    return Wordlists.query.get(task.wl_id) if task.wl_id else None


# --- what the issue is about ---------------------------------------------------

def test_the_rockyou_tasks_point_at_rockyou(fresh_install):
    _seed_everything()

    for name in ('Rockyou Wordlist', 'Rockyou Wordlist + Best64 Rules'):
        wordlist = _wordlist_of(_task(name))
        assert wordlist is not None, f"{name} has no wordlist at all"
        assert wordlist.name == ROCKYOU_WORDLIST_NAME, (
            f"{name} points at {wordlist.name!r}")
        assert wordlist.type == 'static', (
            f"{name} points at a dynamic list, which is empty on a fresh install")


def test_the_rules_task_points_at_best64(fresh_install):
    _seed_everything()

    task = _task('Rockyou Wordlist + Best64 Rules')
    assert task.rule_id is not None
    assert Rules.query.get(task.rule_id).name == BEST64_RULE_NAME


def test_no_seeded_task_points_at_a_dynamic_wordlist(fresh_install):
    # The general form: a starter task exists to demonstrate cracking, and every
    # dynamic list is empty until the instance has recovered something.
    _seed_everything()

    for task in Tasks.query.all():
        wordlist = _wordlist_of(task)
        if wordlist is not None:
            assert wordlist.type != 'dynamic', (
                f"{task.name!r} was seeded against {wordlist.name!r}, which is "
                "empty on a fresh install")


def test_the_mask_task_needs_no_wordlist(fresh_install):
    _seed_everything()
    assert _task('?a?a?a?a?a?a?a?a [8]').wl_id is None


def test_no_seeded_task_has_a_dangling_reference(fresh_install):
    """A task pointing at an id that does not exist is worse than the bug this
    fixes: it fails at dispatch rather than merely cracking nothing."""
    _seed_everything()

    for task in Tasks.query.all():
        if task.wl_id is not None:
            assert Wordlists.query.get(task.wl_id) is not None, task.name
        if task.rule_id is not None:
            assert Rules.query.get(task.rule_id) is not None, task.name


# --- the property that keeps it fixed ------------------------------------------

def test_adding_more_dynamic_wordlists_does_not_repoint_the_tasks(fresh_install,
                                                                  monkeypatch):
    """The actual regression guard.

    Seeding order is not a contract, and twice now it has moved. Push three more
    dynamic lists in front of Rockyou and the tasks must still find it -- under
    the old literals they would quietly slide onto whatever landed at id 2.
    """
    extra = tuple((f'(DYNAMIC) Extra {n}', f'hashview/control/wordlists/extra{n}.txt')
                  for n in range(3))
    monkeypatch.setattr(setup_mod, '_DYNAMIC_WORDLISTS',
                        setup_mod._DYNAMIC_WORDLISTS + extra)

    _seed_everything()

    rockyou = Wordlists.query.filter_by(name=ROCKYOU_WORDLIST_NAME).one()
    assert rockyou.id > 10, "the fixture did not actually shift Rockyou's id"
    for name in ('Rockyou Wordlist', 'Rockyou Wordlist + Best64 Rules'):
        assert _task(name).wl_id == rockyou.id


# --- the all-or-nothing rule ---------------------------------------------------

def test_nothing_is_seeded_when_the_wordlist_is_missing(fresh_install):
    """Seeding Rockyou is best-effort and can fail (a mounted control/, a missing
    install tree). A partial seed would be permanent: default_tasks_need_added
    asks whether ANY task exists, so writing just the mask task closes the gate
    and the two that matter never arrive."""
    add_admin_user(db, bcrypt)
    add_default_dynamic_wordlists(db)
    add_default_rules(db)          # rule yes, wordlist no

    add_default_tasks(db)

    assert Tasks.query.count() == 0
    assert default_tasks_need_added(db) is True, (
        "the gate closed, so a later boot will never seed the missing tasks")


def test_nothing_is_seeded_when_the_rule_is_missing(fresh_install):
    add_admin_user(db, bcrypt)
    add_default_dynamic_wordlists(db)
    add_default_static_wordlist(db)   # wordlist yes, rule no

    add_default_tasks(db)

    assert Tasks.query.count() == 0
    assert default_tasks_need_added(db) is True


def test_a_later_boot_seeds_what_the_first_one_could_not(fresh_install):
    """The point of leaving the gate open."""
    add_admin_user(db, bcrypt)
    add_default_dynamic_wordlists(db)
    add_default_tasks(db)                 # neither dependency exists yet
    assert Tasks.query.count() == 0

    add_default_static_wordlist(db)       # the next boot gets further
    add_default_rules(db)
    add_default_tasks(db)

    assert _wordlist_of(_task('Rockyou Wordlist')).name == ROCKYOU_WORDLIST_NAME


# --- the names themselves -------------------------------------------------------

def test_the_seeded_names_are_the_ones_the_lookup_uses(fresh_install):
    """One definition of each name, so a rename cannot silently orphan the tasks."""
    _seed_everything()
    assert Wordlists.query.filter_by(name=ROCKYOU_WORDLIST_NAME).count() == 1
    assert Rules.query.filter_by(name=BEST64_RULE_NAME).count() == 1
