import importlib.util
import json
from pathlib import Path

CRACK = Path(__file__).resolve().parents[1] / "e2e" / "crack"


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, CRACK / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _make_app(tmp_path):
    from flask import Flask
    from flask_bcrypt import Bcrypt

    from hashview.models import db
    app = Flask(__name__, root_path=str(tmp_path))
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{tmp_path/'t.db'}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)
    Bcrypt(app)
    for sub in ("control/wordlists", "control/rules", "control/tmp"):
        (tmp_path / sub).mkdir(parents=True, exist_ok=True)
    with app.app_context():
        db.create_all()
    return app


def _manifest(tmp_path):
    # NTLM("cat")=plain target ; base "dog" -> Task B target "dog1"
    a = tmp_path / "sliceA.txt"
    a.write_text("cat\nalpha\nbeta\n")
    b = tmp_path / "sliceB.txt"
    b.write_text("dog\ngamma\ndelta\n")
    return {
        "job_name": "e2e-crack-job",
        "customer_id": 9001,
        "rule_body": "$1\n",
        "agents": [
            {"name": "e2e-agent-1", "uuid": "11111111-1111-1111-1111-111111111111"},
            {"name": "e2e-agent-2", "uuid": "22222222-2222-2222-2222-222222222222"},
        ],
        "tasks": [
            {"name": "e2e-crack-task-dict", "use_rule": False,
             "slice_container_path": str(a), "target_plaintexts": ["cat"]},
            {"name": "e2e-crack-task-rules", "use_rule": True,
             "slice_container_path": str(b), "target_plaintexts": ["dog1"]},
        ],
    }


def test_seed_creates_full_job_and_authorizes_agents(tmp_path):
    seed = _load("seed_crack_db", "seed_crack_db.py")
    app = _make_app(tmp_path)
    manifest = _manifest(tmp_path)
    seed.seed(app, manifest)

    from hashview.models import Agents, Hashes, Jobs, JobTasks, Rules, Tasks, Wordlists
    with app.app_context():
        assert Wordlists.query.count() == 2
        assert Rules.query.count() == 1
        assert Hashes.query.count() == 2
        assert Tasks.query.count() == 2
        job = Jobs.query.filter_by(name="e2e-crack-job").first()
        assert job is not None and job.status == "Queued"
        jts = JobTasks.query.filter_by(job_id=job.id).all()
        assert len(jts) == 2
        assert all(jt.status == "Queued" for jt in jts)
        # Each command is a JSON argv list; decode + join the tokens to inspect
        # the agent control paths the server built.
        cmds = " ".join(tok for jt in jts for tok in json.loads(jt.command))
        assert "-m 1000" in cmds
        assert "control/hashes/hashfile_" in cmds
        assert "control/wordlists/" in cmds
        assert "-r control/rules/" in cmds            # Task B emits a rule
        agents = Agents.query.all()
        assert {a.uuid for a in agents} == {
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
        }
        assert all(a.status == "Authorized" for a in agents)


def test_seed_is_idempotent(tmp_path):
    seed = _load("seed_crack_db", "seed_crack_db.py")
    app = _make_app(tmp_path)
    manifest = _manifest(tmp_path)
    seed.seed(app, manifest)
    seed.seed(app, manifest)
    from hashview.models import Jobs
    with app.app_context():
        assert Jobs.query.filter_by(name="e2e-crack-job").count() == 1


def test_verify_dumps_state(tmp_path):
    seed = _load("seed_crack_db", "seed_crack_db.py")
    verify = _load("verify_crack", "verify_crack.py")
    app = _make_app(tmp_path)
    manifest = _manifest(tmp_path)
    seed.seed(app, manifest)
    state = verify.collect(app, "e2e-crack-job")
    assert state["job_status"] == "Queued"
    assert len(state["job_tasks"]) == 2
    assert len(state["hashes"]) == 2
    assert all(h["cracked"] is False for h in state["hashes"])
    # JSON-printable
    json.dumps(state)


def test_main_reports_ok_when_the_job_is_readable_back(tmp_path, monkeypatch, capsys):
    """The happy path still exits 0 and prints the marker the harness greps for."""
    seed = _load("seed_crack_db", "seed_crack_db.py")
    app = _make_app(tmp_path)
    manifest = _manifest(tmp_path)
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    monkeypatch.setattr(seed, "build_app", lambda: app)
    monkeypatch.setattr(seed.sys, "argv", ["seed_crack_db.py", str(path)])

    assert seed.main() == 0
    assert "seed_crack_db: ok" in capsys.readouterr().out


def test_main_fails_when_the_committed_job_is_not_readable_back(tmp_path, monkeypatch, capsys):
    """A commit reporting no error is not proof the row is durable.

    On a freshly created volume the database can still be settling behind an app
    that is already answering, and a seed landing in that window has been seen to
    commit "successfully" and then not be there. Before this check the run
    continued: every agent heartbeat found nothing to do and the failure surfaced
    four minutes later as "recovered set(), expected {...}", which reads as a
    cracking bug rather than a database that never received the job.

    Simulated by making seed() a no-op, which is indistinguishable from a commit
    that did not land as far as the read-back is concerned.
    """
    seed = _load("seed_crack_db", "seed_crack_db.py")
    app = _make_app(tmp_path)
    manifest = _manifest(tmp_path)
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    monkeypatch.setattr(seed, "build_app", lambda: app)
    monkeypatch.setattr(seed, "seed", lambda *a, **k: None)
    monkeypatch.setattr(seed.sys, "argv", ["seed_crack_db.py", str(path)])

    assert seed.main() == 1
    err = capsys.readouterr().err
    assert "seed_crack_db: FAILED" in err
    assert "not in the database on read-back" in err


def test_main_fails_when_the_job_is_short_of_tasks(tmp_path, monkeypatch, capsys):
    """A job row alone is not enough -- a partially applied seed leaves agents
    with less work than the test expects, which would fail just as opaquely."""
    from hashview.models import JobTasks
    from hashview.models import db as _db
    seed = _load("seed_crack_db", "seed_crack_db.py")
    app = _make_app(tmp_path)
    manifest = _manifest(tmp_path)
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))

    def _partial(app_, manifest_):
        seed_real(app_, manifest_)
        with app_.app_context():
            _db.session.delete(JobTasks.query.first())
            _db.session.commit()

    seed_real = seed.seed
    monkeypatch.setattr(seed, "build_app", lambda: app)
    monkeypatch.setattr(seed, "seed", _partial)
    monkeypatch.setattr(seed.sys, "argv", ["seed_crack_db.py", str(path)])

    assert seed.main() == 1
    assert "expected 2" in capsys.readouterr().err
