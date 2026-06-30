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

    from hashview.models import (Agents, Hashes, JobTasks, Jobs, Rules,
                                 Tasks, Wordlists)
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
        # Each command references the agent control paths the server built.
        cmds = " ".join(jt.command for jt in jts)
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
