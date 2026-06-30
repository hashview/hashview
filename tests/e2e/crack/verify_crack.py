"""In-container verifier: dump the crack job's DB state as JSON for the pytest
poll loop. Run:  PYTHONPATH=/ python /tmp/verify_crack.py <job_name>
"""
import json
import sys

from flask import Flask
from flask_bcrypt import Bcrypt

from hashview.models import HashfileHashes, Hashes, JobTasks, Jobs, db


def build_app():
    # Import Config lazily: its class body reads hashview/config.conf at
    # definition time, which only exists inside the running container. Unit
    # tests import this module and build their own app without build_app().
    from hashview.config import Config
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    Bcrypt(app)
    return app


def collect(app, job_name):
    with app.app_context():
        job = Jobs.query.filter_by(name=job_name).first()
        if job is None:
            return {"job_status": None, "job_tasks": [], "hashes": []}
        job_tasks = [
            {"id": jt.id, "task_id": jt.task_id, "status": jt.status, "agent_id": jt.agent_id}
            for jt in JobTasks.query.filter_by(job_id=job.id).all()
        ]
        rows = (db.session.query(Hashes)
                .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
                .filter(HashfileHashes.hashfile_id == job.hashfile_id).all())
        hashes = [
            {"sub_ciphertext": h.sub_ciphertext, "cracked": bool(h.cracked),
             "plaintext": h.plaintext, "task_id": h.task_id}
            for h in rows
        ]
        return {"job_status": job.status, "job_tasks": job_tasks, "hashes": hashes}


def main():
    job_name = sys.argv[1] if len(sys.argv) > 1 else "e2e-crack-job"
    print(json.dumps(collect(build_app(), job_name)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
