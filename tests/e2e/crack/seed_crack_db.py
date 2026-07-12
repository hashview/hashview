"""In-container seeder for the multi-agent crack e2e test. Idempotent.

Builds the full job the agents will execute and authorizes both agents:
  user(id=1) + Settings + Customer + 2 static wordlists (the rockyou slices) +
  1 rule + 1 hashfile with NTLM hashes of every target + 2 tasks (A: dict,
  B: dict+rule) + 1 job (Queued) + 2 job_tasks (Queued, command built) +
  2 Authorized agents.

Run inside the app container:  PYTHONPATH=/ python /tmp/seed_crack_db.py /tmp/crack/manifest.json
"""
import json
import os
import secrets
import sys

import hashview
from flask import Flask
from flask_bcrypt import Bcrypt

from hashview.models import (Agents, Customers, HashfileHashes, Hashes,
                             Hashfiles, JobTasks, Jobs, Rules, Settings, Tasks,
                             Users, Wordlists, db)
from hashview.utils.utils import (build_hashcat_command, get_filehash,
                                  get_linecount, get_md5_hash,
                                  ingest_static_wordlist_file, ntlm_hash_hex)


def build_app():
    # root_path MUST match the running server's app (the hashview package dir),
    # NOT this script's location — ingest_static_wordlist_file and the rule write
    # store files under <root_path>/control/{wordlists,rules}, which is exactly
    # where the server's /v1/wordlists/<id> and /v1/rules/<id> download routes
    # read from. Using Flask(__name__) here would resolve to /tmp and the agent
    # would never find the synced files.
    #
    # Import Config lazily: its class body reads hashview/config.conf at
    # definition time, which only exists inside the running container. Keeping
    # it out of module scope lets unit tests import this seeder (they build
    # their own app and never call build_app()) without a config file present.
    from hashview.config import Config
    app = Flask(__name__, root_path=os.path.dirname(hashview.__file__))
    app.config.from_object(Config)
    db.init_app(app)
    Bcrypt(app)
    return app


def _ensure_admin(app):
    bcrypt = Bcrypt(app)
    admin = db.session.get(Users, 1)
    if admin is None:
        admin = Users(id=1, first_name="E2E", last_name="Crack",
                      email_address="e2e-crack@example.com", password="x", admin=True)
        db.session.add(admin)
    # Always set a NON-default password. The app boots a default admin whose
    # password == DEFAULT_PASSWORD; admin_pass_needs_changed() then keeps EVERY
    # request — including agent endpoints — redirected to the setup wizard until
    # the password is changed. Setting it here satisfies that gate headlessly.
    admin.password = bcrypt.generate_password_hash("e2e-crack-pw").decode("utf-8")
    admin.admin = True
    if db.session.query(Settings).first() is None:
        db.session.add(Settings(retention_period=0, max_runtime_jobs=0, max_runtime_tasks=0))
    db.session.flush()
    return admin


def seed(app, manifest):
    with app.app_context():
        # Idempotency: if the job already exists, only (re)authorize agents and return.
        existing = Jobs.query.filter_by(name=manifest["job_name"]).first()
        if existing is not None:
            _authorize_agents(manifest)
            db.session.commit()
            return

        admin = _ensure_admin(app)
        customer_id = manifest["customer_id"]
        if db.session.get(Customers, customer_id) is None:
            db.session.add(Customers(id=customer_id, name="E2E Crack Customer"))

        # Rule (plaintext at rest; checksum over plaintext — matches rules_add).
        rules_dir = os.path.join(app.root_path, "control/rules")
        os.makedirs(rules_dir, exist_ok=True)
        rule_path = os.path.join(rules_dir, secrets.token_hex(8) + ".txt")
        with open(rule_path, "w", encoding="utf-8") as f:
            f.write(manifest["rule_body"])
        rule = Rules(name="e2e-crack-rule", owner_id=admin.id, path=rule_path,
                     size=get_linecount(rule_path), checksum=get_filehash(rule_path))
        db.session.add(rule)
        db.session.flush()

        # Hashfile shared by both tasks.
        hashfile = Hashfiles(name="e2e-crack-hashfile", customer_id=customer_id,
                             owner_id=admin.id)
        db.session.add(hashfile)
        db.session.flush()

        job = Jobs(name=manifest["job_name"], status="Queued", customer_id=customer_id,
                   hashfile_id=hashfile.id, owner_id=admin.id)
        db.session.add(job)
        db.session.flush()

        for t in manifest["tasks"]:
            # Wordlist (ingest the slice exactly like a UI upload -> correct checksum/type).
            wl = ingest_static_wordlist_file(t["slice_container_path"], admin.id, t["name"] + "-wl")
            db.session.add(wl)
            db.session.flush()

            # NTLM hashes for this task's targets, attached to the shared hashfile.
            for pt in t["target_plaintexts"]:
                ciphertext = ntlm_hash_hex(pt)           # uppercase hex
                h = Hashes(hash_type=1000, ciphertext=ciphertext,
                           sub_ciphertext=get_md5_hash(ciphertext), cracked=0)
                db.session.add(h)
                db.session.flush()
                db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hashfile.id,
                                              username=t["name"]))

            task = Tasks(name=t["name"], hc_attackmode=0, owner_id=admin.id,
                         wl_id=wl.id, rule_id=(rule.id if t["use_rule"] else None),
                         loopback=False)
            db.session.add(task)
            db.session.flush()

            jt = JobTasks(job_id=job.id, task_id=task.id, status="Queued", priority=3)
            db.session.add(jt)
            db.session.flush()
            # build_hashcat_command returns an argv list; the command column stores
            # it as JSON (same as _set_job_task_command), which the agent decodes.
            jt.command = json.dumps(build_hashcat_command(job.id, task.id))

        _authorize_agents(manifest)
        db.session.commit()


def _authorize_agents(manifest):
    for a in manifest["agents"]:
        agent = Agents.query.filter_by(uuid=a["uuid"]).first()
        if agent is None:
            db.session.add(Agents(name=a["name"], uuid=a["uuid"], src_ip="0.0.0.0",
                                  status="Authorized"))
        else:
            agent.status = "Authorized"
            agent.name = a["name"]


def main():
    if len(sys.argv) < 2:
        print("usage: seed_crack_db.py <manifest.json>", file=sys.stderr)
        return 2
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        manifest = json.load(f)
    seed(build_app(), manifest)
    print("seed_crack_db: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
