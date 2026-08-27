"""E2E database seeder. Run inside the app container after the app is up.

Idempotent. Brings the database to the state the e2e suite expects:
- admin user (id=1) has the e2e email/password/api_key from the env vars
- Settings row exists (so the /setup/settings wizard doesn't trigger)
- Customer / Hashfile / Job rows exist at the IDs the suite pins via env vars
- a second, non-admin user (for the job-IDOR test) when the optional
  HASHVIEW_E2E_SECOND_EMAIL / HASHVIEW_E2E_SECOND_PASSWORD vars are provided

Required env vars: HASHVIEW_E2E_SETUP_EMAIL, HASHVIEW_E2E_SETUP_PASSWORD,
HASHVIEW_E2E_API_KEY, HASHVIEW_E2E_CUSTOMER_ID, HASHVIEW_E2E_HASHFILE_ID,
HASHVIEW_E2E_JOB_ID, HASHVIEW_E2E_TASK_ID.
Optional: HASHVIEW_E2E_SECOND_EMAIL, HASHVIEW_E2E_SECOND_PASSWORD (provision a
non-admin user so tests/e2e/test_security.py's IDOR check runs, not skips).
"""
import os
import sys

from flask import Flask
from flask_bcrypt import Bcrypt

from hashview.config import Config
from hashview.models import (
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    Jobs,
    JobTasks,
    Settings,
    Tasks,
    Users,
    db,
)

REQUIRED_ENV = (
    "HASHVIEW_E2E_SETUP_EMAIL",
    "HASHVIEW_E2E_SETUP_PASSWORD",
    "HASHVIEW_E2E_API_KEY",
    "HASHVIEW_E2E_CUSTOMER_ID",
    "HASHVIEW_E2E_HASHFILE_ID",
    "HASHVIEW_E2E_JOB_ID",
    "HASHVIEW_E2E_TASK_ID",
)
OPTIONAL_SECOND_USER_ENV = (
    "HASHVIEW_E2E_SECOND_EMAIL",
    "HASHVIEW_E2E_SECOND_PASSWORD",
)


def build_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    Bcrypt(app)
    return app


def seed(app: Flask) -> None:
    email = os.environ["HASHVIEW_E2E_SETUP_EMAIL"]
    password = os.environ["HASHVIEW_E2E_SETUP_PASSWORD"]
    api_key = os.environ["HASHVIEW_E2E_API_KEY"]
    customer_id = int(os.environ["HASHVIEW_E2E_CUSTOMER_ID"])
    hashfile_id = int(os.environ["HASHVIEW_E2E_HASHFILE_ID"])
    job_id = int(os.environ["HASHVIEW_E2E_JOB_ID"])
    task_id = int(os.environ["HASHVIEW_E2E_TASK_ID"])

    bcrypt = Bcrypt(app)

    with app.app_context():
        admin = db.session.get(Users, 1)
        if admin is None:
            raise RuntimeError(
                "Admin user (id=1) not found. App must finish booting before seeding."
            )
        admin.first_name = admin.first_name or "Admin"
        admin.last_name = admin.last_name or "User"
        admin.email_address = email
        admin.password = bcrypt.generate_password_hash(password).decode("utf-8")
        admin.admin = True
        admin.api_key = api_key

        second_email = os.getenv("HASHVIEW_E2E_SECOND_EMAIL")
        second_password = os.getenv("HASHVIEW_E2E_SECOND_PASSWORD")
        if second_email and second_password:
            second_user = Users.query.filter_by(email_address=second_email).first()
            second_pw_hash = bcrypt.generate_password_hash(second_password).decode("utf-8")
            if second_user is None:
                db.session.add(
                    Users(
                        first_name="E2E",
                        last_name="Second",
                        email_address=second_email,
                        password=second_pw_hash,
                        admin=False,
                    )
                )
            else:
                second_user.password = second_pw_hash
                second_user.admin = False

        if db.session.query(Settings).first() is None:
            db.session.add(
                Settings(
                    retention_period=30,
                    max_runtime_jobs=0,
                    max_runtime_tasks=0,
                )
            )

        if db.session.get(Customers, customer_id) is None:
            db.session.add(Customers(id=customer_id, name="E2E Customer"))

        if db.session.get(Tasks, task_id) is None:
            raise RuntimeError(
                f"Task id={task_id} not found. Default tasks should be created on app boot."
            )

        if db.session.get(Hashfiles, hashfile_id) is None:
            db.session.add(
                Hashfiles(
                    id=hashfile_id,
                    name="e2e-hashfile",
                    customer_id=customer_id,
                    owner_id=admin.id,
                )
            )
            db.session.flush()
            hash_row = Hashes(
                sub_ciphertext="d41d8cd98f00b204e9800998ecf8427e",
                ciphertext="d41d8cd98f00b204e9800998ecf8427e",
                hash_type=0,
                cracked=False,
            )
            db.session.add(hash_row)
            db.session.flush()
            db.session.add(
                HashfileHashes(
                    hash_id=hash_row.id,
                    username="e2e-user",
                    hashfile_id=hashfile_id,
                )
            )

        if db.session.get(Jobs, job_id) is None:
            db.session.add(
                Jobs(
                    id=job_id,
                    name="E2E Job",
                    status="Ready",
                    customer_id=customer_id,
                    hashfile_id=hashfile_id,
                    owner_id=admin.id,
                )
            )
            db.session.flush()
            db.session.add(
                JobTasks(
                    job_id=job_id,
                    task_id=task_id,
                    status="Not Started",
                )
            )

        db.session.commit()


def main() -> int:
    missing = [k for k in REQUIRED_ENV if not os.getenv(k)]
    if missing:
        print(f"seed_e2e_db: missing env vars: {missing}", file=sys.stderr)
        return 2
    seed(build_app())
    print("seed_e2e_db: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
