import os
import subprocess

import pytest
from flask import Response

from hashview import create_app
from hashview.models import Rules, Users, db


@pytest.mark.security
def test_rules_download_command_injection_poc(monkeypatch):
    """
    PoC: a crafted Rules.path can never reach a shell.

    The current implementation is pure-Python: the stored path is reduced to
    its basename, joined under control/rules, and compressed with
    compress_to_gz. There is no subprocess/os.system call anywhere on the
    path. This test plants shell tripwires and asserts the request resolves
    to a 404 (the crafted basename does not exist on disk) without any shell
    invocation. It will FAIL if anyone reintroduces a shell call.
    """
    app = create_app(
        testing=True,
        config_overrides={
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "WTF_CSRF_ENABLED": False,
            "HASHVIEW_SKIP_SETUP": True,
            "HASHVIEW_SKIP_GUI_SETUP": True,
            "HASHVIEW_DISABLE_SCHEDULER": True,
        },
    )

    with app.app_context():
        db.create_all()
        user = Users(
            first_name="Test",
            last_name="User",
            email_address="test@example.com",
            password="x" * 60,
            admin=True,
            api_key="test-api-key",
        )
        db.session.add(user)
        db.session.commit()

        # includes `whoami` to show the injection payload never reaches a shell
        injected_path = "evil; whoami; #.rule"
        rule = Rules(
            name="evil-rule",
            owner_id=user.id,
            path=injected_path,
            size=1,
            checksum="0" * 64,
        )
        db.session.add(rule)
        db.session.commit()

        import hashview.api.routes as api_routes

        def _shell_tripwire(*args, **kwargs):
            pytest.fail("shell invocation attempted")

        # Tripwires: any route through os.system or subprocess fails the test.
        monkeypatch.setattr(api_routes.os, "system", _shell_tripwire)
        monkeypatch.setattr(subprocess, "run", _shell_tripwire)
        monkeypatch.setattr(subprocess, "Popen", _shell_tripwire)

        client = app.test_client()
        client.set_cookie("uuid", "test-api-key")
        resp = client.get(f"/v1/rules/{rule.id}")

        # basename("evil; whoami; #.rule") does not exist under control/rules
        assert resp.status_code == 404


@pytest.mark.security
def test_rules_download_compresses_with_pure_python_gzip(monkeypatch):
    """
    Pin the current implementation: a valid rule file is compressed with the
    pure-Python compress_to_gz helper (level 9) into control/tmp under a
    random .gz name, then served via send_from_directory.
    """
    app = create_app(
        testing=True,
        config_overrides={
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "WTF_CSRF_ENABLED": False,
            "HASHVIEW_SKIP_SETUP": True,
            "HASHVIEW_SKIP_GUI_SETUP": True,
            "HASHVIEW_DISABLE_SCHEDULER": True,
        },
    )

    with app.app_context():
        db.create_all()
        user = Users(
            first_name="Test",
            last_name="User",
            email_address="test@example.com",
            password="x" * 60,
            admin=True,
            api_key="test-api-key",
        )
        db.session.add(user)
        db.session.commit()

        rule = Rules(
            name="safe-rule",
            owner_id=user.id,
            path="safe.rule",
            size=1,
            checksum="0" * 64,
        )
        db.session.add(rule)
        db.session.commit()

        rules_dir = os.path.join(app.root_path, "control/rules")
        os.makedirs(rules_dir, exist_ok=True)
        rule_file = os.path.join(rules_dir, "safe.rule")

        captured = {}

        def fake_compress_to_gz(src, dst, level):
            captured["src"] = src
            captured["dst"] = dst
            captured["level"] = level

        import hashview.api.routes as api_routes
        import hashview.utils.utils as utils_mod

        monkeypatch.setattr(api_routes, "compress_to_gz", fake_compress_to_gz)
        # The response is built by send_generated_file(), which lives in utils
        # and therefore resolves send_from_directory from that module.
        monkeypatch.setattr(
            utils_mod,
            "send_from_directory",
            lambda *args, **kwargs: Response("ok", status=200),
        )

        try:
            with open(rule_file, "w") as f:
                f.write(":\n")

            client = app.test_client()
            client.set_cookie("uuid", "test-api-key")
            resp = client.get(f"/v1/rules/{rule.id}")

            assert resp.status_code == 200
            assert captured["src"].endswith(os.path.join("control/rules", "safe.rule"))
            assert "control/tmp/" in captured["dst"]
            assert captured["dst"].endswith(".gz")
            assert captured["level"] == 9
        finally:
            if os.path.exists(rule_file):
                os.remove(rule_file)


@pytest.mark.security
def test_rules_download_traversal_neutralized(monkeypatch):
    """
    Pin that path traversal in Rules.path is neutralized: the route takes
    os.path.basename() of the stored path, so '../../../../etc/passwd'
    collapses to 'passwd' inside control/rules — a missing file (404) —
    and never an absolute-path read served back to the client.
    """
    app = create_app(
        testing=True,
        config_overrides={
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "WTF_CSRF_ENABLED": False,
            "HASHVIEW_SKIP_SETUP": True,
            "HASHVIEW_SKIP_GUI_SETUP": True,
            "HASHVIEW_DISABLE_SCHEDULER": True,
        },
    )

    with app.app_context():
        db.create_all()
        user = Users(
            first_name="Test",
            last_name="User",
            email_address="test@example.com",
            password="x" * 60,
            admin=True,
            api_key="test-api-key",
        )
        db.session.add(user)
        db.session.commit()

        rule = Rules(
            name="traversal-rule",
            owner_id=user.id,
            path="../../../../etc/passwd",
            size=1,
            checksum="0" * 64,
        )
        db.session.add(rule)
        db.session.commit()

        served = {}

        def sentinel_send_from_directory(directory, *args, **kwargs):
            served["directory"] = directory
            return Response("ok", status=200)

        import hashview.api.routes as api_routes

        monkeypatch.setattr(
            api_routes, "send_from_directory", sentinel_send_from_directory
        )

        client = app.test_client()
        client.set_cookie("uuid", "test-api-key")
        resp = client.get(f"/v1/rules/{rule.id}")

        # Traversal collapses to control/rules/passwd, which does not exist.
        assert resp.status_code == 404
        # Nothing was ever served from disk.
        assert served == {}
