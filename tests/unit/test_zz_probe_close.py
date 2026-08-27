import os

from hashview.models import Rules, Users, db

DOMAIN = "localhost.test"

def test_probe(app, client):
    u = Users(first_name="A", last_name="B", email_address="a@e.com",
              password="x", admin=True, api_key="k")
    db.session.add(u)
    db.session.commit()
    src = os.path.join(app.root_path, "control", "rules", "probe_rule.txt")
    open(src, "wb").write(b"body\n")
    r = Rules(name="r", owner_id=u.id, path="control/rules/probe_rule.txt", checksum="x")
    db.session.add(r)
    db.session.commit()
    client.set_cookie("uuid", "k", domain=DOMAIN)
    tmp = os.path.join(app.root_path, "control", "tmp")
    before = set(os.listdir(tmp))
    resp = client.get(f"/v1/rules/{r.id}")
    print("STATUS", resp.status_code)
    after_req = set(os.listdir(tmp)) - before
    print("AFTER REQUEST, before .data:", after_req)
    _ = resp.data
    print("AFTER .data:", set(os.listdir(tmp)) - before)
    resp.close()
    print("AFTER close():", set(os.listdir(tmp)) - before)
    print("has call_on_close attr:", hasattr(resp, "call_on_close"))
    os.remove(src)
