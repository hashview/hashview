"""Create/edit modals show validation errors INSIDE the reopened modal instead
of flashing them over the listing (or bouncing to a standalone page).

Mirrors the behaviour first shipped for the Add-user modal and extended to
customers, tasks, task_groups and rules. The shared contract per flow:
  * a validation error redirects back to the listing (302),
  * nothing is queued in the flash area (session['_flashes'] is empty),
  * the error text + the modal's reopen script are present in the listing HTML,
  * no partial row is created.
"""

from hashview.models import Customers, Rules, TaskGroups, Tasks, db
from tests.unit.helpers import login, make_admin, make_customer


def _admin_client(app, client):
    admin = make_admin()
    login(client, admin)
    return admin


def _no_flashes(client):
    with client.session_transaction() as sess:
        return not sess.get("_flashes")


# --- customers (modal-only add + edit) -------------------------------------

def test_customers_add_duplicate_shows_error_in_modal(app, client):
    _admin_client(app, client)
    make_customer(name="Acme")
    resp = client.post("/customers/add", data={"name": "Acme"}, follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert _no_flashes(client)
    body = client.get("/customers").get_data(as_text=True)
    assert "That customer already exists" in body
    assert "add-customer-modal" in body          # reopen script targets the add modal
    assert Customers.query.filter_by(name="Acme").count() == 1


def test_customers_edit_duplicate_shows_error_in_modal(app, client):
    _admin_client(app, client)
    make_customer(name="Acme")
    beta = make_customer(name="Beta")
    resp = client.post("/customers/edit", data={"customer_id": beta.id, "name": "Acme"},
                       follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert _no_flashes(client)
    body = client.get("/customers").get_data(as_text=True)
    assert "That customer already exists" in body
    assert "hvEditCustomer(" in body             # reopen script re-opens the edit modal
    assert Customers.query.get(beta.id).name == "Beta"   # rename rejected


# --- tasks (modal + legacy standalone page share the route) ----------------

def test_tasks_add_modal_duplicate_shows_error_in_modal(app, client):
    admin = _admin_client(app, client)
    db.session.add(Tasks(name="DupTask", hc_attackmode=0, owner_id=admin.id))
    db.session.commit()
    resp = client.post("/tasks/add",
                       data={"name": "DupTask", "hc_attackmode": "0", "wl_id": "", "from_modal": "1"},
                       follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert _no_flashes(client)
    body = client.get("/tasks").get_data(as_text=True)
    assert "That task name is taken" in body
    assert "add-task-modal" in body


def test_tasks_add_standalone_page_still_rerenders_on_error(app, client):
    """A submit WITHOUT from_modal (the legacy standalone page / e2e path) keeps
    re-rendering the standalone page — it must NOT hijack into the modal flow."""
    admin = _admin_client(app, client)
    db.session.add(Tasks(name="DupTask", hc_attackmode=0, owner_id=admin.id))
    db.session.commit()
    resp = client.post("/tasks/add",
                       data={"name": "DupTask", "hc_attackmode": "0", "wl_id": ""},
                       follow_redirects=False)
    assert resp.status_code == 200                       # standalone re-render, not a redirect
    with client.session_transaction() as sess:
        assert not sess.get("tasks_form_err")            # modal flow not triggered


# --- task_groups (modal + legacy standalone page) --------------------------

def test_task_groups_add_modal_duplicate_shows_error_in_modal(app, client):
    admin = _admin_client(app, client)
    db.session.add(TaskGroups(name="DupGrp", owner_id=admin.id, tasks="[]"))
    db.session.commit()
    resp = client.post("/task_groups/add",
                       data={"name": "DupGrp", "task_ids": "", "from_modal": "1"},
                       follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert _no_flashes(client)
    body = client.get("/task_groups").get_data(as_text=True)
    assert "That task group name is taken" in body
    assert "new-group-modal" in body


# --- rules (modal + legacy standalone page) --------------------------------

def test_rules_add_modal_missing_file_shows_error_in_modal(app, client):
    _admin_client(app, client)
    resp = client.post("/rules/add", data={"from_modal": "1"}, follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert _no_flashes(client)
    body = client.get("/rules").get_data(as_text=True)
    assert "Please choose a .rule file" in body
    assert "upload-rule-modal" in body
    assert Rules.query.count() == 0
