"""Flask routes to handle Customers"""
from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required
from sqlalchemy import case, func

from hashview.customers.forms import CustomersForm
from hashview.jobs.forms import JobsNewHashFileForm
from hashview.models import (
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    HashNotifications,
    Jobs,
    db,
)
from hashview.utils.audit import log_event
from hashview.utils.utils import try_commit


def _hash_type_names():
    """Reverse-map hashcat modes -> friendly names from the new-hashfile form choices."""
    names = {}
    try:
        f = JobsNewHashFileForm()
        for sel in (f.hash_type, f.pwdump_hash_type, f.netntlm_hash_type,
                    f.kerberos_hash_type, f.shadow_hash_type):
            for v, lab in sel.choices:
                if v is not None and str(v) and str(v).isdigit() and str(v) not in names:
                    nm = lab.split(') ', 1)[1] if ') ' in lab else lab
                    names[str(v)] = nm.split(' / ')[0].split(',')[0].strip()
    except Exception:  # pragma: no cover - defensive
        names = {}
    return names

customers = Blueprint('customers', __name__)

#############################################
# Customers
#############################################

@customers.route("/customers", methods=['GET'])
@login_required
def customers_list():
    """Function to return list of customers"""
    customers = Customers.query.order_by(Customers.name).all()

    # Per-customer counts + recovered % (cracked/total across the customer's
    # hashfiles), as four set-based queries that are flat in customer count.
    #
    # This was one COUNT+SUM(CASE) aggregate per customer, joining `hashes` to
    # `hashfile_hashes`. Its cost scaled with the whole junction table rather
    # than with the page, because ~94% of each query was a clustered-index
    # probe into `hashes` to read the single `cracked` boolean.
    #
    # The two hash aggregates are deliberately kept SEPARATE rather than folded
    # into one grouped query: `total` is then index-only over
    # ix_hashfile_hashes_hashfile_id and never reads `hashes` at all, and
    # `cracked` drives off ix_hashes_cracked_recovered_at so it scales with the
    # recovered population instead of total hash volume. A single grouped
    # COUNT+SUM(CASE) measured *slower* than the per-customer loop it would
    # replace -- it still joins every junction row to `hashes` and cannot use
    # the cracked index. Don't "simplify" these back into one query.
    job_count = dict(
        db.session.query(Jobs.customer_id, func.count(Jobs.id))
        .group_by(Jobs.customer_id).all()
    )
    hf_count = dict(
        db.session.query(Hashfiles.customer_id, func.count(Hashfiles.id))
        .group_by(Hashfiles.customer_id).all()
    )
    # Counting junction rows equals the old COUNT over joined `hashes` rows
    # because every hashfile_hashes row references a live hash: both delete
    # paths (_cascade_delete_hashfile, customers_delete) remove the junction
    # row together with, or ahead of, the hash it points at.
    totals = dict(
        db.session.query(Hashfiles.customer_id, func.count(HashfileHashes.id))
        .join(HashfileHashes, HashfileHashes.hashfile_id == Hashfiles.id)
        .group_by(Hashfiles.customer_id).all()
    )
    cracked_counts = dict(
        db.session.query(Hashfiles.customer_id, func.count(Hashes.id))
        .join(HashfileHashes, HashfileHashes.hashfile_id == Hashfiles.id)
        .join(Hashes, Hashes.id == HashfileHashes.hash_id)
        .filter(Hashes.cracked == True)
        .group_by(Hashfiles.customer_id).all()
    )

    # .get(id, 0) throughout: a customer with no hashfiles -- or none cracked --
    # has no row in the corresponding result and must still render as 0.
    customer_stats = {}
    for customer in customers:
        total = int(totals.get(customer.id, 0))
        cracked = int(cracked_counts.get(customer.id, 0))
        customer_stats[customer.id] = {
            'jobs': job_count.get(customer.id, 0),
            'hashfiles': hf_count.get(customer.id, 0),
            'total': total,
            'cracked': cracked,
            'pct': round(cracked / total * 100) if total else 0,
        }

    return render_template('customers.html.j2', title='Customers', customers=customers,
                           customer_stats=customer_stats,
                           customersForm=CustomersForm(),
                           form_err=session.pop('customers_form_err', None))

@customers.route("/customers/add", methods=['POST'])
@login_required
def customers_add():
    """Create a new customer (from the Add customer modal)."""
    form = CustomersForm()
    if form.validate_on_submit():
        customer = Customers(name=form.name.data)
        db.session.add(customer)
        db.session.commit()
        log_event('customer.create', target=f'customer:{customer.id} {customer.name!r}')
        flash(f'Customer {form.name.data} added!', 'success')
        return redirect(url_for('customers.customers_list'))
    # Validation failed — reopen the Add modal on the listing with the error
    # shown inside it and the typed name preserved (not a flash over the listing).
    session['customers_form_err'] = {
        'modal': 'add-customer-modal',
        'values': {'name': form.name.data or ''},
        'errors': [e for errs in form.errors.values() for e in errs],
    }
    return redirect(url_for('customers.customers_list'))

@customers.route("/customers/edit", methods=['POST'])
@login_required
def customers_edit():
    """Rename an existing customer (from the Edit customer modal)."""
    customer = Customers.query.get(request.form.get('customer_id', type=int))
    if customer is None:
        flash('Customer not found — it may have already been deleted.', 'warning')
        return redirect(url_for('customers.customers_list'))
    name = (request.form.get('name') or '').strip()

    def _edit_error(message):
        # Reopen the Edit modal for this customer with the error inside it.
        session['customers_form_err'] = {
            'modal': 'edit-customer-modal',
            'values': {'name': name, 'customer_id': customer.id},
            'errors': [message],
        }
        return redirect(url_for('customers.customers_list'))

    if not name:
        return _edit_error('Customer name is required.')
    clash = Customers.query.filter_by(name=name).first()
    if clash and clash.id != customer.id:
        return _edit_error('That customer already exists. Please choose a different one.')
    customer.name = name
    db.session.commit()
    log_event('customer.edit', target=f'customer:{customer.id} {customer.name!r}')
    flash('Customer updated!', 'success')
    return redirect(url_for('customers.customers_list'))

@customers.route("/customers/<int:customer_id>/info", methods=['GET'])
@login_required
def customers_info(customer_id):
    """Render the customer info modal body on demand (computed for one customer only, so
    the customers list page doesn't pay the per-hashfile aggregation cost for everyone)."""
    customer = Customers.query.get_or_404(customer_id)
    cust_jobs = Jobs.query.filter_by(customer_id=customer_id).all()
    cust_hashfiles = Hashfiles.query.filter_by(customer_id=customer_id).all()
    hash_type_names = _hash_type_names()

    hf_stats = {}
    for hf in cust_hashfiles:
        agg = db.session.query(
            func.count(Hashes.id),
            func.coalesce(func.sum(case((Hashes.cracked == True, 1), else_=0)), 0),
            func.min(Hashes.hash_type)
        ).join(HashfileHashes, Hashes.id == HashfileHashes.hash_id) \
         .filter(HashfileHashes.hashfile_id == hf.id).first()
        total = agg[0] or 0
        cracked = int(agg[1] or 0)
        mode = agg[2]
        hf_stats[hf.id] = {
            'total': total,
            'cracked': cracked,
            'pct': round(cracked / total * 100) if total else 0,
            'type': hash_type_names.get(str(mode), str(mode)) if mode is not None else '—',
        }

    total_hashes = sum(s['total'] for s in hf_stats.values())
    total_cracked = sum(s['cracked'] for s in hf_stats.values())
    pct = round(total_cracked / total_hashes * 100) if total_hashes else 0
    return render_template('customers_info_modal.html.j2', customer=customer, cust_jobs=cust_jobs,
                           cust_hashfiles=cust_hashfiles, hf_stats=hf_stats,
                           total_hashes=total_hashes, total_cracked=total_cracked, pct=pct)

@customers.route("/customers/delete/<int:customer_id>", methods=['POST'])
@login_required
def customers_delete(customer_id):
    """Function to delete a customer"""
    customer = Customers.query.get(customer_id)
    if customer is None:
        flash('Customer not found — it may have already been deleted.', 'warning')
        return redirect(url_for('customers.customers_list'))
    customer_target = f'customer:{customer.id} {customer.name!r}'
    if not current_user.admin:
        flash('Permission Denied', 'danger')
        return redirect(url_for('customers.customers_list'))
    # Don't delete a customer that still has jobs (previously this flashed the
    # warning but then deleted the customer anyway).
    if Jobs.query.filter_by(customer_id=customer_id).first():
        flash('Unable to delete. Customer has active job', 'danger')
        return redirect(url_for('customers.customers_list'))

    # remove associated hash files & hashes & Hash Notifications
    hashfiles = Hashfiles.query.filter_by(customer_id=customer_id)
    for hashfile in hashfiles:
        hashfile_hashes = HashfileHashes.query.filter_by(hashfile_id = hashfile.id).all()
        for hashfile_hash in hashfile_hashes:
            hashes = Hashes.query.filter_by(id=hashfile_hash.hash_id, cracked=0).all()
            for hash in hashes:
                # Check to see if our hashfile is the ONLY hashfile for this customer that has this hash
                customer_cnt = HashfileHashes.query.filter_by(hash_id=hash.id).distinct('customer_id').count()
                if customer_cnt < 2:
                    db.session.delete(hash)
                    HashNotifications.query.filter_by(hash_id=hashfile_hash.hash_id).delete()
            db.session.delete(hashfile_hash)
        db.session.delete(hashfile)
    db.session.delete(customer)
    if not try_commit(f'delete customer {customer_id}'):
        flash('Customer could not be deleted — it may have already been removed.', 'danger')
        return redirect(url_for('customers.customers_list'))
    log_event('customer.delete', target=customer_target)
    flash('Customer has been deleted!', 'success')
    return redirect(url_for('customers.customers_list'))
