from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required
from hashview.models import Customers
from hashview.customers.forms import CustomersForm
from hashview import db

customers = Blueprint('customers', __name__)

#############################################
# Customers
#############################################

@customers.route("/customers", methods=['GET'])
@login_required
def customers():
    customers = Customers.query.all()
    return render_template('customers.html', title='Cusomters', customers=customers)

@customers.route("/customers/add", methods=['GET', 'POST'])
@login_required
def customers_add():
    form = CustomersForm()
    if form.validate_on_submit():
        customer = Customers(name=form.name.data)
        db.session.add(customer)
        db.session.commit()
        flash(f'Customer created!', 'success')
        return redirect(url_for('customers'))  # will need to do a conditional return if this was reated during a job creation
    return render_template('cusomers_add.html', title='Customer Add', form=form)   

@customers.route("/customers/delete/<int:customer_id>", methods=['POST'])
@login_required
def customers_delete(customer_id):
    customer = Customers.query.get_or_404(customer_id)
    #if post.author != current_user:  #confirm if admin
    #    abort(403)
    db.session.delete(customer)
    db.session.commit()
    flash('Customer has been deleted!', 'success')
    return redirect(url_for('customers'))