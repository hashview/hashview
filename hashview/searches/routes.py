from flask import Blueprint, render_template, redirect, url_for, request
from flask_login import login_required
from hashview.searches.forms import SearchForm
from hashview.models import Customers, Hashfiles, HashfileHashes, Hashes
from hashview import db

searches = Blueprint('searches', __name__)

@searches.route("/search", methods=['GET', 'POST'])
@login_required
def searches_list():
    customers = Customers.query.all()
    hashfiles = Hashfiles.query.all()
    searchForm = SearchForm()
    # TODO
    # We should be able to include Customers and Hashfiles in the following queries
    if searchForm.validate_on_submit():
        if searchForm.search_type.data == 'hash':
            results = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.ciphertext==searchForm.query.data).all()
        elif searchForm.search_type.data == 'user':
            results = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(HashfileHashes.username.like('%' + searchForm.query.data + '%')).all()
        elif searchForm.search_type.data == 'password':
            results = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.plaintext == searchForm.query.data).all()
        else:
            return redirect(url_for('searches.searches_list'))
    elif request.args.get("hash_id"):
        results = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id == HashfileHashes.hash_id).filter(Hashes.id == request.args.get("hash_id"))
    else:
        customers = None
        results = None
        
    return render_template('search.html', title='Search', searchForm=searchForm, customers=customers, results=results, hashfiles=hashfiles )