"""Flask routes to handle Rules"""
import csv
import io

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import login_required

from hashview import jinja_hex_decode
from hashview.models import Customers, Hashes, HashfileHashes, Hashfiles, db
from hashview.searches.forms import SearchForm

searches = Blueprint('searches', __name__)

@searches.route("/search", methods=['GET', 'POST'])
@login_required
def searches_list():
    """Function to return list of search results"""

    customers = Customers.query.all()
    hashfiles = Hashfiles.query.all()
    searchForm = SearchForm()
    redacted_data = False
    hash_results = None
    hashfile_results = None

    # TODO
    # We should be able to include Customers and Hashfiles in the following queries
    if searchForm.validate_on_submit():
        if searchForm.search_type.data == 'hash':
            print(f"[DEBUG] {searchForm.query.data}")
            # can be found in hashfiles, or not, or both?
            hash_results = db.session.query(Hashes).filter(Hashes.ciphertext==searchForm.query.data).all()
            hashfile_results = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.ciphertext==searchForm.query.data).all()
        elif searchForm.search_type.data == 'user':
            hashfile_results = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(HashfileHashes.username.like('%' + searchForm.query.data + '%')).all()
        elif searchForm.search_type.data == 'password':
            hash_results = db.session.query(Hashes).filter(Hashes.plaintext == searchForm.query.data).all()
            hashfile_results = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.plaintext == searchForm.query.data).all()
        else:
            flash('Invalid search option.', 'warning')
            return redirect(url_for('searches.searches_list'))
        
        if not hash_results and not hashfile_results:
            flash('No results found.', 'warning')

    elif request.args.get("hash_id"):
        hashfile_results = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id == HashfileHashes.hash_id).filter(Hashes.id == request.args.get("hash_id"))
        if(hashfile_results.first()): #Without a value in the search input the export button will not pass the form validation
            searchForm.query.data = hashfile_results.first()[0].ciphertext #All hashs should be the same, so set the search input as the first rows hash value
            searchForm.search_type.data = 'hash' #Set the search type to hash
        else:
            hashfile_results = db.session.query(Hashes).filter(Hashes.id == request.args.get("hash_id")).all() #This is a hack to get the hash id to show up in the result
            redacted_data = True #This is a hack to get the hash id to show up in the result 
        if not hashfile_results:
            flash('No results found.', 'warning')
    else:
        customers = None

    # Export Results — the per-table "Export CSV" buttons submit the search form with
    # name="export" and value "hash" / "hashfile" to export that specific table.
    if "export" in request.form:
        export_target = request.form.get('export')
        if export_target == 'hash' and hash_results:
            return export_results(hash_results, 'hash')
        if export_target == 'hashfile' and hashfile_results:
            return export_results(hashfile_results, 'hashfile', customers=customers, hashfiles=hashfiles)

    return render_template('search.html.j2', title='Search', searchForm=searchForm, customers=customers, hash_results=hash_results, hashfile_results=hashfile_results, hashfiles=hashfiles, redacted_data=redacted_data)

#Creating this in memory instead of on disk to avoid any extra cleanup. This can be changed later if files get too large
def export_results(results, kind, customers=None, hashfiles=None):
    """Export search results as a downloadable CSV.

    `kind` selects the column layout, matching the two on-screen tables in
    search.html.j2:
      * 'hash'     - plain Hashes rows (Recovered At, Hash Type, Cipher Text, Plain Text)
      * 'hashfile' - (Hashes, HashfileHashes) tuples (Customer, Username, Hash, Plain Text)
    """
    str_io = io.StringIO()
    get_rows(str_io, results, kind, customers, hashfiles)
    byte_io = io.BytesIO(str_io.getvalue().encode())
    str_io.close()
    byte_io.seek(0)
    return send_file(byte_io, mimetype='text/csv',
                     download_name=f'search_{kind}.csv', as_attachment=True)

#If this logic changes in the html (search.html.j2) it will need to change here as well
def get_rows(str_io, results, kind, customers, hashfiles):
    """Write the search results to `str_io` as CSV rows (comma-delimited)."""
    writer = csv.writer(str_io)
    if kind == 'hash':
        writer.writerow(['Recovered At', 'Hash Type', 'Cipher Text', 'Plain Text'])
        for entry in results:
            if entry.cracked:
                recovered = entry.recovered_at if entry.recovered_at else 'Before Jan 1st 2025'
                plaintext = jinja_hex_decode(entry.plaintext)
            else:
                recovered = 'unrecovered'
                plaintext = 'unrecovered'
            writer.writerow([recovered, entry.hash_type, entry.ciphertext, plaintext])
    else:
        writer.writerow(['Customer', 'Username', 'Hash', 'Plain Text'])
        for entry in results:
            customer_name = 'None'
            for hashfile in hashfiles:
                if hashfile.id == entry[1].hashfile_id:
                    for customer in customers:
                        if customer.id == hashfile.customer_id:
                            customer_name = customer.name
            username = jinja_hex_decode(entry[1].username) if entry[1].username else 'None'
            plaintext = jinja_hex_decode(entry[0].plaintext) if entry[0].cracked else 'unrecovered'
            writer.writerow([customer_name, username, entry[0].ciphertext, plaintext])
    return str_io
