from flask import Blueprint, jsonify, render_template, request
from flask_login import login_required
from hashview.models import Agents, Customers, HashfileHashes, Hashes, Hashfiles
from hashview import db
import re

# TODO
# This whole things is a mess


analytics = Blueprint('analytics', __name__)


@analytics.route('/analytics', methods=['GET'])
@login_required
def get_analytics():

    if request.args.get("customer_id"):
        customer_id = request.args["customer_id"]
    else:
        customer_id = None
    if request.args.get("hashfile_id"):
        hashfile_id = request.args["hashfile_id"]
    else:
        hashfile_id = None

    customers = Customers.query.all()
    hashfiles = Hashfiles.query.all()


    # Figure 1 (Cracked vs uncracked)
    if customer_id:
        # we have a customer
        if hashfile_id:
            fig1_cracked_cnt = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==hashfile_id).count()
            fig1_uncracked_cnt = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '0').filter(HashfileHashes.hashfile_id==hashfile_id).count()
        else:
            # just a customer, no specific hashfile
            fig1_cracked_cnt = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).outerjoin(Hashfiles, HashfileHashes.hashfile_id==Hashfiles.id).filter(Hashfiles.customer_id == customer_id).filter(Hashes.cracked == '1').count()
            fig1_uncracked_cnt = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).outerjoin(Hashfiles, HashfileHashes.hashfile_id==Hashfiles.id).filter(Hashfiles.customer_id == customer_id).filter(Hashes.cracked == '0').count()
    else:
        fig1_cracked_cnt = db.session.query(Hashes).filter(Hashes.cracked=='1').count()
        fig1_uncracked_cnt = db.session.query(Hashes).filter(Hashes.cracked=='0').count()
    
    fig1_data = [
        ("cracked: " + str(fig1_cracked_cnt), fig1_cracked_cnt),
        ("uncracked: " + str(fig1_uncracked_cnt), fig1_uncracked_cnt)
    ]

    fig1_labels = [row[0] for row in fig1_data]
    fig1_values = [row[1] for row in fig1_data]


    # Figure 2 (Cracked Complexity Breakdown)
    if customer_id:
        # we have a customer
        if hashfile_id:
            fig2_cracked_hashes = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==hashfile_id).all()
            fig2_uncracked_cnt = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '0').filter(HashfileHashes.hashfile_id==hashfile_id).count()
        else:
            # just a customer, no specific hashfile
            fig2_cracked_hashes = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).outerjoin(Hashfiles, HashfileHashes.hashfile_id==Hashfiles.id).filter(Hashfiles.customer_id == customer_id).filter(Hashes.cracked == '1').all()
            fig2_uncracked_cnt = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).outerjoin(Hashfiles, HashfileHashes.hashfile_id==Hashfiles.id).filter(Hashfiles.customer_id == customer_id).filter(Hashes.cracked == '0').count()
    else:
        fig2_cracked_hashes = db.session.query(Hashes).filter(Hashes.cracked=='1').all()
        fig2_uncracked_cnt = db.session.query(Hashes).filter(Hashes.cracked=='0').count()
    
    fig2_fails_complexity_cnt = 0
    fig2_meets_complexity_cnt = 0

    for entry in fig2_cracked_hashes:
        flags = 0
        if len(entry.plaintext) < 9:
            fig2_fails_complexity_cnt = fig2_fails_complexity_cnt + 1
        if re.search(r"[a-z]", entry.plaintext):
            flags = flags + 1
        if re.search(r"[A-Z]", entry.plaintext):
            flags = flags + 1
        if re.search(r"[0-9]", entry.plaintext):
            flags = flags + 1
        if not re.search(r"[^0-9A-Za-z]", entry.plaintext):
            flags = flags + 1
        if flags < 3:
            fig2_fails_complexity_cnt = fig2_fails_complexity_cnt + 1
        else:
            fig2_meets_complexity_cnt = fig2_meets_complexity_cnt + 1
        print(entry.plaintext)
    
    fig2_data = [
        ("Fails Complexity: " + str(fig2_fails_complexity_cnt), fig2_fails_complexity_cnt),
        ("Meets Complexity: " + str(fig2_meets_complexity_cnt), fig2_meets_complexity_cnt),
        ("Uncracked: " + str(fig2_uncracked_cnt), fig2_uncracked_cnt)
    ]

    fig2_labels = [row[0] for row in fig2_data]
    fig2_values = [row[1] for row in fig2_data]


    return render_template('analytics.html', 
                            title='analytics', 
                            fig1_labels=fig1_labels, 
                            fig1_values=fig1_values,
                            fig2_labels=fig2_labels,
                            fig2_values=fig2_values, 
                            customers=customers, hashfiles=hashfiles, hashfile_id=hashfile_id, customer_id=customer_id)


@analytics.route('/analytics/graph/TotalHashesCracked', methods=['GET'])
@login_required
def get_analytics_total_hashes_cracked():

    message = {
        'results': [27, 73]
    }


    return jsonify(message)