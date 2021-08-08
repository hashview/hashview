from flask import Blueprint, jsonify, render_template, request, redirect, send_from_directory
from flask_login import login_required
from hashview.models import Agents, Customers, HashfileHashes, Hashes, Hashfiles
from hashview import db
import re
import operator

# TODO
# This whole things is a mess
# Each graph should be its own route


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
        if hashfile_id: # with a hashfile
            fig1_cracked_cnt = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==hashfile_id).count()
            fig1_uncracked_cnt = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '0').filter(HashfileHashes.hashfile_id==hashfile_id).count()
        else:
            # just a customer, no specific hashfile
            fig1_cracked_cnt = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).outerjoin(Hashfiles, HashfileHashes.hashfile_id==Hashfiles.id).filter(Hashfiles.customer_id == customer_id).filter(Hashes.cracked == '1').count()
            fig1_uncracked_cnt = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).outerjoin(Hashfiles, HashfileHashes.hashfile_id==Hashfiles.id).filter(Hashfiles.customer_id == customer_id).filter(Hashes.cracked == '0').count()
    else:
        fig1_cracked_cnt = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked=='1').count()
        fig1_uncracked_cnt = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked=='0').count()
    
    fig1_data = [
        ("Recovered: " + str(fig1_cracked_cnt), fig1_cracked_cnt),
        ("Unrecovered: " + str(fig1_uncracked_cnt), fig1_uncracked_cnt)
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
        fig2_cracked_hashes = db.session.query(Hashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked=='1').all()
        fig2_uncracked_cnt = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked=='0').count()
    
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
    
    fig2_data = [
        ("Fails Complexity: " + str(fig2_fails_complexity_cnt), fig2_fails_complexity_cnt),
        ("Meets Complexity: " + str(fig2_meets_complexity_cnt), fig2_meets_complexity_cnt),
        ("Unrecovered: " + str(fig2_uncracked_cnt), fig2_uncracked_cnt)
    ]

    fig2_labels = [row[0] for row in fig2_data]
    fig2_values = [row[1] for row in fig2_data]

    # General Stats Table
    total_runtime = 0
    total_accounts = 0
    total_unique_hashes = 0
    if customer_id:
        # we have a customer
        if hashfile_id:
            hashfile = Hashfiles.query.get(hashfile_id)
            total_runtime = hashfile.runtime
            total_accounts = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(HashfileHashes.hashfile_id==hashfile_id).count()
            total_unique_hashes = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(HashfileHashes.hashfile_id==hashfile_id).distinct('ciphertext').count()
        else:
            # just a customer, no specific hashfile
            hashfiles = Hashfiles.query.filter_by(customer_id=customer_id).all()
            for hashfile in hashfiles:
                total_runtime = total_runtime + hashfile.runtime
            total_accounts = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).outerjoin(Hashfiles, HashfileHashes.hashfile_id==Hashfiles.id).filter(Hashfiles.customer_id == customer_id).count()
            total_unique_hashes = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).outerjoin(Hashfiles, HashfileHashes.hashfile_id==Hashfiles.id).filter(Hashfiles.customer_id == customer_id).distinct('ciphertext').count()
    else:
        hashfiles = Hashfiles.query.all()
        for hashfile in hashfiles:
            total_runtime = total_runtime + hashfile.runtime
        total_accounts = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).count()
        total_unique_hashes = db.session.query(Hashes).count()


    # Figure 3 (Charset Breakdown)
    # Reusing fig2_cracked_hashes data

    numeric = 0
    loweralpha = 0
    upperalpha = 0
    special = 0

    mixedalpha = 0
    loweralphanum = 0
    upperalphanum = 0
    loweralphaspecial = 0
    upperalphaspecial = 0
    specialnum = 0

    mixedalphaspecial = 0
    upperalphaspecialnum = 0
    loweralphaspecialnum = 0
    mixedalphaspecialnum = 0

    other = 0

    for entry in fig2_cracked_hashes:
        tmp_plaintext = entry.plaintext
        tmp_plaintext = re.sub(r"[A-Z]", 'U', tmp_plaintext)
        tmp_plaintext = re.sub(r"[a-z]", 'L', tmp_plaintext)
        tmp_plaintext = re.sub(r"[0-9]", 'D', tmp_plaintext)
        tmp_plaintext = re.sub(r"[^0-9A-Za-z]", 'S', tmp_plaintext)

        if not re.search("U", tmp_plaintext) and not re.search("L", tmp_plaintext) and re.search("D", tmp_plaintext) and not re.search("S", tmp_plaintext):
            numeric += 1
        elif not re.search("U", tmp_plaintext) and re.search("L", tmp_plaintext) and not re.search("D", tmp_plaintext) and not re.search("S", tmp_plaintext):
            loweralpha += 1
        elif re.search("U", tmp_plaintext) and not re.search("L", tmp_plaintext) and not re.search("D", tmp_plaintext) and not re.search("S", tmp_plaintext):
            upperalpha += 1
        elif not re.search("U", tmp_plaintext) and not re.search("L", tmp_plaintext) and not re.search("D", tmp_plaintext) and re.search("S", tmp_plaintext):
            special += 1 
        elif re.search("U", tmp_plaintext) and re.search("L", tmp_plaintext) and not re.search("D", tmp_plaintext) and not re.search("S", tmp_plaintext):
            mixedalpha += 1
        elif not re.search("U", tmp_plaintext) and re.search("L", tmp_plaintext) and re.search("D", tmp_plaintext) and not re.search("S", tmp_plaintext):
            loweralphanum += 1
        elif re.search("U", tmp_plaintext) and not re.search("L", tmp_plaintext) and re.search("D", tmp_plaintext) and not re.search("S", tmp_plaintext):
            upperalphanum += 1
        elif not re.search("U", tmp_plaintext) and re.search("L", tmp_plaintext) and not re.search("D", tmp_plaintext) and re.search("S", tmp_plaintext):
            loweralphaspecial += 1
        elif re.search("U", tmp_plaintext) and not re.search("L", tmp_plaintext) and not re.search("D", tmp_plaintext) and re.search("S", tmp_plaintext):
            upperalphaspecial += 1
        elif not re.search("U", tmp_plaintext) and not re.search("L", tmp_plaintext) and re.search("D", tmp_plaintext) and re.search("S", tmp_plaintext):
            specialnum += 1
        elif re.search("U", tmp_plaintext) and re.search("L", tmp_plaintext) and not re.search("D", tmp_plaintext) and re.search("S", tmp_plaintext):
            mixedalphaspecial += 1
        elif re.search("U", tmp_plaintext) and not re.search("L", tmp_plaintext) and re.search("D", tmp_plaintext) and re.search("S", tmp_plaintext):
            upperalphaspecialnum += 1
        elif not re.search("U", tmp_plaintext) and re.search("L", tmp_plaintext) and re.search("D", tmp_plaintext) and re.search("S", tmp_plaintext):
            loweralphaspecialnum += 1
        elif re.search("U", tmp_plaintext) and re.search("L", tmp_plaintext) and re.search("D", tmp_plaintext) and re.search("S", tmp_plaintext):
            mixedalphaspecialnum += 1
        else:
            other += 1

    fig3_labels = []
    fig3_values = []

    # We only want the top 4 with the 5th being other
    fig3_dict = {
        "Numeric Only": numeric, 
        "LowerAlpha Only": loweralpha, 
        "UpperAlpha Only": upperalpha, 
        "Special Only": special, 
        "MixedAlpha": mixedalpha, 
        "LowerAlphaNumeric": loweralphanum, 
        "LowerAlphaSpecial": loweralphaspecial, 
        "UpperAlphaSpecial": upperalphaspecial, 
        "SpecialNumeric": specialnum, 
        "MixedAlphaSpecial": mixedalphaspecial, 
        "UpperAlphaSpecialNumeric": upperalphaspecialnum, 
        "LowerAlphaSpecialNumeric": loweralphaspecialnum, 
        "MixedAlphaSpecialNumeric": mixedalphaspecialnum
        }

    fig3_array_sorted = dict(sorted(fig3_dict.items(), key=operator.itemgetter(1),reverse=True))

    limit = 0
    fig3_other = 0
    for key in fig3_array_sorted:
        if limit <= 3:
            fig3_labels.append(key)
            fig3_values.append(fig3_array_sorted[key])
            limit += 1
        else:
            fig3_other += fig3_array_sorted[key]

    fig3_labels.append('Other')
    fig3_values.append(fig3_other)

    # Figure 4 (Passwords by Length)
    if customer_id:
        # we have a customer
        if hashfile_id:
            fig4_cracked_hashes = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==hashfile_id).all()
        else:
            # just a customer, no specific hashfile
            fig4_cracked_hashes = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).outerjoin(Hashfiles, HashfileHashes.hashfile_id==Hashfiles.id).filter(Hashfiles.customer_id == customer_id).filter(Hashes.cracked == '1').all()
    else:
        fig4_cracked_hashes = db.session.query(Hashes).filter(Hashes.cracked=='1').all()

    fig4_data = {}

    for entry in fig4_cracked_hashes:
        if len(entry.plaintext) > 0:
            if len(entry.plaintext) in fig4_data:
                fig4_data[len(entry.plaintext)] += 1
            else:
                fig4_data[len(entry.plaintext)] = 1

    fig4_labels =[]
    fig4_values = []


    # Sort by length and limit to 20
    for entry in sorted(fig4_data):
        if len(fig4_labels) < 20:
            fig4_labels.append(entry)
            fig4_values.append(fig4_data[entry])
        else:
            break


    # Figure 5 (Top 10 Passwords)
    if customer_id:
        # we have a customer
        if hashfile_id:
            fig5_cracked_hashes = db.session.query(Hashes, HashfileHashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==hashfile_id).all()
        else:
            # just a customer, no specific hashfile
            fig5_cracked_hashes = db.session.query(Hashes, HashfileHashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).outerjoin(Hashfiles, HashfileHashes.hashfile_id==Hashfiles.id).filter(Hashfiles.customer_id == customer_id).filter(Hashes.cracked == '1').all()
    else:
        fig5_cracked_hashes = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked=='1').all()

    fig5_data = {}

    for entry in fig5_cracked_hashes:
        if len(entry[0].plaintext) > 0:
            if entry[0].plaintext in fig5_data:
                fig5_data[entry[0].plaintext] += 1
            else:
                fig5_data[entry[0].plaintext] = 1

    fig5_labels =[]
    fig5_values = []

    # Sort by Highest and Limit to 10
    for entry in sorted(fig5_data, key=fig5_data.__getitem__, reverse=True):
        if len (fig5_labels) < 10:
            fig5_labels.append(entry)
            fig5_values.append(fig5_data[entry])
        else:
            break


    return render_template('analytics.html', 
                            title='analytics', 
                            fig1_labels=fig1_labels, 
                            fig1_values=fig1_values,
                            fig2_labels=fig2_labels,
                            fig2_values=fig2_values, 
                            fig3_labels=fig3_labels,
                            fig3_values=fig3_values,
                            fig4_labels=fig4_labels,
                            fig4_values=fig4_values,
                            fig5_labels=fig5_labels,
                            fig5_values=fig5_values,
                            customers=customers, 
                            hashfiles=hashfiles, 
                            hashfile_id=hashfile_id, 
                            customer_id=customer_id,
                            total_runtime=total_runtime,
                            total_accounts=total_accounts,
                            total_unique_hashes=total_unique_hashes)

# serve a list of cracks
@analytics.route('/analytics/download', methods=['GET'])
@login_required
def analytics_download_hashes():

    filename = ''

    if request.args.get('type') == 'found':
        filename += 'found'
    elif request.args.get('type') == 'left':
        filename += 'left'
    else:
        redirect('/analytics')

    if request.args.get("customer_id"):
        customer_id = request.args["customer_id"]
        filename += '_' + customer_id
    else:
        customer_id = None
    if request.args.get("hashfile_id"):
        hashfile_id = request.args["hashfile_id"]
        filename += '_' + customer_id
    else:
        hashfile_id = None
        filename += '_all'
    
    filename += '.txt'

    if customer_id:
        # we have a customer
        if hashfile_id:
            cracked_hashes = db.session.query(Hashes, HashfileHashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==hashfile_id).all()
            uncracked_hashes = db.session.query(Hashes, HashfileHashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '0').filter(HashfileHashes.hashfile_id==hashfile_id).all()
        else:
            # just a customer, no specific hashfile
            cracked_hashes = db.session.query(Hashes, HashfileHashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).outerjoin(Hashfiles, HashfileHashes.hashfile_id==Hashfiles.id).filter(Hashfiles.customer_id == customer_id).filter(Hashes.cracked == '1').all()
            uncracked_hashes = db.session.query(Hashes, HashfileHashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).outerjoin(Hashfiles, HashfileHashes.hashfile_id==Hashfiles.id).filter(Hashfiles.customer_id == customer_id).filter(Hashes.cracked == '0').all()
    else:
        cracked_hashes = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked=='1').all()
        uncracked_hashes = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked=='1').all()

    outfile = open('hashview/control/tmp/' + filename, 'w')

    if request.args.get('type') == 'found':
        for entry in cracked_hashes:
            outfile.write(str(entry[1].username) + ":" + str(entry[0].ciphertext) + ':' + str(entry[0].plaintext) + "\n")

    if request.args.get('type') == 'left':
        for entry in uncracked_hashes:
            outfile.write(str(entry[1].username) + ":" + str(entry[0].ciphertext) + "\n")
    
    outfile.close()
    return send_from_directory('control/tmp', filename, as_attachment=True)
