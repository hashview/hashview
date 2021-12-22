from flask import Blueprint, jsonify, render_template, request, redirect, send_from_directory
from flask_login import login_required
from hashview.models import Customers, HashfileHashes, Hashes, Hashfiles
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

    hashfiles, customers = [], []
    results =  db.session.query(Customers, Hashfiles).join(Hashfiles, Customers.id==Hashfiles.customer_id).order_by(Customers.name)

    #Put all hashes in a list (hashfiles) and pull out all unique customers into a separate list (customers)
    for rows in results:
        customers.append(rows.Customers) if rows.Customers not in customers else customers
        hashfiles.append(rows.Hashfiles)

    # Figure 1 (Cracked vs uncracked)
    if customer_id:
        # we have a customer
        if hashfile_id: # with a hashfile
            fig1_cracked_cnt = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==hashfile_id).count()
            fig1_uncracked_cnt = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '0').filter(HashfileHashes.hashfile_id==hashfile_id).count()
        else:
            # just a customer, no specific hashfile
            fig1_cracked_cnt = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).join(Hashfiles, HashfileHashes.hashfile_id==Hashfiles.id).filter(Hashfiles.customer_id == customer_id).filter(Hashes.cracked == '1').count()
            fig1_uncracked_cnt = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).join(Hashfiles, HashfileHashes.hashfile_id==Hashfiles.id).filter(Hashfiles.customer_id == customer_id).filter(Hashes.cracked == '0').count()
    else:
        fig1_cracked_cnt = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked=='1').count()
        fig1_uncracked_cnt = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked=='0').count()
    
    fig1_data = [
        ("Recovered: " + str(fig1_cracked_cnt), fig1_cracked_cnt),
        ("Unrecovered: " + str(fig1_uncracked_cnt), fig1_uncracked_cnt)
    ]

    fig1_labels = [row[0] for row in fig1_data]
    fig1_values = [row[1] for row in fig1_data]
    fig1_total = (fig1_cracked_cnt + fig1_uncracked_cnt)
    
    # Cracked Percent
    fig1_percent = 0 if fig1_total is 0 else [str(round(((fig1_cracked_cnt / fig1_total)*100),1)) + '%'] 

    # Figure 2 (Cracked Complexity Breakdown)
    if customer_id:
        # we have a customer
        if hashfile_id:
            fig2_cracked_hashes = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==hashfile_id).with_entities(Hashes.plaintext).all()
            fig2_uncracked_cnt = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '0').filter(HashfileHashes.hashfile_id==hashfile_id).count()
        else:
            # just a customer, no specific hashfile
            fig2_cracked_hashes = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).join(Hashfiles, HashfileHashes.hashfile_id==Hashfiles.id).filter(Hashfiles.customer_id == customer_id).filter(Hashes.cracked == '1').with_entities(Hashes.plaintext).all()
            fig2_uncracked_cnt = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).join(Hashfiles, HashfileHashes.hashfile_id==Hashfiles.id).filter(Hashfiles.customer_id == customer_id).filter(Hashes.cracked == '0').count()
    else:
        fig2_cracked_hashes = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked=='1').with_entities(Hashes.plaintext).all()
        fig2_uncracked_cnt = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked=='0').count()
    
    fig2_fails_complexity_cnt = 0
    fig2_meets_complexity_cnt = 0

    for entry in fig2_cracked_hashes:
        flags = 0
        if len(bytes.fromhex(entry[0]).decode('latin-1')) < 9:
            flags = 3
        if re.search(r"[a-z]", bytes.fromhex(entry[0]).decode('latin-1')):
            flags = flags + 1
        if re.search(r"[A-Z]", bytes.fromhex(entry[0]).decode('latin-1')):
            flags = flags + 1
        if re.search(r"[0-9]", bytes.fromhex(entry[0]).decode('latin-1')):
            flags = flags + 1
        if not re.search(r"[^0-9A-Za-z]", bytes.fromhex(entry[0]).decode('latin-1')):
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
            total_accounts = db.session.query(Hashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(HashfileHashes.hashfile_id==hashfile_id).count()
            total_unique_hashes = db.session.query(Hashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(HashfileHashes.hashfile_id==hashfile_id).distinct('ciphertext').count()
        else:
            # just a customer, no specific hashfile
            hashfiles = Hashfiles.query.filter_by(customer_id=customer_id).all()
            for hashfile in hashfiles:
                total_runtime = total_runtime + hashfile.runtime
            total_accounts = db.session.query(Hashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).join(Hashfiles, HashfileHashes.hashfile_id==Hashfiles.id).filter(Hashfiles.customer_id == customer_id).count()
            total_unique_hashes = db.session.query(Hashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).join(Hashfiles, HashfileHashes.hashfile_id==Hashfiles.id).filter(Hashfiles.customer_id == customer_id).distinct('ciphertext').count()
    else:
        hashfiles = Hashfiles.query.all()
        for hashfile in hashfiles:
            total_runtime = total_runtime + hashfile.runtime
        total_accounts = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).count()
        total_unique_hashes = db.session.query(Hashes).count()


    # Figure 3 (Charset Breakdown)
    # Reusing fig2_cracked_hashes data

    blank = 0

    numeric = 0
    loweralpha = 0
    upperalpha = 0
    special = 0

    mixedalpha = 0
    mixedalphanum = 0
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
        tmp_plaintext = bytes.fromhex(entry[0]).decode('latin-1')
        tmp_plaintext = re.sub(r"[A-Z]", 'U', tmp_plaintext)
        tmp_plaintext = re.sub(r"[a-z]", 'L', tmp_plaintext)
        tmp_plaintext = re.sub(r"[0-9]", 'D', tmp_plaintext)
        tmp_plaintext = re.sub(r"[^0-9A-Za-z]", 'S', tmp_plaintext)

        if len(tmp_plaintext) == 0:
            blank += 1
        elif not re.search("U", tmp_plaintext) and not re.search("L", tmp_plaintext) and re.search("D", tmp_plaintext) and not re.search("S", tmp_plaintext):
            numeric += 1
        elif not re.search("U", tmp_plaintext) and re.search("L", tmp_plaintext) and not re.search("D", tmp_plaintext) and not re.search("S", tmp_plaintext):
            loweralpha += 1
        elif re.search("U", tmp_plaintext) and not re.search("L", tmp_plaintext) and not re.search("D", tmp_plaintext) and not re.search("S", tmp_plaintext):
            upperalpha += 1
        elif not re.search("U", tmp_plaintext) and not re.search("L", tmp_plaintext) and not re.search("D", tmp_plaintext) and re.search("S", tmp_plaintext):
            special += 1 
        elif re.search("U", tmp_plaintext) and re.search("L", tmp_plaintext) and not re.search("D", tmp_plaintext) and not re.search("S", tmp_plaintext):
            mixedalpha += 1
        elif re.search("U", tmp_plaintext) and re.search("L", tmp_plaintext) and re.search("D", tmp_plaintext) and not re.search("S", tmp_plaintext):
            mixedalphanum += 1
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
        "Blank (unset): " + str(blank): blank,
        "Numeric Only: " + str(numeric) : numeric, 
        "LowerAlpha Only: " + str(loweralpha): loweralpha, 
        "UpperAlpha Only: " + str(upperalpha): upperalpha, 
        "Special Only: " + str(special): special, 
        "MixedAlpha: " + str(mixedalpha): mixedalpha, 
        "MixedAlphaNumeric: " +str(mixedalphanum): mixedalphanum,
        "LowerAlphaNumeric: " + str(loweralphanum): loweralphanum, 
        "LowerAlphaSpecial: " + str(loweralphaspecial): loweralphaspecial, 
        "UpperAlphaSpecial: " + str(upperalphaspecial): upperalphaspecial, 
        "SpecialNumeric: " + str(specialnum): specialnum, 
        "MixedAlphaSpecial: " + str(mixedalphaspecial): mixedalphaspecial, 
        "UpperAlphaSpecialNumeric: " + str(upperalphaspecialnum): upperalphaspecialnum, 
        "LowerAlphaSpecialNumeric: " + str(loweralphaspecialnum): loweralphaspecialnum, 
        "MixedAlphaSpecialNumeric: " + str(mixedalphaspecialnum): mixedalphaspecialnum,
        "Other: " + str(other): other, 
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

    fig3_labels.append('Other: ' + str(fig3_other))
    fig3_values.append(fig3_other)

    # Figure 4 (Passwords by Length)
    if customer_id:
        # we have a customer
        if hashfile_id:
            fig4_cracked_hashes = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==hashfile_id).with_entities(Hashes.plaintext).all()
        else:
            # just a customer, no specific hashfile
            fig4_cracked_hashes = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).join(Hashfiles, HashfileHashes.hashfile_id==Hashfiles.id).filter(Hashfiles.customer_id == customer_id).filter(Hashes.cracked == '1').with_entities(Hashes.plaintext).all()
    else:
        fig4_cracked_hashes = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked=='1').with_entities(Hashes.plaintext).all() 

    fig4_data = {}

    for entry in fig4_cracked_hashes:
        #print(str(entry))
        if len(bytes.fromhex(entry[0]).decode('latin-1')) in fig4_data:
            fig4_data[len(bytes.fromhex(entry[0]).decode('latin-1'))] += 1
        else:
            fig4_data[len(bytes.fromhex(entry[0]).decode('latin-1'))] = 1

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
            fig5_cracked_hashes = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==hashfile_id).with_entities(Hashes.plaintext).all()
        else:
            # just a customer, no specific hashfile
            fig5_cracked_hashes = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).join(Hashfiles, HashfileHashes.hashfile_id==Hashfiles.id).filter(Hashfiles.customer_id == customer_id).filter(Hashes.cracked == '1').with_entities(Hashes.plaintext).all()
    else:
        fig5_cracked_hashes = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked=='1').with_entities(Hashes.plaintext).all()

    fig5_data = {}

    blank_label = 'Blank (unset)'
    for entry in fig5_cracked_hashes:
        if len(bytes.fromhex(entry[0]).decode('latin-1')) > 0:
            if bytes.fromhex(entry[0]).decode('latin-1') in fig5_data:
                fig5_data[bytes.fromhex(entry[0]).decode('latin-1')] += 1
            else:
                fig5_data[bytes.fromhex(entry[0]).decode('latin-1')] = 1
        else:
            if blank_label in fig5_data:
                fig5_data[blank_label] += 1
            else:
                fig5_data[blank_label] = 1

    fig5_labels = []
    fig5_values = []

    # Sort by Highest and Limit to 10
    for entry in sorted(fig5_data, key=fig5_data.__getitem__, reverse=True):
        if len (fig5_labels) < 10:
            fig5_labels.append(entry)
            fig5_values.append(fig5_data[entry])
        else:
            break

    # Figure 6 (Top 10 Masks)
    # Using Fig 5 data for this
    fig6_values = {}
    fig6_data = {}
    fig6_total = 0
    for entry in fig5_cracked_hashes:
        tmp_plaintext = bytes.fromhex(entry[0]).decode('latin-1')
        tmp_plaintext = re.sub(r"[A-Z]", 'U', tmp_plaintext)
        tmp_plaintext = re.sub(r"[a-z]", 'L', tmp_plaintext)
        tmp_plaintext = re.sub(r"[0-9]", 'D', tmp_plaintext)
        tmp_plaintext = re.sub(r"[^0-9A-Za-z]", 'S', tmp_plaintext)
        # Shhh... i know this is ugly
        tmp_plaintext = re.sub(r"U", '?u', tmp_plaintext)
        tmp_plaintext = re.sub(r"L", '?l', tmp_plaintext)
        tmp_plaintext = re.sub(r"D", '?d', tmp_plaintext)
        tmp_plaintext = re.sub(r"S", '?s', tmp_plaintext)

        if tmp_plaintext not in fig6_data:
            fig6_data[tmp_plaintext] = 1
        else:
            fig6_data[tmp_plaintext] += 1
        fig6_total +=1

            # Sort by Highest and Limit to 10
    for entry in sorted(fig6_data, key=fig6_data.__getitem__, reverse=True):
        if len (fig6_values) < 10:
            fig6_values[entry] = fig6_data[entry]
        else:
            break


    return render_template('analytics.html', 
                            title='analytics', 
                            fig1_labels=fig1_labels, 
                            fig1_values=fig1_values,
                            fig1_percent=fig1_percent,
                            fig2_labels=fig2_labels,
                            fig2_values=fig2_values, 
                            fig3_labels=fig3_labels,
                            fig3_values=fig3_values,
                            fig4_labels=fig4_labels,
                            fig4_values=fig4_values,
                            fig5_labels=fig5_labels,
                            fig5_values=fig5_values,
                            fig6_values=fig6_values,
                            fig6_total=fig6_total,
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
            cracked_hashes = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==hashfile_id).all()
            uncracked_hashes = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '0').filter(HashfileHashes.hashfile_id==hashfile_id).all()
        else:
            # just a customer, no specific hashfile
            cracked_hashes = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).join(Hashfiles, HashfileHashes.hashfile_id==Hashfiles.id).filter(Hashfiles.customer_id == customer_id).filter(Hashes.cracked == '1').all()
            uncracked_hashes = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).join(Hashfiles, HashfileHashes.hashfile_id==Hashfiles.id).filter(Hashfiles.customer_id == customer_id).filter(Hashes.cracked == '0').all()
    else:
        cracked_hashes = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked=='1').all()
        uncracked_hashes = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked=='0').all()

    outfile = open('hashview/control/tmp/' + filename, 'w')

    if request.args.get('type') == 'found':
        for entry in cracked_hashes:
            if entry[1].username:
                outfile.write(str(bytes.fromhex(entry[1].username).decode('latin-1')) + ":" + str(entry[0].ciphertext) + ':' + str(bytes.fromhex(entry[0].plaintext).decode('latin-1')) + "\n")
            else:
                outfile.write(str(entry[0].ciphertext) + ':' + str(bytes.fromhex(entry[0].plaintext).decode('latin-1')) + "\n")

    if request.args.get('type') == 'left':
        for entry in uncracked_hashes:
            if entry[1].username:
                outfile.write(str(bytes.fromhex(entry[1].username).decode('latin-1')) + ":" + str(entry[0].ciphertext) + "\n")
            else:
                outfile.write(str(entry[0].ciphertext) + "\n")

    
    outfile.close()
    return send_from_directory('control/tmp', filename, as_attachment=True)
