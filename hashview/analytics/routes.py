from flask import Blueprint, jsonify, render_template, request, redirect, send_from_directory
from flask_login import login_required
from hashview.models import Customers, HashfileHashes, Hashes, Hashfiles
from hashview.models import db
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
        ("Recovered: " + str(formatDisplay(fig1_cracked_cnt)), fig1_cracked_cnt),
        ("Unrecovered: " + str(formatDisplay(fig1_uncracked_cnt)), fig1_uncracked_cnt)
    ]

    fig1_labels = [row[0] for row in fig1_data]
    fig1_values = [row[1] for row in fig1_data]
    fig1_total = (fig1_cracked_cnt + fig1_uncracked_cnt)

    # Cracked Percent
    fig1_percent = 0 if (0 == fig1_total) else [str(round(((fig1_cracked_cnt / fig1_total)*100),1)) + '%']

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
        if len(bytes.fromhex(entry[0]).decode('latin-1')) < 8:
            flags = -3 # set to negative 3 so that there's no way we can meet complexity
        if re.search(r"[a-z]", bytes.fromhex(entry[0]).decode('latin-1')):
            flags = flags + 1
        if re.search(r"[A-Z]", bytes.fromhex(entry[0]).decode('latin-1')):
            flags = flags + 1
        if re.search(r"[0-9]", bytes.fromhex(entry[0]).decode('latin-1')):
            flags = flags + 1
        if re.search(r"[^0-9A-Za-z]", bytes.fromhex(entry[0]).decode('latin-1')):
            flags = flags + 1

        if flags < 3:
            fig2_fails_complexity_cnt = fig2_fails_complexity_cnt + 1
        else:
            fig2_meets_complexity_cnt = fig2_meets_complexity_cnt + 1

    fig2_data = [
        ("Fails Complexity: " + str(formatDisplay(fig2_fails_complexity_cnt)), fig2_fails_complexity_cnt),
        ("Meets Complexity: " + str(formatDisplay(fig2_meets_complexity_cnt)), fig2_meets_complexity_cnt),
        ("Unrecovered: " + str(formatDisplay(fig2_uncracked_cnt)), fig2_uncracked_cnt)
    ]

    fig2_labels = [row[0] for row in fig2_data]
    fig2_values = [row[1] for row in fig2_data]

    # Figure 3 Recovered Hashes
    if customer_id:
        # we have a customer
        if hashfile_id: # with a hashfile
            fig3_cracked_cnt = db.session.query(Hashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==hashfile_id).distinct(Hashes.plaintext).count()
            fig3_uncracked_cnt = db.session.query(Hashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '0').filter(HashfileHashes.hashfile_id==hashfile_id).distinct(Hashes.ciphertext).count()
        else:
            # just a customer, no specific hashfile
            fig3_cracked_cnt = db.session.query(Hashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).join(Hashfiles, HashfileHashes.hashfile_id==Hashfiles.id).filter(Hashfiles.customer_id == customer_id).filter(Hashes.cracked == '1').distinct(Hashes.plaintext).count()
            fig3_uncracked_cnt = db.session.query(Hashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).join(Hashfiles, HashfileHashes.hashfile_id==Hashfiles.id).filter(Hashfiles.customer_id == customer_id).filter(Hashes.cracked == '0').distinct(Hashes.ciphertext).count()
    else:
        fig3_cracked_cnt = db.session.query(Hashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked=='1').distinct(Hashes.plaintext).count()
        fig3_uncracked_cnt = db.session.query(Hashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked=='0').distinct(Hashes.ciphertext).count()

    fig3_data = [
        ("Recovered: " + str(formatDisplay(fig3_cracked_cnt)), fig3_cracked_cnt),
        ("Unrecovered: " + str(formatDisplay(fig3_uncracked_cnt)), fig3_uncracked_cnt)
    ]

    fig3_labels = [row[0] for row in fig3_data]
    fig3_values = [row[1] for row in fig3_data]
    fig3_total = (fig3_cracked_cnt + fig3_uncracked_cnt)

    # Cracked Percent
    fig3_percent = 0 if (0 == fig3_total) else [str(round(((fig3_cracked_cnt / fig3_total)*100),1)) + '%']

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

    total_accounts = formatDisplay(total_accounts)
    total_unique_hashes = formatDisplay(total_unique_hashes)

    # Figure 4 (Charset Breakdown)
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

    fig4_labels = []
    fig4_values = []

    # We only want the top 4 with the 5th being other
    fig4_dict = {
        "Blank (unset): " + str(formatDisplay(blank)): blank,
        "Numeric Only: " + str(formatDisplay(numeric)) : numeric,
        "LowerAlpha Only: " + str(formatDisplay(loweralpha)): loweralpha,
        "UpperAlpha Only: " + str(formatDisplay(upperalpha)): upperalpha,
        "Special Only: " + str(formatDisplay(special)): special,
        "MixedAlpha: " + str(formatDisplay(mixedalpha)): mixedalpha,
        "MixedAlphaNumeric: " +str(formatDisplay(mixedalphanum)): mixedalphanum,
        "LowerAlphaNumeric: " + str(formatDisplay(loweralphanum)): loweralphanum,
        "LowerAlphaSpecial: " + str(formatDisplay(loweralphaspecial)): loweralphaspecial,
        "UpperAlphaSpecial: " + str(formatDisplay(upperalphaspecial)): upperalphaspecial,
        "SpecialNumeric: " + str(formatDisplay(specialnum)): specialnum,
        "MixedAlphaSpecial: " + str(formatDisplay(mixedalphaspecial)): mixedalphaspecial,
        "UpperAlphaSpecialNumeric: " + str(formatDisplay(upperalphaspecialnum)): upperalphaspecialnum,
        "LowerAlphaSpecialNumeric: " + str(formatDisplay(loweralphaspecialnum)): loweralphaspecialnum,
        "MixedAlphaSpecialNumeric: " + str(formatDisplay(mixedalphaspecialnum)): mixedalphaspecialnum,
        "Other: " + str(formatDisplay(other)): other,
        }

    fig4_array_sorted = dict(sorted(fig4_dict.items(), key=operator.itemgetter(1),reverse=True))

    limit = 0
    fig4_other = 0
    for key in fig4_array_sorted:
        if limit <= 3:
            fig4_labels.append(key)
            fig4_values.append(fig4_array_sorted[key])
            limit += 1
        else:
            fig4_other += fig4_array_sorted[key]

    fig4_labels.append('Other: ' + str(fig4_other))
    fig4_values.append(fig4_other)

    # Figure 4 (Passwords by Length)
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

    for entry in fig5_cracked_hashes:
        if len(bytes.fromhex(entry[0]).decode('latin-1')) in fig5_data:
            fig5_data[len(bytes.fromhex(entry[0]).decode('latin-1'))] += 1
        else:
            fig5_data[len(bytes.fromhex(entry[0]).decode('latin-1'))] = 1

    fig5_labels =[]
    fig5_values = []

    # Sort by length and limit to 20
    for entry in sorted(fig5_data):
        if len(fig5_labels) < 20:
            fig5_labels.append(entry)
            fig5_values.append(fig5_data[entry])
        else:
            break

    # Figure 5 (Top 10 Passwords)
    if customer_id:
        # we have a customer
        if hashfile_id:
            fig6_cracked_hashes = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==hashfile_id).with_entities(Hashes.plaintext).all()
        else:
            # just a customer, no specific hashfile
            fig6_cracked_hashes = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).join(Hashfiles, HashfileHashes.hashfile_id==Hashfiles.id).filter(Hashfiles.customer_id == customer_id).filter(Hashes.cracked == '1').with_entities(Hashes.plaintext).all()
    else:
        fig6_cracked_hashes = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked=='1').with_entities(Hashes.plaintext).all()

    fig6_data = {}

    blank_label = 'Blank (unset)'
    for entry in fig6_cracked_hashes:
        if len(bytes.fromhex(entry[0]).decode('latin-1')) > 0:
            if bytes.fromhex(entry[0]).decode('latin-1') in fig6_data:
                fig6_data[bytes.fromhex(entry[0]).decode('latin-1')] += 1
            else:
                fig6_data[bytes.fromhex(entry[0]).decode('latin-1')] = 1
        else:
            if blank_label in fig6_data:
                fig6_data[blank_label] += 1
            else:
                fig6_data[blank_label] = 1

    fig6_labels = []
    fig6_values = []

    # Sort by Highest and Limit to 10
    for entry in sorted(fig6_data, key=fig6_data.__getitem__, reverse=True):
        if len (fig6_labels) < 10:
            fig6_labels.append(entry)
            fig6_values.append(fig6_data[entry])
        else:
            break

    # Figure 6 (Top 10 Masks)
    # Using Fig 5 data for this
    fig7_values = {}
    fig7_data = {}
    fig7_total = 0
    for entry in fig6_cracked_hashes:
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

        if tmp_plaintext not in fig7_data:
            fig7_data[tmp_plaintext] = 1
        else:
            fig7_data[tmp_plaintext] += 1
        fig7_total +=1

    # Sort by Highest and Limit to 10
    for entry in sorted(fig7_data, key=fig7_data.__getitem__, reverse=True):
        if len (fig7_values) < 10:
            fig7_values[entry] = fig7_data[entry]
        else:
            break

    # Figure 8 (Users where Passwords are the same as the username)

    if customer_id:
        # we have a customer
        if hashfile_id:
            fig8_cracked_hashes = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==hashfile_id).with_entities(Hashes.plaintext, HashfileHashes.username).all()
        else:
            # just a customer, no specific hashfile
            fig8_cracked_hashes = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).join(Hashfiles, HashfileHashes.hashfile_id==Hashfiles.id).filter(Hashfiles.customer_id == customer_id).filter(Hashes.cracked == '1').with_entities(Hashes.plaintext, HashfileHashes.username).all()
    else:
        fig8_cracked_hashes = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked=='1').with_entities(Hashes.plaintext, HashfileHashes.username).all()

    fig8_table = []
    for entry in fig8_cracked_hashes:
        if entry[1] and entry[0]:
            # check if username has domain in it
            if '\\' in bytes.fromhex(entry[1]).decode('latin-1'):
                username = bytes.fromhex(entry[1]).decode('latin-1').split('\\')[1]
            # check if username has astrix in it (found with some kerb tickets)
            elif '*' in  bytes.fromhex(entry[1]).decode('latin-1'):
                username = bytes.fromhex(entry[1]).decode('latin-1').split('*')[1]
            else:
                username = bytes.fromhex(entry[1]).decode('latin-1')
            if bytes.fromhex(entry[0]).decode('latin-1') == username:
                fig8_table.append(bytes.fromhex(entry[0]).decode('latin-1'))


    return render_template('analytics.html',
                            title='analytics',
                            fig1_labels=fig1_labels,
                            fig1_values=fig1_values,
                            fig1_percent=fig1_percent,
                            fig2_labels=fig2_labels,
                            fig2_values=fig2_values,
                            fig3_labels=fig3_labels,
                            fig3_values=fig3_values,
                            fig3_percent=fig3_percent,
                            fig4_labels=fig4_labels,
                            fig4_values=fig4_values,
                            fig5_labels=fig5_labels,
                            fig5_values=fig5_values,
                            fig6_labels=fig6_labels,
                            fig6_values=fig6_values,
                            fig7_values=fig7_values,
                            fig7_total=fig7_total,
                            fig8_table=fig8_table,
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

def formatDisplay(number): # add commas to the number after every thousand places
    return "{:,}".format(number)

