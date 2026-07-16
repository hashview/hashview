"""Flask routes to handle Analytics"""
import io
import os
import re
import zipfile
from collections import Counter, defaultdict
from datetime import timedelta

from flask import (
    Blueprint,
    abort,
    redirect,
    render_template,
    request,
    send_file,
    send_from_directory,
)
from flask_login import login_required
from sqlalchemy import func, select
from werkzeug.utils import secure_filename

from hashview.models import Customers, Hashes, HashfileHashes, Hashfiles, Jobs, Tasks, db
from hashview.utils.utils import decode_hex_plain

analytics = Blueprint('analytics', __name__)


# ---------------------------------------------------------------------------
# Scope + analytics helpers
#
# /analytics has three scopes, chosen purely by the customer + hashfile query
# args (there is no separate "scope" control):
#   * (no args)                  -> all data (every customer)
#   * customer_id                -> one customer (all of their hashfiles)
#   * customer_id + hashfile_id  -> a single hashfile
# These arg names are part of the URL contract that the jobs / hashfiles /
# customer / job-completion-email links rely on, so they must not change.
# ---------------------------------------------------------------------------

BLANK_LABEL = 'Blank (unset)'


def _scoped_hash_query(customer_id, hashfile_id, cracked=None):
    """Hashes joined to their HashfileHashes (account) rows, narrowed to the
    active scope. ``cracked`` optionally keeps only recovered (True) or
    not-yet-recovered (False) hashes."""
    query = db.session.query(Hashes).join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
    if hashfile_id:
        query = query.filter(HashfileHashes.hashfile_id == hashfile_id)
    elif customer_id:
        query = (query.join(Hashfiles, HashfileHashes.hashfile_id == Hashfiles.id)
                 .filter(Hashfiles.customer_id == customer_id))
    if cracked is True:
        query = query.filter(Hashes.cracked == 1)
    elif cracked is False:
        query = query.filter(Hashes.cracked == 0)
    return query


def _scoped_hashfiles(customer_id, hashfile_id):
    """Hashfiles in the active scope (used for runtime + file counts)."""
    query = db.session.query(Hashfiles)
    if hashfile_id:
        return query.filter(Hashfiles.id == hashfile_id)
    if customer_id:
        return query.filter(Hashfiles.customer_id == customer_id)
    return query


def _distinct_hash_count(customer_id, hashfile_id, cracked=None):
    """Distinct hashes (de-duped across shared accounts) in the scope."""
    return (_scoped_hash_query(customer_id, hashfile_id, cracked)
            .with_entities(Hashes.id).distinct().count())


def _local_part(username):
    """DOMAIN\\user or *user -> bare user (netntlm / kerberos style names)."""
    if not username:
        return username
    if '\\' in username:
        return username.split('\\')[-1]
    if '*' in username:
        return username.split('*')[-1]
    return username


def _char_classes(plaintext):
    """(has_lower, has_upper, has_digit, has_special) for a plaintext."""
    return (
        bool(re.search(r'[a-z]', plaintext)),
        bool(re.search(r'[A-Z]', plaintext)),
        bool(re.search(r'[0-9]', plaintext)),
        bool(re.search(r'[^A-Za-z0-9]', plaintext)),
    )


def _mask(plaintext):
    """hashcat-style ?l?u?d?s mask for a plaintext (one token per character)."""
    out = []
    for char in plaintext:
        if 'a' <= char <= 'z':
            out.append('?l')
        elif 'A' <= char <= 'Z':
            out.append('?u')
        elif '0' <= char <= '9':
            out.append('?d')
        else:
            out.append('?s')
    return ''.join(out)


# Pattern-intelligence vocab (substring match against the lowercased plaintext).
SEASONS = ('spring', 'summer', 'autumn', 'winter', 'fall')
MONTHS = ('january', 'february', 'march', 'april', 'may', 'june', 'july',
          'august', 'september', 'october', 'november', 'december')
KEYBOARD_WALKS = ('qwerty', 'qwertz', 'azerty', 'asdfgh', 'asdf', 'zxcvbn', 'zxcv',
                  'qazwsx', '1qaz', '2wsx', '1q2w3e', 'qweasd', 'poiuy')
YEAR_RE = re.compile(r'(?:19|20)\d{2}')
# generic org-name tokens that would over-match if treated as "company name" hits
_COMPANY_STOPWORDS = frozenset({'inc', 'llc', 'ltd', 'corp', 'the', 'and', 'group',
                                'company', 'gmbh', 'holdings'})
_ATTACK_LABELS = {0: 'Wordlist', 1: 'Combinator', 3: 'Mask / brute-force', 6: 'Hybrid', 7: 'Hybrid'}


def _base_word(plaintext):
    """Root word: strip leading/trailing non-letters, lowercase ('Summer2024!' -> 'summer')."""
    core = re.sub(r'^[^A-Za-z]+', '', plaintext)
    core = re.sub(r'[^A-Za-z]+$', '', core)
    return core.lower()


def _suffix(plaintext):
    """Trailing run of non-letter characters users append ('Welcome1!' -> '1!')."""
    match = re.search(r'[^A-Za-z]+$', plaintext)
    return match.group(0) if match else '(ends with a letter)'


def _company_tokens(customer_obj, customers):
    """Significant name tokens to flag as 'company name' hits. Uses the scoped
    customer when one is selected, else every customer (all-data scope)."""
    names = [customer_obj.name] if customer_obj else [c.name for c in customers]
    return {tok for name in names
            for tok in re.split(r'[^a-z0-9]+', (name or '').lower())
            if len(tok) >= 3 and tok not in _COMPANY_STOPWORDS}


def _pattern_intelligence(corpus, company_tokens):
    """Base words, common themes, embedded years and trailing tokens over the
    recovered ``(plaintext, _username)`` corpus. Returns four bar_row-ready lists."""
    base, suffixes, years = Counter(), Counter(), Counter()
    themes = {'Company name': 0, 'Season': 0, 'Month': 0, 'Year (19xx/20xx)': 0, 'Keyboard walk': 0}
    for plaintext, _username in corpus:
        pword = plaintext or ''
        if not pword:
            continue
        low = pword.lower()
        word = _base_word(pword)
        if len(word) >= 3:
            base[word] += 1
        suffixes[_suffix(pword)] += 1
        found_years = YEAR_RE.findall(pword)
        for year in found_years:
            years[year] += 1
        if company_tokens and any(tok in low for tok in company_tokens):
            themes['Company name'] += 1
        if any(season in low for season in SEASONS):
            themes['Season'] += 1
        if any(month in low for month in MONTHS):
            themes['Month'] += 1
        if found_years:
            themes['Year (19xx/20xx)'] += 1
        if any(walk in low for walk in KEYBOARD_WALKS):
            themes['Keyboard walk'] += 1

    tones = {'Company name': 'red', 'Season': 'amber', 'Month': 'amber',
             'Year (19xx/20xx)': 'amber', 'Keyboard walk': 'red'}
    return (
        [{'pw': word, 'n': n} for word, n in base.most_common(10)],
        [{'label': label, 'n': count, 'tone': tones[label]} for label, count in themes.items()],
        [{'year': year, 'n': n} for year, n in years.most_common(10)],
        [{'token': token, 'n': n} for token, n in suffixes.most_common(10)],
    )


def _attack_breakdown(customer_id, hashfile_id):
    """Recovered (distinct) hashes grouped by the attack method that cracked them."""
    rows = (_scoped_hash_query(customer_id, hashfile_id, cracked=True)
            .with_entities(Hashes.id, Hashes.task_id).distinct().all())
    method = {}
    for task in Tasks.query.with_entities(Tasks.id, Tasks.hc_attackmode, Tasks.rule_id).all():
        label = _ATTACK_LABELS.get(task.hc_attackmode, 'Other')
        if task.hc_attackmode == 0 and task.rule_id:
            label = 'Wordlist + rules'
        method[task.id] = label
    counts = Counter(method.get(task_id, 'Unknown') for _hash_id, task_id in rows)
    return [{'label': label, 'n': n} for label, n in counts.most_common()]


_MODE_BADGE = {1: 'Combinator', 3: 'Mask', 6: 'Hybrid', 7: 'Hybrid'}


def _task_mode_label(attackmode, rule_id):
    """Short attack-mode badge label for a task's hc_attackmode."""
    if attackmode == 0:
        return 'Dict + Rule' if rule_id else 'Dictionary'
    return _MODE_BADGE.get(attackmode, 'Mode %s' % attackmode)


def _recovery_by_task(customer_id, hashfile_id):
    """Recovered (distinct) hashes grouped by the task that cracked them.

    Each recovered hash carries Hashes.task_id -- the task that recovered it.
    Returns (rows, total): rows are sorted by recovered count descending, each
    ``{'name', 'mode', 'n', 'share', 'bar'}`` where ``share`` is the percent of
    the scope's attributed recoveries and ``bar`` is the count relative to the
    top task (drives the contribution bar width). Hashes with no task_id (e.g.
    imported cracks) aren't attributable and are excluded.
    """
    rows = (_scoped_hash_query(customer_id, hashfile_id, cracked=True)
            .with_entities(Hashes.id, Hashes.task_id).distinct().all())
    counts = Counter(task_id for _hash_id, task_id in rows if task_id is not None)
    total = sum(counts.values())
    if not counts:
        return [], 0
    top = counts.most_common(1)[0][1]
    meta = {t.id: t for t in (Tasks.query
            .with_entities(Tasks.id, Tasks.name, Tasks.hc_attackmode, Tasks.rule_id)
            .filter(Tasks.id.in_(list(counts))).all())}
    result = []
    for task_id, n in counts.most_common():
        t = meta.get(task_id)
        result.append({
            'name': t.name if t else 'task %s (deleted)' % task_id,
            'mode': _task_mode_label(t.hc_attackmode, t.rule_id) if t else 'Unknown',
            'n': n,
            'share': round(100.0 * n / total, 1),
            'bar': round(100.0 * n / top, 1),
        })
    return result, total


# Length-bucket columns for the length x complexity heatmap.
_LEN_COLS = ('≤5', '6', '7', '8', '9', '10', '11', '12', '13-15', '16+')
STRENGTH_LABELS = ('Very weak', 'Weak', 'Fair', 'Strong', 'Very strong')
_STRENGTH_TONES = ('red', 'red', 'amber', 'primary', 'cyan')


def _len_col(length):
    """Column index into _LEN_COLS for a password length."""
    if length <= 5:
        return 0
    if length <= 12:
        return length - 5      # 6->1 ... 12->7
    if length <= 15:
        return 8
    return 9


def _strength_bucket(plaintext):
    """Heuristic 0-4 password strength (zxcvbn-style buckets): rewards length and
    character-class diversity, penalises keyboard walks, runs of repeats and short
    passwords. A fast estimate (not the real zxcvbn library, which is too slow per
    password for a whole corpus)."""
    if not plaintext:
        return 0
    length = len(plaintext)
    lower, upper, digit, special = _char_classes(plaintext)
    classes = lower + upper + digit + special
    score = 0
    score += (length >= 8) + (length >= 12) + (length >= 16)
    score += (classes >= 3) + (classes == 4)
    low = plaintext.lower()
    if any(walk in low for walk in KEYBOARD_WALKS):
        score -= 2
    if re.search(r'(.)\1\1', plaintext):          # 3+ identical chars in a row
        score -= 1
    if length < 8:
        score -= 1
    return max(0, min(4, score))


def _structure_breakdowns(corpus):
    """length x character-class heatmap, password-rotation clusters, and a
    strength distribution over the recovered corpus -- computed in one pass."""
    heat = defaultdict(int)              # (len_col, n_classes 1-4) -> count
    stem_variants = defaultdict(set)     # rotation stem (lowercased) -> {full plaintext, ...}
    strength = [0, 0, 0, 0, 0]
    for plaintext, _username in corpus:
        pword = plaintext or ''
        if not pword:
            continue
        lower, upper, digit, special = _char_classes(pword)
        n_classes = lower + upper + digit + special
        if n_classes:
            heat[(_len_col(len(pword)), n_classes)] += 1
        stem = re.sub(r'[^A-Za-z]+$', '', pword).lower()    # strip trailing digits/symbols
        if len(stem) >= 3:
            stem_variants[stem].add(pword)
        strength[_strength_bucket(pword)] += 1

    heatmap_rows = [
        {'classes': cls,
         'cells': [{'n': heat.get((col, cls), 0)} for col in range(len(_LEN_COLS))]}
        for cls in (4, 3, 2, 1)
    ]
    heatmap_max = max(heat.values()) if heat else 0
    rotations = sorted(
        ({'stem': stem, 'count': len(variants), 'variants': sorted(variants)}
         for stem, variants in stem_variants.items() if len(variants) >= 2),
        key=lambda item: item['count'], reverse=True)[:8]
    strength_dist = [{'label': STRENGTH_LABELS[i], 'n': strength[i], 'tone': _STRENGTH_TONES[i]}
                     for i in range(5)]
    return heatmap_rows, list(_LEN_COLS), heatmap_max, rotations, strength_dist


@analytics.route('/analytics', methods=['GET'])
@login_required
def get_analytics():
    """Scope-aware analytics dashboard (all data / per-customer / per-hashfile)."""

    customer_id = request.args.get('customer_id') or None
    hashfile_id = request.args.get('hashfile_id') or None

    # Dropdown option lists: every customer that has a hashfile, and every
    # hashfile (the template filters the hashfile list by the chosen customer).
    customers, hashfiles = [], []
    rows = (db.session.query(Customers, Hashfiles)
            .join(Hashfiles, Customers.id == Hashfiles.customer_id)
            .order_by(Customers.name))
    for row in rows:
        if row.Customers not in customers:
            customers.append(row.Customers)
        hashfiles.append(row.Hashfiles)

    customer_obj = Customers.query.get(customer_id) if customer_id else None
    hashfile_obj = Hashfiles.query.get(hashfile_id) if hashfile_id else None

    # ---- one recovered (plaintext, username) corpus query feeds every
    #      plaintext-derived chart below ----
    # Decode hashcat's `$HEX[...]` marker once here so every plaintext-derived
    # chart below (length, strength, char-classes, masks, top passwords) measures
    # the real password rather than the wrapper. Mirrors Wrapped's _decode_plain.
    corpus = [(decode_hex_plain(plaintext), username)
              for plaintext, username in
              _scoped_hash_query(customer_id, hashfile_id, cracked=True)
              .with_entities(Hashes.plaintext, HashfileHashes.username).all()]
    total_cracked = len(corpus)

    freq = Counter()
    shared_map = defaultdict(list)
    length_counter = Counter()
    mask_counter = Counter()
    class_counts = [0, 0, 0, 0]          # index 0 -> 1 class ... index 3 -> 4 classes
    user_eq_pass = []
    hist = defaultdict(int)              # (len<=16, class_mask 0-15, contains_username) -> count

    for plaintext, username in corpus:
        pword = plaintext or ''
        freq[pword] += 1
        shared_map[pword].append(username)
        length_counter[len(pword)] += 1
        mask_counter[_mask(pword)] += 1

        lower, upper, digit, special = _char_classes(pword)
        n_classes = lower + upper + digit + special
        if n_classes:
            class_counts[n_classes - 1] += 1

        local = _local_part(username) or ''
        if pword and local and local.lower() == pword.lower():
            user_eq_pass.append({'u': username, 'p': pword})

        class_mask = (1 if lower else 0) | (2 if upper else 0) | (4 if digit else 0) | (8 if special else 0)
        contains_user = 1 if (local and local.lower() in pword.lower()) else 0
        hist[(min(len(pword), 16), class_mask, contains_user)] += 1

    top_passwords = [{'pw': pw or BLANK_LABEL, 'n': n} for pw, n in freq.most_common(10)]
    reused = sum(n for n in freq.values() if n > 1)
    reused_pct = round(reused / total_cracked * 1000) / 10 if total_cracked else 0
    unique_pct = round((100 - reused_pct) * 10) / 10 if total_cracked else 0
    top_reuse_count = freq.most_common(1)[0][1] if freq else 0

    shared = sorted(
        ({'plain': pw or BLANK_LABEL, 'plain_raw': pw, 'count': len(users),
          'users': [_local_part(user) for user in users if user]}
         for pw, users in shared_map.items() if len(users) > 1),
        key=lambda item: item['count'], reverse=True)

    masks = [{'mask': mask, 'n': n} for mask, n in mask_counter.most_common(10)]
    length_dist = [{'len': length, 'n': length_counter[length]} for length in sorted(length_counter)]
    class_buckets = [
        {'label': '1 class · weak', 'n': class_counts[0], 'tone': 'red'},
        {'label': '2 classes', 'n': class_counts[1], 'tone': 'amber'},
        {'label': '3 classes', 'n': class_counts[2], 'tone': 'primary'},
        {'label': '4 classes · strong', 'n': class_counts[3], 'tone': 'cyan'},
    ]
    complexity_hist = [[length, mask, user, n] for (length, mask, user), n in hist.items()]

    # ---- pattern intelligence (base words / themes / years / endings) + crack method ----
    top_base_words, themes, year_dist, suffixes = _pattern_intelligence(
        corpus, _company_tokens(customer_obj, customers))
    fell = _attack_breakdown(customer_id, hashfile_id)
    recovery_by_task, recovery_total = _recovery_by_task(customer_id, hashfile_id)
    heatmap_rows, heatmap_cols, heatmap_max, rotations, strength_dist = _structure_breakdowns(corpus)

    # ---- scope totals (uncracked is derived in the template as total - cracked) ----
    accounts = _scoped_hash_query(customer_id, hashfile_id).count()
    accounts_cracked = _scoped_hash_query(customer_id, hashfile_id, cracked=True).count()
    unique_hashes = _distinct_hash_count(customer_id, hashfile_id)
    unique_cracked = _distinct_hash_count(customer_id, hashfile_id, cracked=True)
    runtime = (_scoped_hashfiles(customer_id, hashfile_id)
               .with_entities(func.coalesce(func.sum(Hashfiles.runtime), 0)).scalar()) or 0
    scope_hashfiles_cnt = _scoped_hashfiles(customer_id, hashfile_id).count()

    jobs_query = db.session.query(Jobs)
    if hashfile_id:
        jobs_query = jobs_query.filter(Jobs.hashfile_id == hashfile_id)
    elif customer_id:
        jobs_query = jobs_query.filter(Jobs.customer_id == customer_id)
    jobs_cnt = jobs_query.count()

    # ---- recovery over time: distinct cracked hashes bucketed by hour ----
    # The template toggles between two series built here: per-hour counts and the
    # running cumulative total. Buckets are hourly and the window spans at most
    # RECOVERY_WINDOW_HOURS, ending at the most recent recovery; recoveries before
    # the window are folded into the cumulative baseline so the cumulative line
    # stays accurate. Gaps inside the window are zero-filled so both series are
    # continuous (and the x-axis is time-proportional).
    RECOVERY_WINDOW_HOURS = 48
    recovered_rows = (_scoped_hash_query(customer_id, hashfile_id, cracked=True)
                      .with_entities(Hashes.id, Hashes.recovered_at).distinct().all())
    by_hour = Counter()
    for _hash_id, recovered_at in recovered_rows:
        if recovered_at:
            by_hour[recovered_at.replace(minute=0, second=0, microsecond=0)] += 1
    timeline = []
    if by_hour:
        hours = sorted(by_hour)
        last = hours[-1]
        window_start = max(hours[0], last - timedelta(hours=RECOVERY_WINDOW_HOURS - 1))
        running = sum(c for h, c in by_hour.items() if h < window_start)  # cumulative baseline
        bucket = window_start
        while bucket <= last:
            count = by_hour.get(bucket, 0)
            running += count
            timeline.append({'label': bucket.strftime('%m/%d %H:%M'),
                             'count': count, 'cum': running})
            bucket += timedelta(hours=1)

    # ---- customer rollup (shown whenever a customer is selected) ----
    if customer_id and not hashfile_id:
        rollup = {'files': scope_hashfiles_cnt, 'cracked': unique_cracked, 'total': unique_hashes}
    elif customer_id:
        rollup = {'files': _scoped_hashfiles(customer_id, None).count(),
                  'cracked': _distinct_hash_count(customer_id, None, cracked=True),
                  'total': _distinct_hash_count(customer_id, None)}
    else:
        rollup = None

    if hashfile_id:
        scope_mode = 'file'
        scope_name = hashfile_obj.name if hashfile_obj else 'hashfile'
    elif customer_id:
        scope_mode = 'customer'
        scope_name = '%s · all %d hashfiles' % (
            customer_obj.name if customer_obj else 'customer', scope_hashfiles_cnt)
    else:
        scope_mode = 'all'
        scope_name = 'all data'

    return render_template(
        'analytics.html.j2',
        title='analytics',
        customers=customers,
        hashfiles=hashfiles,
        customer_id=customer_id,
        hashfile_id=hashfile_id,
        customer_obj=customer_obj,
        scope_mode=scope_mode,
        scope_name=scope_name,
        rollup=rollup,
        accounts=accounts,
        accounts_cracked=accounts_cracked,
        unique_hashes=unique_hashes,
        unique_cracked=unique_cracked,
        runtime=runtime,
        jobs_cnt=jobs_cnt,
        scope_hashfiles_cnt=scope_hashfiles_cnt,
        total_cracked=total_cracked,
        top_passwords=top_passwords,
        reused_pct=reused_pct,
        unique_pct=unique_pct,
        top_reuse_count=top_reuse_count,
        shared=shared,
        masks=masks,
        length_dist=length_dist,
        class_buckets=class_buckets,
        user_eq_pass=user_eq_pass,
        timeline=timeline,
        complexity_hist=complexity_hist,
        complexity_total=total_cracked,
        top_base_words=top_base_words,
        themes=themes,
        year_dist=year_dist,
        suffixes=suffixes,
        fell=fell,
        recovery_by_task=recovery_by_task,
        recovery_total=recovery_total,
        heatmap_rows=heatmap_rows,
        heatmap_cols=heatmap_cols,
        heatmap_max=heatmap_max,
        rotations=rotations,
        strength_dist=strength_dist)

def _download_scope_ids():
    """Parse the optional customer_id / hashfile_id download args as ints.

    They are always numeric resource ids; coercing to int (and rejecting
    non-numeric input) keeps attacker-controlled strings out of the on-disk
    output filename the download routes build, closing a path-traversal /
    arbitrary-file-write hole (issue #216). Returns (customer_id, hashfile_id);
    either may be None. Aborts 400 on non-numeric input.
    """
    def _opt_int(name):
        raw = request.args.get(name)
        if not raw:
            return None
        try:
            return int(raw)
        except (TypeError, ValueError):
            abort(400)
    return _opt_int('customer_id'), _opt_int('hashfile_id')


def _tmp_download_path(filename):
    """Resolve a download temp file inside control/tmp, refusing path traversal.

    Defense-in-depth on top of the int-coerced ids: run the name through
    secure_filename and confirm the resolved path stays within control/tmp.
    Returns (safe_name, abs_path) -- write to abs_path, serve safe_name from
    'control/tmp'.
    """
    safe_name = secure_filename(filename)
    tmp_dir = os.path.realpath(os.path.join('hashview', 'control', 'tmp'))
    abs_path = os.path.realpath(os.path.join(tmp_dir, safe_name))
    if os.path.commonpath((tmp_dir, abs_path)) != tmp_dir:
        abort(400)
    return safe_name, abs_path


# serve a list of cracks
@analytics.route('/analytics/download', methods=['GET'])
@login_required
def analytics_download_hashes():
    """Function to download hashes"""

    filename = ''

    if request.args.get('type') == 'found':
        filename += 'found'
    elif request.args.get('type') == 'left':
        filename += 'left'
    else:
        redirect('/analytics')

    # customer_id / hashfile_id are coerced to int so a crafted value can't
    # escape control/tmp via the output filename (#216).
    customer_id, hashfile_id = _download_scope_ids()
    if customer_id is not None:
        filename += '_' + str(customer_id)
    if hashfile_id is not None:
        # Append the hashfile identifier to the filename (not the customer id)
        filename += '_' + str(hashfile_id)
    else:
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

    safe_name, outfile_path = _tmp_download_path(filename)
    outfile = open(outfile_path, 'w')

    if request.args.get('type') == 'found':
        for entry in cracked_hashes:
            if entry[1].username:
                outfile.write(str(entry[1].username) + ":" + str(entry[0].ciphertext) + ':' + str(entry[0].plaintext) + "\n")
            else:
                outfile.write(str(entry[0].ciphertext) + ':' + str(entry[0].plaintext) + "\n")

    if request.args.get('type') == 'left':
        for entry in uncracked_hashes:
            if entry[1].username:
                outfile.write(str(entry[1].username) + ":" + str(entry[0].ciphertext) + "\n")
            else:
                outfile.write(str(entry[0].ciphertext) + "\n")

    outfile.close()
    return send_from_directory('control/tmp', safe_name, as_attachment=True)

# Download the list of accounts that share the same password or password hash (fig9)
@analytics.route('/analytics/download/fig9', methods=['GET'])
@login_required
def analytics_download_fig9():
    """
    Generate a plain‑text file containing every username that appears in the
    fig9_table (accounts that share the same password or password hash) and
    serve it as a downloadable attachment.
    """
    # Build a filename that reflects any filters applied
    filename = 'fig9_shared_passwords'

    # Preserve any customer or hashfile filters for consistency with the main
    # analytics view. customer_id / hashfile_id are coerced to int so a crafted
    # value can't escape control/tmp via the output filename (#216).
    customer_id, hashfile_id = _download_scope_ids()
    if customer_id is not None:
        filename += '_' + str(customer_id)
    if hashfile_id is not None:
        filename += '_' + str(hashfile_id)

    filename += '.txt'

    # Gather the usernames from fig9_table logic (same as in the template)
    fig9_usernames = []

    if customer_id:
        # we have a customer
        if hashfile_id:
            # Specific hashfile
            fig9_hashes_ids = db.session.query(HashfileHashes) \
                .where(HashfileHashes.hashfile_id == hashfile_id) \
                .group_by(HashfileHashes.hash_id) \
                .having(func.count() > 1) \
                .with_entities(HashfileHashes.hash_id) \
                .subquery()

            fig9_usernames = (
                db.session.execute(
                    select(HashfileHashes.username)
                        .where(HashfileHashes.hashfile_id == hashfile_id)
                        .where(HashfileHashes.hash_id.in_(fig9_hashes_ids))
                        .distinct()
                )
                .scalars()
                .all()
            )
        else:
            # All hashfiles for the customer
            fig9_hashes_ids = db.session.query(HashfileHashes) \
                .join(Hashfiles, HashfileHashes.hashfile_id == Hashfiles.id) \
                .where(Hashfiles.customer_id == customer_id) \
                .group_by(HashfileHashes.hash_id) \
                .having(func.count() > 1) \
                .with_entities(HashfileHashes.hash_id) \
                .subquery()

            fig9_usernames = (
                db.session.execute(
                    select(HashfileHashes.username)
                        .join(Hashfiles, HashfileHashes.hashfile_id == Hashfiles.id)
                        .where(Hashfiles.customer_id == customer_id)
                        .where(HashfileHashes.hash_id.in_(fig9_hashes_ids))
                        .distinct()
                )
                .scalars()
                .all()
            )
    else:
        # No customer filter – all hashfiles
        fig9_hashes_ids = db.session.query(HashfileHashes) \
            .group_by(HashfileHashes.hash_id) \
            .having(func.count() > 1) \
            .with_entities(HashfileHashes.hash_id) \
            .subquery()

        fig9_usernames = (
            db.session.execute(
                select(HashfileHashes.username)
                    .where(HashfileHashes.hash_id.in_(fig9_hashes_ids))
                    .distinct()
            )
            .scalars()
            .all()
        )

    # Write usernames to the file
    safe_name, outfile_path = _tmp_download_path(filename)
    with open(outfile_path, 'w') as outfile:
        for entry in fig9_usernames:
            if entry:
                # Decode possible hex‑encoded usernames
                try:
                    decoded = entry
                except Exception:
                    decoded = entry
                outfile.write(f"{decoded}\n")

    return send_from_directory('control/tmp', safe_name, as_attachment=True)

@analytics.route('/analytics/download/fig8', methods=['GET'])
@login_required
def analytics_download_fig8():
    """
    Generate a plain‑text file containing every username whose password matches the username
    (fig8) and serve it as a downloadable attachment.
    """
    # Build a filename that reflects any filters applied
    filename = 'fig8_same_user_pass'

    # customer_id / hashfile_id are coerced to int so a crafted value can't
    # escape control/tmp via the output filename (#216).
    customer_id, hashfile_id = _download_scope_ids()
    if customer_id is not None:
        filename += '_' + str(customer_id)
    if hashfile_id is not None:
        filename += '_' + str(hashfile_id)

    filename += '.txt'

    # Gather the usernames where password == username using the same logic as fig8_table
    fig8_usernames = []

    if customer_id:
        if hashfile_id:
            # Specific hashfile
            fig8_cracked_hashes = db.session.query(Hashes, HashfileHashes) \
                .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id) \
                .filter(Hashes.cracked == '1') \
                .filter(HashfileHashes.hashfile_id == hashfile_id) \
                .with_entities(Hashes.plaintext, HashfileHashes.username) \
                .all()
        else:
            # All hashfiles for the customer
            fig8_cracked_hashes = db.session.query(Hashes, HashfileHashes) \
                .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id) \
                .join(Hashfiles, HashfileHashes.hashfile_id == Hashfiles.id) \
                .filter(Hashfiles.customer_id == customer_id) \
                .filter(Hashes.cracked == '1') \
                .with_entities(Hashes.plaintext, HashfileHashes.username) \
                .all()
    else:
        # No customer filter – all hashfiles
        fig8_cracked_hashes = db.session.query(Hashes, HashfileHashes) \
            .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id) \
            .filter(Hashes.cracked == '1') \
            .with_entities(Hashes.plaintext, HashfileHashes.username) \
            .all()

    for entry in fig8_cracked_hashes:
        if entry[1] and entry[0]:
            # Decode username (handle possible domain delimiters)
            raw_username = entry[1]
            if '\\' in raw_username:
                username = raw_username.split('\\')[1]
            elif '*' in raw_username:
                username = raw_username.split('*')[1]
            else:
                username = raw_username

            # Decode password
            password = entry[0]

            if username == password:
                fig8_usernames.append(username)

    # Write usernames to the file
    safe_name, outfile_path = _tmp_download_path(filename)
    with open(outfile_path, 'w') as outfile:
        for uname in fig8_usernames:
            outfile.write(f"{uname}\n")

    return send_from_directory('control/tmp', safe_name, as_attachment=True)


# --- Shared-password downloads (per-group txt and an all-groups zip) ---------

def _safe_name(plaintext):
    """A filesystem-safe stub for a plaintext, used in download filenames."""
    stub = re.sub(r'[^A-Za-z0-9]+', '_', plaintext or '').strip('_')[:32]
    return stub or 'blank'


def _shared_txt(plaintext, users):
    """The text file served for one shared-password group."""
    label = plaintext if plaintext else '(blank password)'
    header = 'The following users were found to share the same password: ' + label
    return header + '\n\n' + '\n'.join(users) + '\n'


def _shared_groups(customer_id, hashfile_id):
    """{plaintext: [usernames]} for recovered passwords shared by >1 account in scope."""
    rows = (_scoped_hash_query(customer_id, hashfile_id, cracked=True)
            .with_entities(Hashes.plaintext, HashfileHashes.username).all())
    groups = defaultdict(list)
    for plaintext, username in rows:
        if username:
            groups[plaintext or ''].append(username)
    return {pword: users for pword, users in groups.items() if len(users) > 1}


@analytics.route('/analytics/download/shared', methods=['POST'])
@login_required
def analytics_download_shared():
    """Users who share one specific recovered password. POST so the plaintext
    travels in the body, not the URL / access logs."""
    plaintext = request.form.get('plaintext', '')
    customer_id = request.form.get('customer_id') or None
    hashfile_id = request.form.get('hashfile_id') or None
    rows = (_scoped_hash_query(customer_id, hashfile_id, cracked=True)
            .filter(Hashes.plaintext == plaintext)
            .with_entities(HashfileHashes.username).all())
    users = sorted({username for (username,) in rows if username})
    buf = io.BytesIO(_shared_txt(plaintext, users).encode('utf-8'))
    return send_file(buf, mimetype='text/plain', as_attachment=True,
                     download_name='shared_' + _safe_name(plaintext) + '.txt')


@analytics.route('/analytics/download/shared_zip', methods=['GET'])
@login_required
def analytics_download_shared_zip():
    """One text file per shared-password group, zipped together."""
    customer_id = request.args.get('customer_id') or None
    hashfile_id = request.args.get('hashfile_id') or None
    groups = sorted(_shared_groups(customer_id, hashfile_id).items(),
                    key=lambda item: len(item[1]), reverse=True)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as archive:
        for index, (plaintext, users) in enumerate(groups, start=1):
            name = 'shared_%02d_%s.txt' % (index, _safe_name(plaintext))
            archive.writestr(name, _shared_txt(plaintext, sorted(set(users))))
    buf.seek(0)
    return send_file(buf, mimetype='application/zip', as_attachment=True,
                     download_name='shared_passwords.zip')
