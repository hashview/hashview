import datetime

from flask import Blueprint, render_template
from flask_login import current_user, login_required
from sqlalchemy import func

from hashview.models import Hashes, Tasks, Users, db
from hashview.utils.utils import decode_hex_plain

wrapped = Blueprint('wrapped', __name__)


def _percentile_top(ordered_ids, user_id):
    """Where ``user_id`` ranks among crackers, expressed as a "top N%" badge.

    ``ordered_ids`` is the list of distinct ``recovered_by`` ids ordered best
    (most recovered) first. Returns an int 1..100 where a SMALLER number is
    better (rank #1 of 100 -> "top 1%"), matching the plain-English meaning of
    "top N%". Returns None when the user isn't ranked in that category.
    """
    n = len(ordered_ids)
    if not n or user_id not in ordered_ids:
        return None
    rank = ordered_ids.index(user_id) + 1          # 1-based rank from the top
    return max(1, round(rank / n * 100))


def _rank_of(ordered_ids, user_id):
    """1-based rank of the user among crackers (None if unranked)."""
    return ordered_ids.index(user_id) + 1 if user_id in ordered_ids else None


# Human plaintext used for length checks + display: decode hashcat's `$HEX[..]`
# marker so the length reflects the real password, not the wrapper. Shared with
# Analytics via hashview.utils.utils.decode_hex_plain.
_decode_plain = decode_hex_plain


@wrapped.route("/wrapped", methods=['GET'])
@login_required
def wrapped_list():
    """Render the Wrapped statistics page with various hash recovery metrics.

    This route is protected by ``login_required`` and collects data for the
    most recently completed calendar year (the "previous" year — Wrapped is a
    year-in-review). It gathers longest recovered passwords, most recovered
    passwords, per-hash-type counts, and the most effective tasks, then passes
    them to the ``wrapped.html.j2`` template.
    """

    uid = current_user.id

    # Wrapped is a year-in-review. Until go-live it reports on the CURRENT
    # calendar year (so there's data to see while testing); switch this to
    # ``- 1`` (previous year) when it ships.
    year = datetime.datetime.now().year
    # Half-open datetime range [Jan 1 00:00 of `year`, Jan 1 00:00 next year):
    # using real datetime bounds (not 'YYYY-12-31' strings) so the whole of
    # Dec 31 — and the first instant of Jan 1 — are included.
    range_start = datetime.datetime(year, 1, 1)
    range_end = datetime.datetime(year + 1, 1, 1)

    def in_year(query):
        return query.filter(Hashes.recovered_at >= range_start, Hashes.recovered_at < range_end)

    # Hash types excluded from "longest password" rankings (network protocol hashes).
    excluded_hash_types_for_length = (7500, 27000, 27100, 31500, 31600, 35300, 35400)

    def ranked_ids(*hash_type_filters):
        """Distinct recovered_by ids (real users only) for a category, ordered
        most-recovered first — the basis for rank/percentile."""
        q = (db.session.query(Hashes.recovered_by)
             .filter(Hashes.cracked == '1', Hashes.recovered_by.isnot(None)))
        q = in_year(q)
        for f in hash_type_filters:
            q = q.filter(f)
        rows = (q.group_by(Hashes.recovered_by)
                .order_by(func.count(Hashes.id).desc())
                .all())
        return [r.recovered_by for r in rows]

    def personal_cnt(*hash_type_filters):
        q = (db.session.query(Hashes.id)
             .filter(Hashes.cracked == '1', Hashes.recovered_by == uid))
        q = in_year(q)
        for f in hash_type_filters:
            q = q.filter(f)
        return q.count()

    def leaderboard(*hash_type_filters):
        """Top 10 crackers (with email) for a category."""
        q = (db.session.query(Hashes.recovered_by, Users.email_address,
                              func.count(Hashes.id).label('row_count'))
             .join(Users, Hashes.recovered_by == Users.id)
             .filter(Hashes.cracked == '1'))
        q = in_year(q)
        for f in hash_type_filters:
            q = q.filter(f)
        rows = (q.group_by(Hashes.recovered_by)
                .order_by(func.count(Hashes.id).desc())
                .limit(10).all())
        return [{'count': r.row_count, 'email_address': r.email_address} for r in rows]

    def effective_tasks(*hash_type_filters):
        """Top 10 tasks by hashes recovered for a category."""
        q = (db.session.query(func.count(Hashes.id).label('row_count'),
                              Tasks.name, Users.email_address)
             .join(Tasks, Hashes.task_id == Tasks.id)
             .join(Users, Tasks.owner_id == Users.id)
             .filter(Hashes.cracked == '1', Hashes.task_id.isnot(None)))
        q = in_year(q)
        for f in hash_type_filters:
            q = q.filter(f)
        rows = (q.group_by(Hashes.task_id)
                .order_by(func.count(Hashes.id).desc())
                .limit(10).all())
        return [{'count': r.row_count, 'task_name': r.name, 'task_author': r.email_address}
                for r in rows]

    # Hash-type groupings.
    ntlm_filter = (Hashes.hash_type == 1000,)
    ntlmv1_filter = (Hashes.hash_type.in_((5500, 27000)),)
    ntlmv2_filter = (Hashes.hash_type.in_((5600, 27100)),)
    kerberos_filter = (Hashes.hash_type.in_((7500, 13100, 18200, 19600, 19700, 19800, 19900)),)
    kerberos_task_filter = (Hashes.hash_type.in_(
        (7500, 13100, 18200, 19600, 19700, 19800, 19900, 35300, 35400)),)
    dcc2_filter = (Hashes.hash_type == 2100,)

    # ---- Longest recovered passwords ----
    # Load the full pool of cracked, non-network passwords for the year, decode
    # any $HEX[..] plaintexts, and rank by the DECODED length in Python — SQL
    # length() would measure the $HEX[..] wrapper and over-rank encoded entries.
    # This one pool drives the top-10 table, the user's longest, its global rank,
    # and the "out of N" denominator, so they all stay consistent.
    longest_rows = in_year(
        db.session.query(Hashes.plaintext, Hashes.recovered_at, Hashes.recovered_by)
        .filter(Hashes.cracked == '1')
        .filter(Hashes.hash_type.notin_(excluded_hash_types_for_length))).all()
    longest_pool = []
    for r in longest_rows:
        raw = r.plaintext or ''
        decoded = _decode_plain(raw)
        longest_pool.append({'plaintext': raw, 'decoded': decoded,
                             'is_hex': raw.startswith('$HEX['), 'length': len(decoded),
                             'recovered_at': r.recovered_at, 'recovered_by': r.recovered_by})
    longest_pool.sort(key=lambda d: (-d['length'], d['recovered_at']))
    longest_password_total_cnt = len(longest_pool)

    emails = {u.id: u.email_address for u in Users.query.all()}
    longest_password_all_table = [
        {'length': d['length'], 'recovered_at': d['recovered_at'],
         'plaintext': d['plaintext'], 'decoded': d['decoded'], 'is_hex': d['is_hex'],
         'email_address': emails.get(d['recovered_by'], '(unknown)')}
        for d in longest_pool[:10]]

    longest_password_personal = ''        # decoded (the real password)
    longest_password_personal_raw = ''    # as stored ($HEX[..] when non-UTF-8)
    longest_password_personal_is_hex = False
    longest_password_personal_rank = None
    for i, d in enumerate(longest_pool):
        if d['recovered_by'] == uid:
            longest_password_personal = d['decoded']
            longest_password_personal_raw = d['plaintext']
            longest_password_personal_is_hex = d['is_hex']
            longest_password_personal_rank = i + 1
            break
    longest_password_personal_len = len(longest_password_personal)

    # ---- Total passwords recovered ----
    most_passwords_recovered_all_table = leaderboard()
    total_ids = ranked_ids()
    total_passwords_recovered_personal_cnt = personal_cnt()
    total_passwords_recovered_personal_pct = _percentile_top(total_ids, uid)
    total_passwords_recovered_personal_rank = _rank_of(total_ids, uid)

    # ---- NTLM (1000) ----
    total_ntlm_recovered_all_table = leaderboard(*ntlm_filter)
    total_ntlm_recovered_personal_cnt = personal_cnt(*ntlm_filter)
    total_ntlm_recovered_personal_pct = _percentile_top(ranked_ids(*ntlm_filter), uid)

    # ---- NetNTLMv1 (5500/27000) ----
    total_ntlmv1_recovered_all_table = leaderboard(*ntlmv1_filter)
    total_ntlmv1_recovered_personal_cnt = personal_cnt(*ntlmv1_filter)
    total_ntlmv1_recovered_personal_pct = _percentile_top(ranked_ids(*ntlmv1_filter), uid)

    # ---- NetNTLMv2 (5600/27100) ----
    total_ntlmv2_recovered_all_table = leaderboard(*ntlmv2_filter)
    total_ntlmv2_recovered_personal_cnt = personal_cnt(*ntlmv2_filter)
    total_ntlmv2_recovered_personal_pct = _percentile_top(ranked_ids(*ntlmv2_filter), uid)

    # ---- Kerberos ----
    total_kerberos_recovered_all_table = leaderboard(*kerberos_filter)
    total_kerberos_recovered_personal_cnt = personal_cnt(*kerberos_filter)
    total_kerberos_recovered_personal_pct = _percentile_top(ranked_ids(*kerberos_filter), uid)

    # ---- DCC2 (2100) ----
    total_dcc2_recovered_all_table = leaderboard(*dcc2_filter)
    total_dcc2_recovered_personal_cnt = personal_cnt(*dcc2_filter)
    total_dcc2_recovered_personal_pct = _percentile_top(ranked_ids(*dcc2_filter), uid)

    # ---- Most effective tasks (overall + per hash type) ----
    most_effective_tasks_table = effective_tasks()
    most_effective_tasks_ntlm_table = effective_tasks(*ntlm_filter)
    most_effective_tasks_ntlmv1_table = effective_tasks(*ntlmv1_filter)
    most_effective_tasks_ntlmv2_table = effective_tasks(*ntlmv2_filter)
    most_effective_tasks_kerberos_table = effective_tasks(*kerberos_task_filter)
    most_effective_tasks_dcc2_table = effective_tasks(*dcc2_filter)

    # A short handle for the intro/finale + leaderboards: the email local-part
    # (e.g. "j.mercer@..." -> "j.mercer"), matching how crackers are listed.
    user_handle = (current_user.email_address or 'you').split('@')[0]

    return render_template(
        'wrapped.html.j2',
        title='Hashview Wrapped',
        year=year,
        user_handle=user_handle,
        longest_password_all_table=longest_password_all_table,
        longest_password_personal=longest_password_personal,
        longest_password_personal_raw=longest_password_personal_raw,
        longest_password_personal_is_hex=longest_password_personal_is_hex,
        longest_password_personal_len=longest_password_personal_len,
        longest_password_personal_rank=longest_password_personal_rank,
        longest_password_total_cnt=longest_password_total_cnt,
        most_passwords_recovered_all_table=most_passwords_recovered_all_table,
        total_passwords_recovered_personal_cnt=total_passwords_recovered_personal_cnt,
        total_passwords_recovered_personal_pct=total_passwords_recovered_personal_pct,
        total_passwords_recovered_personal_rank=total_passwords_recovered_personal_rank,
        total_ntlm_recovered_personal_cnt=total_ntlm_recovered_personal_cnt,
        total_ntlm_recovered_personal_pct=total_ntlm_recovered_personal_pct,
        total_ntlm_recovered_all_table=total_ntlm_recovered_all_table,
        total_ntlmv1_recovered_personal_cnt=total_ntlmv1_recovered_personal_cnt,
        total_ntlmv1_recovered_personal_pct=total_ntlmv1_recovered_personal_pct,
        total_ntlmv1_recovered_all_table=total_ntlmv1_recovered_all_table,
        total_ntlmv2_recovered_personal_cnt=total_ntlmv2_recovered_personal_cnt,
        total_ntlmv2_recovered_personal_pct=total_ntlmv2_recovered_personal_pct,
        total_ntlmv2_recovered_all_table=total_ntlmv2_recovered_all_table,
        total_kerberos_recovered_personal_cnt=total_kerberos_recovered_personal_cnt,
        total_kerberos_recovered_personal_pct=total_kerberos_recovered_personal_pct,
        total_kerberos_recovered_all_table=total_kerberos_recovered_all_table,
        total_dcc2_recovered_personal_cnt=total_dcc2_recovered_personal_cnt,
        total_dcc2_recovered_personal_pct=total_dcc2_recovered_personal_pct,
        total_dcc2_recovered_all_table=total_dcc2_recovered_all_table,
        most_effective_tasks_table=most_effective_tasks_table,
        most_effective_tasks_ntlm_table=most_effective_tasks_ntlm_table,
        most_effective_tasks_ntlmv1_table=most_effective_tasks_ntlmv1_table,
        most_effective_tasks_ntlmv2_table=most_effective_tasks_ntlmv2_table,
        most_effective_tasks_kerberos_table=most_effective_tasks_kerberos_table,
        most_effective_tasks_dcc2_table=most_effective_tasks_dcc2_table,
    )
