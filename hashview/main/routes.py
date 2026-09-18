"""Flask routes to main page"""
import json
import re
from datetime import datetime, timedelta

from flask import Blueprint, flash, jsonify, make_response, redirect, render_template, request
from flask_login import current_user, login_required
from sqlalchemy import and_, case

from hashview import jinja_human_count as _human
from hashview.models import (
    Agents,
    Customers,
    Hashes,
    HashfileHashes,
    Jobs,
    JobTaskLedger,
    JobTasks,
    Settings,
    Tasks,
    Users,
    db,
)
from hashview.utils.audit import job_task_target, log_event
from hashview.utils.utils import (
    agent_telemetry,
    close_ledger,
    is_chunk_row,
    job_assignments,
    update_job_task_status,
)
from hashview.utils.utils import (
    fmt_hps as _fmt,
)
from hashview.utils.utils import (
    parse_hps as _hps,
)

main = Blueprint('main', __name__)

def _chart_data():
    """7-day 'passwords recovered' series: (labels, values), oldest→newest.

    `values` is a per-day count of cracked hashes; it drives both the line chart and
    the 'Recovered today' / 'Cracked this week' KPIs.
    """
    today = datetime.now()
    labels = [(today - timedelta(days=i)).strftime("%b-%d") for i in range(6, -1, -1)]

    # One index-bounded query with a conditional SUM per rolling 24h window, instead
    # of 7 separate COUNTs. The WHERE bounds the scan to the 7-day window (served by
    # the (cracked, recovered_at) index); the per-bucket CASE uses the exact same
    # exclusive window bounds as before, so the numbers are unchanged.
    bounds = [(today - timedelta(days=i + 1), today - timedelta(days=i)) for i in range(6, -1, -1)]
    buckets = [
        db.func.coalesce(db.func.sum(case(
            (and_(Hashes.recovered_at > lo, Hashes.recovered_at < hi), 1), else_=0)), 0)
        for lo, hi in bounds
    ]
    row = db.session.query(*buckets).filter(
        and_(
            Hashes.cracked == 1,
            Hashes.recovered_at > today - timedelta(days=7),
            Hashes.recovered_at < today,
        )
    ).first()
    values = [int(v or 0) for v in row] if row else [0] * 7
    return labels, values


def _relative_time(dt):
    """Human 'N <unit> ago' for the recovery feed's Time column.

    Under 24h shows the largest fitting unit (seconds / minutes / hours); at or
    beyond 24h shows days. ``dt`` is the naive local ``recovered_at`` (set with
    datetime.today()), so it is compared against a naive local ``now`` from the
    same host.
    """
    if not dt:
        return '—'
    secs = int((datetime.now() - dt).total_seconds())
    if secs < 0:
        secs = 0
    if secs < 60:
        n, unit = secs, 'second'
    elif secs < 3600:
        n, unit = secs // 60, 'minute'
    elif secs < 86400:
        n, unit = secs // 3600, 'hour'
    else:
        n, unit = secs // 86400, 'day'
    return '%d %s%s ago' % (n, unit, '' if n == 1 else 's')


def _recovery_feed():
    """Most-recent recovered passwords for the live feed (max 100, deduped)."""
    from hashview.jobs.forms import JobsNewHashFileForm
    hash_type_names = {}
    try:
        _f = JobsNewHashFileForm()
        for _sel in (_f.hash_type, _f.pwdump_hash_type, _f.netntlm_hash_type,
                     _f.kerberos_hash_type, _f.shadow_hash_type):
            for _v, _lab in _sel.choices:
                if _v is not None and str(_v).isdigit() and str(_v) not in hash_type_names:
                    _nm = _lab.split(') ', 1)[1] if ') ' in _lab else _lab
                    hash_type_names[str(_v)] = _nm.split(' / ')[0].split(',')[0].strip()
    except Exception:  # pragma: no cover - defensive: never break the dashboard
        hash_type_names = {}

    users = Users.query.all()
    user_names = {u.id: ((u.first_name or '') + ' ' + (u.last_name or '')).strip() for u in users}
    # Which attack actually recovered it. Hashes.task_id is stamped at upload
    # time, so a hash cracked before that column existed -- or by a task since
    # deleted -- resolves to nothing and shows an em dash rather than a bare id.
    task_names = {t.id: t.name for t in Tasks.query.all()}

    # Last 100 recovered passwords, deduped by (hash_id, username). The hash↔hashfile_hashes
    # join is one-to-many (same hash across hashfiles / repeated username rows), so a plain
    # LIMIT gets eaten by duplicates. We fetch a wider window of the most-recent joined rows
    # and dedupe by (hash_id, username) — collapsing exact duplicates while keeping distinct
    # accounts that happen to share the same password — then cap the output at 100.
    recent_rows = db.session.query(Hashes, HashfileHashes.username) \
        .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id) \
        .filter(Hashes.cracked == True) \
        .filter(Hashes.recovered_at.isnot(None)) \
        .order_by(Hashes.recovered_at.desc()) \
        .limit(500).all()
    recovery_feed = []
    seen = set()
    for h, username in recent_rows:
        key = (h.id, username)
        if key in seen:
            continue
        seen.add(key)
        recovery_feed.append({
            'key': f'{h.id}:{username}',
            'time': _relative_time(h.recovered_at),
            # usernames/plaintexts are stored as plain text now; use as-is.
            'account': (username or '') or '—',
            'plaintext': h.plaintext or '',
            'type': hash_type_names.get(str(h.hash_type), str(h.hash_type)),
            'recovered_by': user_names.get(h.recovered_by) or '—',
            'task': task_names.get(h.task_id) or '—',
        })
        if len(recovery_feed) >= 100:
            break
    return recovery_feed


def _agents_ctx():
    """Agents + their parsed hashcat progress.

    Shared by the running-job task table and the agent-fleet modal so the hc_status
    parse lives in one place.
    """
    agents = Agents.query.all()
    recovered_list = {}
    time_estimated_list = {}
    for agent in agents:
        if agent.hc_status:
            hc = json.loads(agent.hc_status)
            recovered_list[agent.id] = hc['Recovered']
            time_estimated_list[agent.id] = hc['Time_Estimated']
    return {
        'agents': agents,
        'recovered_list': recovered_list,
        'time_estimated_list': time_estimated_list,
        'telemetry': agent_telemetry(agents),
    }


_ATTACK_LABELS = {1: 'Combinator', 3: 'Mask',
                  6: 'Hybrid (wordlist + mask)', 7: 'Hybrid (mask + wordlist)'}


# _hps / _fmt are imported (aliased) from hashview.utils.utils — single source for
# speed parsing/formatting shared by the dashboard, sidebar KPIs and agent util.


def _attack_label(task):
    """Short attack descriptor shown under a task name."""
    if task is None:
        return ''
    if task.hc_attackmode == 0:
        return 'Dict + Rule' if task.rule_id else 'Dictionary'
    return _ATTACK_LABELS.get(task.hc_attackmode, 'mode %s' % task.hc_attackmode)


def _eta_compact(text):
    """Rewrite a spelled-out duration as '1d 2h 3m 4s'.

    hashcat writes the units out in full -- '(2 hours, 48 minutes)' -- while the
    elapsed and runtime figures beside this column are already 'Xh Ym', so the
    ETA was the odd one out and the widest thing in a narrow column.

    Matched on each unit's leading letter, unambiguous across the four hashcat
    emits (days/hours/minutes/seconds, singular or plural). Anything that does
    not parse cleanly is returned untouched rather than guessed at: the agent's
    non-duration sentinels ("The specified time is in the past.") reach this
    function too, and mangling one into a plausible-looking duration would be
    worse than passing it through. Already-short input is unchanged.
    """
    if not text:
        return text
    parts = re.findall(r'(\d+)\s*([A-Za-z]+)', text)
    if not parts:
        return text
    out = []
    for count, word in parts:
        initial = word[0].lower()
        if initial not in ('d', 'h', 'm', 's'):
            return text
        out.append(count + initial)
    return ' '.join(out)


def _eta_text(raw):
    """hashcat's '(...)' portion of a Time_Estimated string, in the short form
    the dashboard's other durations use."""
    if raw and '(' in raw:
        return _eta_compact(raw.split('(', 1)[1].split(')', 1)[0])
    return ''


def _eta_seconds(text):
    """Loosely parse an ETA like '1d 2h 3m 4s' to seconds (0 if unparseable)."""
    unit = {'d': 86400, 'h': 3600, 'm': 60, 's': 1}
    return sum(int(n) * unit[u] for n, u in re.findall(r'(\d+)\s*([dhms])', text or ''))


def _short_duration(seconds):
    """Seconds as '1d 2h 3m 4s', largest two units that matter, or '0s'.

    Matches the ETA column's short units so the two read as the same kind of
    thing. Anything already past its deadline is '0s' rather than a negative:
    the reaper cancels on the next heartbeat, so the honest reading is "any
    moment now", not "-4m".
    """
    seconds = int(seconds)
    if seconds <= 0:
        return '0s'
    parts = []
    for unit, size in (('d', 86400), ('h', 3600), ('m', 60), ('s', 1)):
        if seconds >= size:
            parts.append('%d%s' % (seconds // size, unit))
            seconds %= size
    return ' '.join(parts[:2])


def _job_task_groups(running_jobs, job_tasks, tasks_by_id, agents_by_id,
                     recovered_list, time_estimated_list, max_runtime_tasks=0):
    """Group each running job's JobTasks by task_id into per-task summary rows.

    With chunking on, a task fans out into many JobTasks; the dashboard shows one
    parent row per task (status, chunk progress, summed rate, recovered, eta) and
    expands to its ACTIVE (Running) chunks. Returns
    {job_id: {groups: [...], tasks_total/done/running, chunks_total/done/active}}.
    """
    hashfile_ids = {j.hashfile_id for j in running_jobs}
    # The Recovered column reads X/Y where Y is the hashfile's TOTAL accounts.
    # It briefly showed "unrecovered left" (total minus already-cracked), which
    # made Y shrink as X grew -- two moving numbers, and a ratio that never
    # reached 1. The cracked-per-hashfile query that fed that subtraction is gone
    # with it, one fewer aggregate per dashboard poll.

    # Total accounts (HashfileHashes rows) per hashfile.
    hashfile_totals = {}
    if hashfile_ids:
        rows = (db.session.query(HashfileHashes.hashfile_id,
                                 db.func.count(HashfileHashes.id))
                .filter(HashfileHashes.hashfile_id.in_(hashfile_ids))
                .group_by(HashfileHashes.hashfile_id)
                .all())
        for hf_id, cnt in rows:
            hashfile_totals[hf_id] = cnt

    # Attacks, keyed by ledger id. Grouping on task_id merged two assignments of
    # the same dynamic-wordlist task into one row, and cannot express queue order
    # at all once slices are issued on demand.
    ledgers_by_id, ledger_order = {}, {}
    for ledger in JobTaskLedger.query.order_by(JobTaskLedger.position.asc(),
                                               JobTaskLedger.id.asc()).all():
        ledgers_by_id[ledger.id] = ledger
        ledger_order.setdefault(ledger.job_id, []).append(ledger.id)

    out = {}
    for job in running_jobs:
        order, by_task = [], {}
        for key in ledger_order.get(job.id, []):
            by_task[key] = []
            order.append(key)
        for jt in job_tasks:
            if jt.job_id != job.id:
                continue
            # Pre-ledger rows have no attack to belong to; group them by task as
            # before so a job queued before the upgrade still renders.
            key = jt.ledger_id if jt.ledger_id in by_task else ('task', jt.task_id)
            if key not in by_task:
                by_task[key] = []
                order.append(key)
            by_task[key].append(jt)

        # Hashes recovered by each task for THIS job's hashfile since the current
        # run started (recovered_at >= job.started_at), counted per account.
        task_ids_here = {ledgers_by_id[k].task_id if k in ledgers_by_id else k[1]
                         for k in by_task}
        recovered_by_task = {}
        if job.hashfile_id and job.started_at and task_ids_here:
            rows = (db.session.query(Hashes.task_id, db.func.count(HashfileHashes.id))
                    .join(HashfileHashes, HashfileHashes.hash_id == Hashes.id)
                    .filter(Hashes.cracked == 1,
                            Hashes.task_id.in_(list(task_ids_here)),
                            HashfileHashes.hashfile_id == job.hashfile_id,
                            Hashes.recovered_at >= job.started_at)
                    .group_by(Hashes.task_id)
                    .all())
            recovered_by_task = {tid: cnt for tid, cnt in rows}

        groups = []
        chunks_total = chunks_done = chunks_active = 0
        ks_total_job = ks_done_job = ks_running_job = 0
        for key in order:
            chunks = by_task[key]
            ledger = ledgers_by_id.get(key)
            task_id = ledger.task_id if ledger else key[1]
            total = len(chunks)
            completed = sum(1 for c in chunks if c.status == 'Completed')
            running = sum(1 for c in chunks if c.status == 'Running')
            canceled = sum(1 for c in chunks if c.status == 'Canceled')
            queued = sum(1 for c in chunks if c.status in ('Queued', 'Not Started'))
            chunks_total += total
            chunks_done += completed
            chunks_active += running

            # Derive the parent status, preferring "canceled" in the terminal state.
            # A canceled task often has some chunks that finished before the stop (or
            # a race completes one mid-cancel); checking canceled == total here would
            # let that Completed+Canceled mix fall through to 'Queued'. So: running
            # wins; then any still-pending work is 'Queued'; otherwise (terminal) a
            # single canceled chunk makes the task 'Canceled'; else all-done.
            # Keyspace, which is a denominator that does not move. A row count
            # does: slices are issued on demand, so 'total' grows through a run
            # and a bar computed from it snaps toward 100% then jumps backwards.
            ks_total = int(ledger.keyspace) if (ledger and ledger.keyspace) else 0
            ks_done = sum(int(c.chunk_keyspace or 0) for c in chunks
                          if c.status == 'Completed') if ks_total else 0
            ks_running = sum(int(c.chunk_keyspace or 0) for c in chunks
                             if c.status == 'Running') if ks_total else 0
            ks_unissued = max(ks_total - int(ledger.keyspace_pos or 0), 0) if ledger else 0
            ks_total_job += ks_total
            ks_done_job += ks_done
            ks_running_job += ks_running

            if running:
                status = 'Running'
            elif ledger is not None and ledger.state in ('Ready', 'Pending') and (
                    ledger.keyspace is None or ledger.keyspace_pos < ledger.keyspace):
                # Keyspace still unissued: the attack is BETWEEN slices, not done.
                # The old row-count test read that gap as 'Completed'.
                status = 'Measuring' if ledger.state == 'Pending' else 'Queued'
            elif queued:
                status = 'Queued'
            elif canceled:
                status = 'Canceled'
            elif completed == total:
                status = 'Completed'
            else:
                status = 'Queued'

            is_chunked = bool(ledger.chunkable) if ledger else (
                total > 1 or any(is_chunk_row(c) for c in chunks))
            active, rate_hps = [], 0.0
            for c in sorted((c for c in chunks if c.status == 'Running'),
                            key=lambda c: (c.chunk_no or 0)):
                agent = agents_by_id.get(c.agent_id)
                bench = agent.benchmark if agent else None
                rate_hps += _hps(bench)
                rec = recovered_list.get(c.agent_id, '')
                rec_str = rec.split(' ')[0] if rec else ''   # hashcat "X/Y" (drop the %)
                # Chunk X = hashcat's recovered count for this agent's session. The
                # /Y denominator shown in the template is the hashfile's total
                # accounts (hashfile_total), same as the task row -- so hashcat's
                # own total is dropped here. Numeric so |commafy adds thousands
                # separators.
                rec_x = None
                if rec_str:
                    head = rec_str.split('/')[0]
                    rec_x = int(head) if head.isdigit() else None
                # Built here rather than composed in Jinja: chunk_no is NULL on a
                # whole run, and {{ None }} renders the literal string 'None'.
                active.append({
                    'chunk_no': c.chunk_no,
                    'chunk_total': c.chunk_total,
                    'label': ('#%d' % c.chunk_no) if c.chunk_no else '—',
                    # Bare count: this renders under the Keyspace COLUMN, where
                    # "1.2B keyspace" would repeat the header back at the reader.
                    'keyspace': (_human(c.chunk_keyspace)
                                 if c.chunk_keyspace else ''),
                    'agent': agent.name if agent else '—',
                    'rate': bench or '—',
                    'recovered': rec_x,
                    'eta': _eta_text(time_estimated_list.get(c.agent_id, '')),
                })
            eta = (max((a['eta'] for a in active), key=_eta_seconds, default='')
                   if active else '')

            # Distinct agent(s) currently working this task (from its Running
            # chunks): a single name, or "Nx Agents" when chunked across several.
            agent_names = sorted({a['agent'] for a in active
                                  if a['agent'] and a['agent'] != '—'})
            if len(agent_names) == 1:
                agent_display = agent_names[0]
            elif len(agent_names) > 1:
                agent_display = '%dx Agents' % len(agent_names)
            else:
                agent_display = ''

            # Time left before Settings.max_runtime_tasks cancels this attack.
            # Measured from the EARLIEST chunk start, which is what the cap itself
            # uses (api/routes.py _parent_task_started_at): a task fans out across
            # agents, so any single chunk's started_at would under-report the
            # parent's elapsed time and the column would disagree with the reaper.
            # None whenever there is nothing to say -- cap disabled, or the attack
            # has not started -- and the column is hidden entirely in that case.
            cancel_in = None
            if max_runtime_tasks and status == 'Running':
                starts = [c.started_at for c in chunks if c.started_at is not None]
                if starts:
                    deadline = min(starts) + timedelta(hours=max_runtime_tasks)
                    cancel_in = _short_duration(
                        (deadline - datetime.now()).total_seconds())

            task = tasks_by_id.get(task_id)
            groups.append({
                'entry_id': key if ledger else ('t%s' % task_id),
                'task_id': task_id,
                'name': task.name if task else ('task %s' % task_id),
                'attack': _attack_label(task),
                'status': status,
                'total': total, 'completed': completed, 'running': running,
                'queued': queued, 'canceled': canceled,
                'ks_total': ks_total, 'ks_done': ks_done,
                'ks_running': ks_running, 'ks_unissued': ks_unissued,
                'is_chunked': is_chunked,
                'expandable': bool(running) and is_chunked,
                'agent_display': agent_display,
                'recovered': recovered_by_task.get(task_id, 0),
                'rate': _fmt(rate_hps) if rate_hps else '',
                'eta': eta,
                'cancel_in': cancel_in,
                'active_chunks': active,
            })

        out[job.id] = {
            'groups': groups,
            'hashfile_total': hashfile_totals.get(job.hashfile_id, 0),
            'tasks_total': len(groups),
            'tasks_done': sum(1 for g in groups if g['status'] == 'Completed'),
            'tasks_running': sum(1 for g in groups if g['status'] == 'Running'),
            'chunks_total': chunks_total,
            'chunks_done': chunks_done,
            'chunks_active': chunks_active,
            'ks_total': ks_total_job,
            'ks_done': ks_done_job,
            'ks_running': ks_running_job,
            'tasks_measuring': sum(1 for g in groups if g['status'] == 'Measuring'),
        }
    return out


def _jobs_ctx():
    """Template context for the running-job cards + queue table.

    Shared by the full page (home) and the /dashboard/jobs poll so the markup has a
    single source of truth.
    """
    running_jobs = Jobs.query.filter_by(status='Running').order_by(Jobs.priority.desc(), Jobs.queued_at.asc()).all()
    queued_jobs = Jobs.query.filter_by(status='Queued').order_by(Jobs.priority.desc(), Jobs.queued_at.asc()).all()
    job_tasks = JobTasks.query.all()
    tasks = Tasks.query.all()
    agents_ctx = _agents_ctx()
    tasks_by_id = {t.id: t for t in tasks}
    agents_by_id = {a.id: a for a in agents_ctx['agents']}
    settings = Settings.current()
    # Attack counts for the queue table, off the ledger. Counting raw rows there
    # was wrong in two directions at once: a chunked attack counted once per
    # chunk, and under on-demand minting a freshly queued job has no rows yet, so
    # the column read 0 for exactly the jobs the queue table exists to show.
    attack_counts = {job_id: len(entries) for job_id, entries
                     in job_assignments([j.id for j in queued_jobs]).items()}
    return {
        'attack_counts': attack_counts,
        'running_jobs': running_jobs,
        'queued_jobs': queued_jobs,
        'users': Users.query.all(),
        'customers': Customers.query.all(),
        'job_tasks': job_tasks,
        'tasks': tasks,
        'settings': settings,
        'datetime': datetime,
        'timedelta': timedelta,
        'job_dash': _job_task_groups(running_jobs, job_tasks, tasks_by_id, agents_by_id,
                                     agents_ctx['recovered_list'], agents_ctx['time_estimated_list'],
                                     max_runtime_tasks=(settings.max_runtime_tasks
                                                        if settings else 0) or 0),
        **agents_ctx,
    }


@main.route("/")
@login_required
def home():
    """Render the operations dashboard."""
    fig1_labels, fig1_values = _chart_data()
    now = datetime.now()
    # Dashboard flourish: auto-runs once per user on the first visit of April 1
    # (server time); the cookie records it so it doesn't repeat that year.
    dash_autoplay = (now.month == 4 and now.day == 1
                     and request.cookies.get('hv_dash') != str(now.year))
    resp = make_response(render_template(
        'home.html.j2',
        fig1_labels=fig1_labels,
        fig1_values=fig1_values,
        recovery_feed=_recovery_feed(),
        dash_autoplay=dash_autoplay,
        **_jobs_ctx(),
    ))
    if dash_autoplay:
        resp.set_cookie('hv_dash', str(now.year), max_age=60 * 60 * 24 * 2, samesite='Lax')
    return resp


@main.route("/dashboard/jobs")
@login_required
def dashboard_jobs():
    """HTML fragment: running-job cards + queue table (polled ~20s)."""
    return render_template('_dash_jobs.html.j2', **_jobs_ctx())


@main.route("/dashboard/recovery")
@login_required
def dashboard_recovery():
    """HTML fragment: live recovery feed table (polled ~5s)."""
    return render_template('_dash_recovery.html.j2', recovery_feed=_recovery_feed())


@main.route("/dashboard/fleet")
@login_required
def dashboard_fleet():
    """HTML fragment: agent-fleet modal contents (polled ~20s while the modal is open).

    agent_stats is supplied by the inject_nav_counts() context processor.
    """
    return render_template('_dash_fleet.html.j2', **_agents_ctx())


@main.route("/dashboard/summary")
@login_required
def dashboard_summary():
    """JSON: rendered KPI cards + chart series (polled ~15s).

    Computes the 7×COUNT chart data once and feeds both the KPI row and the line
    chart. agent_stats / job_queue are supplied to the KPI partial by the global
    inject_nav_counts() context processor.
    """
    fig1_labels, fig1_values = _chart_data()
    return jsonify({
        'status': 'ok',
        'kpis_html': render_template('_dash_kpis.html.j2', fig1_values=fig1_values),
        'chart': {'labels': fig1_labels, 'values': fig1_values},
    })

@main.route("/job_task/stop/<int:job_task_id>")
@login_required
def stop_job_task(job_task_id):
    """Function to stop specific task on a running job"""

    job_task = JobTasks.query.get(job_task_id)
    job = Jobs.query.get(job_task.job_id)

    if job_task and job:
        if current_user.admin or job.owner_id == current_user.id:
            # Stopping ONE slice of an attack that still has a cursor is not a
            # coherent request: the attack would just issue the next slice, and
            # meanwhile the cancelled range is a permanent hole below the cursor
            # that nothing will ever re-run. Stop the whole attack.
            if job_task.ledger_id is None or not close_ledger(
                    job.id, 'canceled', ledger_id=job_task.ledger_id):
                update_job_task_status(job_task.id, 'Canceled')
            # Logged after the cancel, on BOTH branches: the fallback is the one
            # a pre-ledger job takes, and it would otherwise leave no record.
            log_event('task.cancel',
                      target=job_task_target(job, task_id=job_task.task_id),
                      detail=f'stopped by user from the dashboard (job_task:{job_task.id})')
        else:
            flash('You are unauthorized to stop this task', 'danger')

    return redirect("/")


@main.route("/job_task/stop_task/<int:job_id>/<int:task_id>")
@login_required
def stop_task(job_id, task_id):
    """Stop a whole task on a running job by canceling ALL of its chunks.

    The dashboard groups chunks under one parent row, so the parent stop must
    cancel every still-active chunk of the (job, task) rather than a single one.
    """
    job = Jobs.query.get(job_id)
    if job is None:
        flash('Job not found.', 'warning')
        return redirect("/")
    if current_user.admin or job.owner_id == current_user.id:
        # Closes the attack's ledger as well as its live rows; without that the
        # attack stays mintable and simply re-appears on the next heartbeat.
        if not close_ledger(job_id, 'canceled', task_id=task_id):
            for jt in JobTasks.query.filter_by(job_id=job_id, task_id=task_id).all():
                if jt.status in ('Running', 'Queued', 'Not Started', 'Importing'):
                    update_job_task_status(jt.id, 'Canceled')
        log_event('task.cancel', target=job_task_target(job, task_id=task_id),
                  detail='stopped by user from the dashboard')
    else:
        flash('You are unauthorized to stop this task', 'danger')

    return redirect("/")
