"""Flask routes to main page"""
import json
import re
from datetime import datetime, timedelta

from flask import Blueprint, flash, jsonify, make_response, redirect, render_template, request
from flask_login import current_user, login_required
from sqlalchemy import and_

from hashview.models import (
    Agents,
    Customers,
    Hashes,
    HashfileHashes,
    Jobs,
    JobTasks,
    Settings,
    Tasks,
    Users,
    db,
)
from hashview.utils.utils import (
    agent_telemetry,
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
    values = [
        Hashes.query.filter(
            and_(
                (Hashes.cracked == 1),
                (Hashes.recovered_at > today - timedelta(days=i + 1)),
                (Hashes.recovered_at < today - timedelta(days=i)),
            )
        ).count()
        for i in range(6, -1, -1)
    ]
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
    """Most-recent recovered passwords for the live feed (max 10, deduped)."""
    from hashview.jobs.forms import JobsNewHashFileForm
    hash_type_names = {}
    try:
        _f = JobsNewHashFileForm()
        for _sel in (_f.hash_type, _f.pwdump_hash_type, _f.netntlm_hash_type,
                     _f.kerberos_hash_type, _f.shadow_hash_type):
            for _v, _lab in _sel.choices:
                if _v is not None and str(_v) not in hash_type_names:
                    _nm = _lab.split(') ', 1)[1] if ') ' in _lab else _lab
                    hash_type_names[str(_v)] = _nm.split(' / ')[0].split(',')[0].strip()
    except Exception:  # pragma: no cover - defensive: never break the dashboard
        hash_type_names = {}

    users = Users.query.all()
    user_names = {u.id: ((u.first_name or '') + ' ' + (u.last_name or '')).strip() for u in users}

    # Last 10 recovered passwords, deduped by (hash_id, username). The hash↔hashfile_hashes
    # join is one-to-many (same hash across hashfiles / repeated username rows), so a plain
    # LIMIT 10 gets eaten by duplicates. We fetch a bounded window of the most-recent joined
    # rows and dedupe by (hash_id, username) — collapsing exact duplicates while keeping
    # distinct accounts that happen to share the same password.
    recent_rows = db.session.query(Hashes, HashfileHashes.username) \
        .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id) \
        .filter(Hashes.cracked == True) \
        .filter(Hashes.recovered_at.isnot(None)) \
        .order_by(Hashes.recovered_at.desc()) \
        .limit(100).all()
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
        })
        if len(recovery_feed) >= 10:
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


def _eta_text(raw):
    """Extract hashcat's '(3h 22m)' portion from a Time_Estimated string."""
    if raw and '(' in raw:
        return raw.split('(', 1)[1].split(')', 1)[0]
    return ''


def _eta_seconds(text):
    """Loosely parse an ETA like '1d 2h 3m 4s' to seconds (0 if unparseable)."""
    unit = {'d': 86400, 'h': 3600, 'm': 60, 's': 1}
    return sum(int(n) * unit[u] for n, u in re.findall(r'(\d+)\s*([dhms])', text or ''))


def _job_task_groups(running_jobs, job_tasks, tasks_by_id, agents_by_id,
                     recovered_list, time_estimated_list):
    """Group each running job's JobTasks by task_id into per-task summary rows.

    With chunking on, a task fans out into many JobTasks; the dashboard shows one
    parent row per task (status, chunk progress, summed rate, recovered, eta) and
    expands to its ACTIVE (Running) chunks. Returns
    {job_id: {groups: [...], tasks_total/done/running, chunks_total/done/active}}.
    """
    running_ids = {j.id for j in running_jobs}
    task_ids = {jt.task_id for jt in job_tasks if jt.job_id in running_ids}
    # Recovered count per (hashfile, task): cracked hashes credited to the task
    # that actually live in THIS job's hashfile. Scoping by hashfile_id matters
    # because a task is reusable across jobs/hashfiles -- counting Hashes.task_id
    # alone credited cracks from every other job that ran the same task. Counted
    # per HashfileHashes (account) row, matching the recovered counts shown
    # elsewhere (job-completion email, analytics).
    hashfile_ids = {j.hashfile_id for j in running_jobs}
    recovered_by_hf_task = {}
    if task_ids and hashfile_ids:
        rows = (db.session.query(HashfileHashes.hashfile_id, Hashes.task_id,
                                 db.func.count(HashfileHashes.id))
                .join(Hashes, Hashes.id == HashfileHashes.hash_id)
                .filter(Hashes.cracked == 1,
                        Hashes.task_id.in_(task_ids),
                        HashfileHashes.hashfile_id.in_(hashfile_ids))
                .group_by(HashfileHashes.hashfile_id, Hashes.task_id)
                .all())
        for hf_id, tid, cnt in rows:
            recovered_by_hf_task[(hf_id, tid)] = cnt

    out = {}
    for job in running_jobs:
        order, by_task = [], {}
        for jt in job_tasks:
            if jt.job_id != job.id:
                continue
            if jt.task_id not in by_task:
                by_task[jt.task_id] = []
                order.append(jt.task_id)
            by_task[jt.task_id].append(jt)

        groups = []
        chunks_total = chunks_done = chunks_active = 0
        for task_id in order:
            chunks = by_task[task_id]
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
            if running:
                status = 'Running'
            elif queued:
                status = 'Queued'
            elif canceled:
                status = 'Canceled'
            elif completed == total:
                status = 'Completed'
            else:
                status = 'Queued'

            is_chunked = total > 1 or any(c.chunk_total for c in chunks)
            active, rate_hps = [], 0.0
            for c in sorted((c for c in chunks if c.status == 'Running'),
                            key=lambda c: (c.chunk_no or 0)):
                agent = agents_by_id.get(c.agent_id)
                bench = agent.benchmark if agent else None
                rate_hps += _hps(bench)
                rec = recovered_list.get(c.agent_id, '')
                active.append({
                    'chunk_no': c.chunk_no,
                    'chunk_total': c.chunk_total,
                    'agent': agent.name if agent else '—',
                    'rate': bench or '—',
                    'recovered': rec.split(' ')[0] if rec else '',
                    'eta': _eta_text(time_estimated_list.get(c.agent_id, '')),
                })
            eta = (max((a['eta'] for a in active), key=_eta_seconds, default='')
                   if active else '')

            task = tasks_by_id.get(task_id)
            groups.append({
                'task_id': task_id,
                'name': task.name if task else ('task %s' % task_id),
                'attack': _attack_label(task),
                'status': status,
                'total': total, 'completed': completed, 'running': running,
                'queued': queued, 'canceled': canceled,
                'is_chunked': is_chunked,
                'expandable': bool(running) and is_chunked,
                'recovered': recovered_by_hf_task.get((job.hashfile_id, task_id), 0),
                'rate': _fmt(rate_hps) if rate_hps else '',
                'eta': eta,
                'active_chunks': active,
            })

        out[job.id] = {
            'groups': groups,
            'tasks_total': len(groups),
            'tasks_done': sum(1 for g in groups if g['status'] == 'Completed'),
            'tasks_running': sum(1 for g in groups if g['status'] == 'Running'),
            'chunks_total': chunks_total,
            'chunks_done': chunks_done,
            'chunks_active': chunks_active,
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
    return {
        'running_jobs': running_jobs,
        'queued_jobs': queued_jobs,
        'users': Users.query.all(),
        'customers': Customers.query.all(),
        'job_tasks': job_tasks,
        'tasks': tasks,
        'settings': Settings.query.first(),
        'datetime': datetime,
        'timedelta': timedelta,
        'job_dash': _job_task_groups(running_jobs, job_tasks, tasks_by_id, agents_by_id,
                                     agents_ctx['recovered_list'], agents_ctx['time_estimated_list']),
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
            update_job_task_status(job_task.id, 'Canceled')
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
        for jt in JobTasks.query.filter_by(job_id=job_id, task_id=task_id).all():
            if jt.status in ('Running', 'Queued', 'Not Started', 'Importing'):
                update_job_task_status(jt.id, 'Canceled')
    else:
        flash('You are unauthorized to stop this task', 'danger')

    return redirect("/")
