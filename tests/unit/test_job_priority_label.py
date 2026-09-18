"""The priority slider says what the number means, in words.

The wizard showed pips and "3/5" and nothing else, so a user moving the slider
had to already know whether 5 was the fastest or the slowest. The five values
now carry names, rendered server-side on first paint and updated by the slider's
own handler.

The vocabulary lives in exactly one place -- PRIORITY_NAMES in macros.html.j2 --
and reaches the browser through a data attribute rather than a second copy in
the JavaScript. These tests exist mostly to keep it that way: two lists that
agree today are two lists that disagree later.
"""

import json
import re

import pytest

from hashview.models import Settings
from hashview.models import db as _db
from tests.unit.helpers import login, make_admin

pytestmark = pytest.mark.security

EXPECTED = ['Lowest', 'Lower', 'Normal', 'Higher', 'Highest']


@pytest.fixture()
def wizard(app, client):
    """The job wizard with priority weighting enabled (it is hidden otherwise)."""
    with app.app_context():
        login(client, make_admin())
        _db.session.add(Settings(retention_period=30, max_runtime_jobs=0,
                                 max_runtime_tasks=0, enabled_job_weights=True))
        _db.session.commit()
        resp = client.get('/jobs/add', follow_redirects=True)
        assert resp.status_code == 200
        yield resp.get_data(as_text=True)


def test_the_slider_shows_a_word_for_the_default_priority(wizard):
    """Rendered server-side, so it is right before any JavaScript runs."""
    assert 'id="priority_word"' in wizard, 'no priority word element'
    match = re.search(r'id="priority_word".*?>([^<]*)</span>', wizard, re.S)
    assert match, 'the priority word element has no content'
    assert match.group(1).strip() == 'Normal', (
        f'the default priority reads {match.group(1).strip()!r}; 3 is the default')


def test_every_priority_value_has_a_name(wizard):
    """All five reach the browser, in slider order."""
    match = re.search(r"data-priority-names='([^']+)'", wizard)
    assert match, 'the slider carries no priority names for the JS to read'
    assert json.loads(match.group(1)) == EXPECTED


def test_the_names_match_the_forms_own_vocabulary():
    """One vocabulary for one concept.

    JobsForm.priority already labels these five values. A second, different set
    of words for the same numbers is how a UI ends up calling 4 'Higher' in one
    place and 'High' in another.
    """
    from hashview.jobs.forms import JobsForm

    choices = dict(JobsForm.priority.kwargs['choices'])
    for value, name in enumerate(EXPECTED, start=1):
        assert name.lower() in choices[str(value)].lower(), (
            f'priority {value} is {name!r} on the slider but '
            f'{choices[str(value)]!r} in JobsForm')


def test_the_javascript_holds_no_copy_of_the_words(wizard):
    """The JS must read the names, not restate them.

    A literal list in the handler would render correctly today and drift the
    first time the vocabulary changes, because only the server-side half would
    be updated.
    """
    script = wizard[wizard.index('function updatePriority'):]
    script = script[:script.index('</script>')]
    for name in EXPECTED:
        assert f"'{name}'" not in script and f'"{name}"' not in script, (
            f'{name!r} is hard-coded in updatePriority(); it should come from '
            'the slider data attribute')
    assert 'priorityNames' in script, 'the handler never reads the data attribute'


def test_a_chosen_priority_is_reflected_on_re_render(app, client):
    """A rejected submission re-renders the wizard; the word must follow it."""
    with app.app_context():
        login(client, make_admin())
        _db.session.add(Settings(retention_period=30, max_runtime_jobs=0,
                                 max_runtime_tasks=0, enabled_job_weights=True))
        _db.session.commit()

        # No customer_id -> validation fails -> the form re-renders with the data.
        body = client.post('/jobs/add', data={'name': 'prio', 'priority': '5'},
                           follow_redirects=True).get_data(as_text=True)

        match = re.search(r'id="priority_word".*?>([^<]*)</span>', body, re.S)
        assert match and match.group(1).strip() == 'Highest', (
            'the re-rendered wizard lost the chosen priority word')


def test_the_name_helper_tolerates_an_out_of_range_value(app):
    """Jobs.priority is a plain integer with no constraint."""
    with app.app_context():
        from flask import render_template_string
        rendered = render_template_string(
            '{% from "macros.html.j2" import priority_name %}'
            '{{ priority_name(0) }}|{{ priority_name(9) }}|{{ priority_name(3) }}')
        assert rendered == 'Normal|Normal|Normal'
