"""The web forms must not accept more characters than the database stores.

MySQL in strict mode (production) rejects an over-long INSERT with a DataError,
which reaches the user as a 500 with whatever they typed thrown away. SQLite
(what this suite runs on) silently truncates nothing and accepts everything, so
no ordinary functional test would ever notice the mismatch -- this module
compares the two sides directly instead.

The database is the authoritative side: when a column and a form disagree, the
form is what changes. ``hashview.utils.form_limits.db_length`` builds each
validator from the column itself so the two cannot drift, and ``FIELD_COLUMNS``
below pins which column each field lands in. ``NOT_PERSISTED`` lists the
single-line fields that are deliberately unbounded, each with its reason.

A new single-line form field belongs in exactly one of those two maps;
``test_every_single_line_field_is_classified`` fails until it is in one, which
is what keeps a newly added form from quietly shipping a mismatch.
"""

import importlib
import inspect
import re
from pathlib import Path

from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, TextAreaField
from wtforms.validators import Length

from hashview.models import (
    Agents,
    Customers,
    Hashfiles,
    Jobs,
    Rules,
    Settings,
    TaskGroups,
    Tasks,
    Users,
    Wordlists,
)
from hashview.utils.form_limits import column_length

FORM_MODULES = [
    'hashview.agents.forms',
    'hashview.customers.forms',
    'hashview.hashfiles.forms',
    'hashview.jobs.forms',
    'hashview.notifications.forms',
    'hashview.rules.forms',
    'hashview.searches.forms',
    'hashview.settings.forms',
    'hashview.setup.forms',
    'hashview.task_groups.forms',
    'hashview.tasks.forms',
    'hashview.users.forms',
    'hashview.wordlists.forms',
]

# (form class, field) -> (model, column) the value is stored in.
FIELD_COLUMNS = {
    ('AgentsForm', 'name'): (Agents, 'name'),
    ('CustomersForm', 'name'): (Customers, 'name'),
    ('HashfilesForm', 'name'): (Hashfiles, 'name'),
    ('JobsForm', 'name'): (Jobs, 'name'),
    # 'add new customer' on the job wizard creates a Customers row.
    ('JobsForm', 'customer_name'): (Customers, 'name'),
    ('JobsNewHashFileForm', 'name'): (Hashfiles, 'name'),
    ('LoginForm', 'email'): (Users, 'email_address'),
    ('HashviewSettingsForm', 'slack_bot_token'): (Settings, 'slack_bot_token'),
    ('HashviewSettingsForm', 'slack_admin_channel'): (Settings, 'slack_admin_channel'),
    ('HashviewSettingsForm', 'azure_tenant_id'): (Settings, 'azure_tenant_id'),
    ('HashviewSettingsForm', 'azure_client_id'): (Settings, 'azure_client_id'),
    ('HashviewSettingsForm', 'azure_client_secret'): (Settings, 'azure_client_secret'),
    ('HashviewSettingsForm', 'azure_redirect_uri'): (Settings, 'azure_redirect_uri'),
    ('HashviewSettingsForm', 'azure_allowed_groups'): (Settings, 'azure_allowed_groups'),
    ('ProfileForm', 'first_name'): (Users, 'first_name'),
    ('ProfileForm', 'last_name'): (Users, 'last_name'),
    ('ProfileForm', 'email'): (Users, 'email_address'),
    ('ProfileForm', 'pushover_user_key'): (Users, 'pushover_user_key'),
    ('ProfileForm', 'pushover_app_id'): (Users, 'pushover_app_id'),
    ('ProfileForm', 'slack_id'): (Users, 'slack_id'),
    ('RequestResetForm', 'email'): (Users, 'email_address'),
    ('RulesForm', 'name'): (Rules, 'name'),
    ('RulesEditForm', 'name'): (Rules, 'name'),
    ('SetupAdminPassForm', 'first_name'): (Users, 'first_name'),
    ('SetupAdminPassForm', 'last_name'): (Users, 'last_name'),
    ('SetupAdminPassForm', 'email_address'): (Users, 'email_address'),
    ('TaskGroupsForm', 'name'): (TaskGroups, 'name'),
    ('TasksForm', 'name'): (Tasks, 'name'),
    ('TasksForm', 'j_rule'): (Tasks, 'j_rule'),
    ('TasksForm', 'k_rule'): (Tasks, 'k_rule'),
    ('TasksForm', 'mask'): (Tasks, 'hc_mask'),
    ('ThemeForm', 'theme'): (Users, 'theme'),
    ('UsersForm', 'first_name'): (Users, 'first_name'),
    ('UsersForm', 'last_name'): (Users, 'last_name'),
    ('UsersForm', 'email'): (Users, 'email_address'),
    ('WordlistsForm', 'name'): (Wordlists, 'name'),
}

# Single-line fields whose value never reaches a VARCHAR column as typed.
NOT_PERSISTED = {
    ('AgentsForm', 'id'): 'the agent id, posted as a hidden field; an integer key',
    ('JobsForm', 'customer_id'): 'a <select> value: a customer id, or the "add_new" sentinel',
    ('SearchForm', 'query'): 'a search term; never written to the database',
    ('HashviewSettingsForm', 'retention_period'): 'numeric; a SmallInteger, range-checked',
    ('HashviewSettingsForm', 'max_runtime_jobs'): 'numeric; a SmallInteger, range-checked',
    ('HashviewSettingsForm', 'max_runtime_tasks'): 'numeric; a SmallInteger, range-checked',
    ('LoginForm', 'password'): 'compared against a hash; never stored',
    ('UsersForm', 'password'): 'bcrypt-hashed before storage (the digest is a fixed 60 chars)',
    ('UsersForm', 'confirm_password'): 'never stored; only compared with password',
    ('SetupAdminPassForm', 'password'): 'bcrypt-hashed before storage',
    ('SetupAdminPassForm', 'confirm_password'): 'never stored; only compared with password',
    ('ResetPasswordForm', 'password'): 'bcrypt-hashed before storage',
    ('ResetPasswordForm', 'confirm_password'): 'never stored; only compared with password',
}


def _form_classes():
    """Every FlaskForm subclass defined in hashview/*/forms.py."""
    for module_name in FORM_MODULES:
        module = importlib.import_module(module_name)
        for obj in vars(module).values():
            if (inspect.isclass(obj) and issubclass(obj, FlaskForm)
                    and obj is not FlaskForm and obj.__module__ == module_name):
                yield obj


def _single_line_fields(app):
    """(form class, field name, bound field) for every one-line text input.

    PasswordField subclasses StringField and is included on purpose: a password
    that is stored as typed would need the same bound as any other column. A
    TextAreaField is excluded -- those back TEXT columns, not VARCHAR.
    """
    with app.test_request_context():
        for form_class in _form_classes():
            form = form_class(meta={'csrf': False})
            for name, field in form._fields.items():
                if isinstance(field, StringField) and not isinstance(field, TextAreaField):
                    yield form_class, name, field


def _length_validators(field):
    return [v for v in field.validators if isinstance(v, Length)]


def test_form_class_names_are_unique():
    """The maps above are keyed on the class name alone, so it has to be unique."""
    names = [c.__name__ for c in _form_classes()]
    assert len(names) == len(set(names)), f'duplicate form class names: {sorted(names)}'


def test_every_single_line_field_is_classified(app):
    """A new single-line field must be declared either persisted or not.

    This is the guard that makes the rest of the file self-maintaining: add a
    form field and this fails until you have said which column it lands in (or
    that it lands in none), at which point the parity test below checks it.
    """
    unclassified = [
        (form_class.__name__, name)
        for form_class, name, _ in _single_line_fields(app)
        if (form_class.__name__, name) not in FIELD_COLUMNS
        and (form_class.__name__, name) not in NOT_PERSISTED
    ]
    assert not unclassified, (
        'New single-line form field(s) are not classified: '
        f'{sorted(unclassified)}. Add each to FIELD_COLUMNS in '
        'tests/unit/test_form_db_length_parity.py with the model column it is '
        'stored in (and give the field a db_length(...) validator), or to '
        'NOT_PERSISTED with the reason it never reaches a VARCHAR column.'
    )


def test_every_persisted_field_is_bounded_by_its_column(app):
    """Each persisted field carries exactly one Length whose max IS the column's."""
    problems = []
    for form_class, name, field in _single_line_fields(app):
        target = FIELD_COLUMNS.get((form_class.__name__, name))
        if target is None:
            continue
        model, column = target
        expected = column_length(model, column)
        lengths = _length_validators(field)
        if len(lengths) != 1:
            problems.append(
                f'{form_class.__name__}.{name}: expected one Length validator '
                f'bounded by {model.__name__}.{column} ({expected}), found {len(lengths)}')
            continue
        if lengths[0].max != expected:
            problems.append(
                f'{form_class.__name__}.{name}: Length(max={lengths[0].max}) but '
                f'{model.__name__}.{column} is VARCHAR({expected}) — the database '
                'is authoritative, so change the form (use db_length).')
    assert not problems, '\n'.join(problems)


def test_unpersisted_fields_stay_unbounded(app):
    """A field listed as not persisted has no business claiming a column limit.

    Keeps NOT_PERSISTED honest: if someone starts storing one of these, the
    validator they add makes this fail and pushes the field into FIELD_COLUMNS.
    """
    for form_class, name, field in _single_line_fields(app):
        if (form_class.__name__, name) not in NOT_PERSISTED:
            continue
        if isinstance(field, PasswordField):
            continue  # Length(min=14) on a password is a strength rule, not a column bound
        assert not _length_validators(field), (
            f'{form_class.__name__}.{name} is listed as NOT_PERSISTED but has a '
            'Length validator. If it is stored now, move it to FIELD_COLUMNS.')


def test_persisted_fields_render_a_matching_maxlength(app):
    """WTForms emits maxlength from the Length validator; prove it for real.

    The browser-side half of the fix. It is a hint, not a control -- every
    field above is also enforced server-side -- but it is what stops a user
    typing 300 characters into a 50-character field in the first place.
    """
    with app.test_request_context():
        forms = importlib.import_module('hashview.customers.forms')
        form = forms.CustomersForm(meta={'csrf': False})
        assert f'maxlength="{column_length(Customers, "name")}"' in form.name()


# --- the hand-written inputs in the modals ------------------------------------
#
# Several modals write their <input> elements out by hand instead of rendering a
# WTForms field, so they get no maxlength for free. Those inputs carry
# {{ db_maxlength('Model', 'column') }} instead, which reads the same column.

TEMPLATE_INPUTS = {
    ('customers.html.j2', 'name'): ('Customers', 'name'),
    ('jobs_add.html.j2', 'customer_name'): ('Customers', 'name'),
    ('layout.html.j2', 'first_name'): ('Users', 'first_name'),
    ('layout.html.j2', 'last_name'): ('Users', 'last_name'),
    ('layout.html.j2', 'email'): ('Users', 'email_address'),
    ('layout.html.j2', 'pushover_user_key'): ('Users', 'pushover_user_key'),
    ('layout.html.j2', 'pushover_app_id'): ('Users', 'pushover_app_id'),
    ('layout.html.j2', 'slack_id'): ('Users', 'slack_id'),
    ('task_groups.html.j2', 'name'): ('TaskGroups', 'name'),
    ('tasks.html.j2', 'name'): ('Tasks', 'name'),
    ('tasks.html.j2', 'mask'): ('Tasks', 'hc_mask'),
    ('tasks.html.j2', 'j_rule'): ('Tasks', 'j_rule'),
    ('tasks.html.j2', 'k_rule'): ('Tasks', 'k_rule'),
    ('users.html.j2', 'first_name'): ('Users', 'first_name'),
    ('users.html.j2', 'last_name'): ('Users', 'last_name'),
    ('users.html.j2', 'email'): ('Users', 'email_address'),
}

TEMPLATE_INPUTS_EXEMPT = {
    ('jobs.html.j2', 'q'): 'a listing filter; never submitted for storage',
    ('rules.html.j2', 'q'): 'a listing filter; never submitted for storage',
    ('tasks.html.j2', 'q'): 'a listing filter; never submitted for storage',
    ('users.html.j2', 'password'): 'bcrypt-hashed before storage',
    ('users.html.j2', 'confirm_password'): 'never stored; only compared with password',
}

_INPUT_TAG = re.compile(r'<input\b[^>]*>', re.S)
_ATTR = re.compile(r'([a-zA-Z_-]+)\s*=\s*"([^"]*)"')
_NON_TEXT_TYPES = {'hidden', 'checkbox', 'radio', 'file', 'submit', 'range'}


def _template_inputs():
    """(template name, input name, attrs) for every visible named <input>."""
    root = Path(__file__).resolve().parents[2] / 'hashview' / 'templates'
    for path in sorted(root.rglob('*.j2')):
        for match in _INPUT_TAG.finditer(path.read_text()):
            attrs = dict(_ATTR.findall(match.group(0)))
            if attrs.get('type', 'text') in _NON_TEXT_TYPES or 'name' not in attrs:
                continue
            yield path.name, attrs['name'], attrs


def test_every_hand_written_input_is_classified():
    """Same guard as for forms, for the inputs WTForms never sees."""
    unclassified = [
        (template, name)
        for template, name, _ in _template_inputs()
        if (template, name) not in TEMPLATE_INPUTS
        and (template, name) not in TEMPLATE_INPUTS_EXEMPT
    ]
    assert not unclassified, (
        f'Hand-written <input> element(s) are not classified: {sorted(unclassified)}. '
        'Add each to TEMPLATE_INPUTS in tests/unit/test_form_db_length_parity.py '
        "with the column it is stored in (and give the tag "
        "maxlength=\"{{ db_maxlength('Model', 'column') }}\"), or to "
        'TEMPLATE_INPUTS_EXEMPT with the reason it is not stored.'
    )


def test_hand_written_inputs_carry_the_column_maxlength():
    """The maxlength must come from db_maxlength, naming the mapped column."""
    problems = []
    for template, name, attrs in _template_inputs():
        target = TEMPLATE_INPUTS.get((template, name))
        if target is None:
            continue
        model, column = target
        expected = f"{{{{ db_maxlength('{model}', '{column}') }}}}"
        if attrs.get('maxlength') != expected:
            problems.append(
                f'{template}: <input name="{name}"> has maxlength='
                f'{attrs.get("maxlength")!r}, expected {expected!r}')
    assert not problems, '\n'.join(problems)


def test_db_maxlength_is_available_to_templates(app):
    """The global has to be registered, or every template above renders blank."""
    assert app.jinja_env.globals['db_maxlength']('Customers', 'name') == \
        column_length(Customers, 'name')


# Enforcement -- that each of these routes actually refuses an over-long value
# instead of handing it to the database -- is proven route by route in
# tests/unit/test_form_length_rejected_before_insert.py.
