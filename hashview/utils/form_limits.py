"""Form field length limits, derived from the database schema.

The database is the authoritative source for how long a value may be. MySQL in
strict mode raises a DataError on an over-long INSERT, which reaches the user as
a 500 with whatever they typed thrown away, so every single-line form field that
lands in a VARCHAR column has to be bounded by that column's length -- and by the
*same* number, not by a copy of it that drifts the next time a migration widens
or narrows the column.

``db_length`` builds a wtforms ``Length`` validator from the column itself, so a
schema change moves the form with it. WTForms 3 renders ``maxlength`` on the
input from that validator, so browser-side truncation comes along for free on
every WTForms-rendered field; ``template_maxlength`` (exposed to Jinja as
``db_maxlength``) does the same job for the hand-written ``<input>`` elements in
the modals, which WTForms never touches.

``tests/unit/test_form_db_length_parity.py`` fails any single-line field that is
neither bounded this way nor listed there as not persisted, so a new form cannot
quietly ship a mismatch.
"""

from wtforms.validators import Length

from hashview import models


def column_length(model, column_name):
    """Return the declared VARCHAR length of ``model.column_name``."""
    column = model.__table__.columns[column_name]
    length = getattr(column.type, 'length', None)
    if not length:
        raise ValueError(f'{model.__name__}.{column_name} declares no length')
    return length


def db_length(model, column_name, minimum=-1):
    """A ``Length`` validator bounded by the column the field is stored in.

    ``minimum`` defaults to -1 (wtforms' "no minimum"), which also picks the
    "cannot be longer than N characters" wording for the error message.
    """
    return Length(min=minimum, max=column_length(model, column_name))


def template_maxlength(model_name, column_name):
    """``db_maxlength('Customers', 'name')`` -> 40, for use in templates.

    Takes the model by name so a template needn't import anything; raises
    rather than returning a default, because a silently-absent maxlength is the
    exact drift this module exists to prevent.
    """
    model = getattr(models, model_name)
    return column_length(model, column_name)
