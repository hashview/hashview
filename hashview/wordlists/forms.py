"""Forms Page to manage Wordlists"""
from flask_wtf import FlaskForm
from wtforms import FileField, StringField, SubmitField
from wtforms.validators import DataRequired

from hashview.models import Wordlists
from hashview.utils.form_limits import db_length, db_truncate


class WordlistsForm(FlaskForm):
    """Class representing Wordlist Form"""

    # Filled from the chosen file's name by the upload modal, so it is
    # trimmed to fit rather than refused -- see db_truncate.
    name = StringField('Name', validators=[DataRequired(), db_length(Wordlists, 'name')],
                       filters=[db_truncate(Wordlists, 'name')])
    wordlist = FileField('Upload Wordlist')
    submit = SubmitField('upload')

class WordlistRestoreForm(FlaskForm):
    """Upload a replacement file for an EXISTING wordlist row (issue #383).

    No name field: restoring keeps the row's identity, including its name, path
    and id, so every Tasks.wl_id / wl_id_2 reference stays valid. Exists as a
    form (rather than a bare <input>) so the route can gate on
    validate_on_submit() and get real CSRF validation; there is no global
    CSRFProtect, so a hidden token alone would be decorative.
    """

    wordlist = FileField('Replacement wordlist file', validators=[DataRequired()])
    submit = SubmitField('restore')
