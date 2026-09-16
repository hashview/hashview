"""Forms Page to manage Hashfiles"""
from flask_wtf import FlaskForm
from wtforms import FileField, StringField, SubmitField
from wtforms.validators import DataRequired

from hashview.models import Hashfiles
from hashview.utils.form_limits import db_length


class HashfilesForm(FlaskForm):
    """Class representing a Hashfile upload form"""

    # `validators`, not `validator`: the singular spelling is not a Field kwarg,
    # so instantiating this form raised TypeError. Nothing renders it today
    # (hashfile uploads go through jobs.JobsNewHashFileForm), which is why the
    # typo survived.
    name = StringField('Hashfile Name',
                       validators=[DataRequired(), db_length(Hashfiles, 'name')])
    hashfile = FileField('Upload Hashfile')
    submit = SubmitField('Upload')
