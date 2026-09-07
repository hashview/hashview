"""Forms Page to manage Hashfiles"""
from flask_wtf import FlaskForm
from wtforms import FileField, StringField, SubmitField
from wtforms.validators import DataRequired


class HashfilesForm(FlaskForm):
    """Class representing a Hashfile upload form"""

    name = StringField('Hashfile Name', validator=[DataRequired()])
    hashfile = FileField('Upload Hashfile')
    submit = SubmitField('Upload')
