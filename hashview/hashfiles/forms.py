"""Forms Page to manage Hashfiles"""
from flask_wtf import FlaskForm
from wtforms import StringField, FileField, SubmitField
from wtforms.validators import DataRequired

class HashfilesForm(FlaskForm):
    """Class representing an Agent Forms"""

    name = StringField('Hashfile Name', validator=[DataRequired()])
    hashfile = FileField('Upload Hashfile')
    submit = SubmitField('Upload')
