from flask_wtf import FlaskForm
from wtforms import StringField, FileField, SubmitField
from wtforms.validators import DataRequired

class HashfilesForm(FlaskForm):
    name = StringField('Hashfile Name', validator=[DataRequired()])
    hashfile = FileField('Upload Hashfile')
    submit = SubmitField('Upload')