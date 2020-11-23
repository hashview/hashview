from flask_wtf import FlaskForm
from wtforms import StringField, FileField, SubmitField
from wtforms.validators import DataRequired

class WordlistsForm(FlaskForm):
    name = StringField('Name', validators=([DataRequired()]))
    wordlist = FileField('Upload Wordlist')
    submit = SubmitField('upload')      