from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import DataRequired


class JobsForm(FlaskForm):
    name = StringField('Job Name', validator=[DataRequired()])