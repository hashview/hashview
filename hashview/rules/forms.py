"""Forms Page to manage Rules"""
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, FileField
from wtforms.validators import DataRequired

class RulesForm(FlaskForm):
    """Class representing an Rules Forms"""

    name = StringField('Name', validators=[DataRequired()])
    rules = FileField('Upload Rules')
    submit = SubmitField('upload')
