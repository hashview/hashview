"""Forms Page to manage Agents"""
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired

class AgentsForm(FlaskForm):
    """Class representing an Agent Forms"""

    name = StringField('Agent Name', validators=[DataRequired()])
    id = StringField('agent_id', validators=[DataRequired()])

    submit = SubmitField('Update')
