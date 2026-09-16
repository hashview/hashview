"""Forms Page to manage Agents"""
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired

from hashview.models import Agents
from hashview.utils.form_limits import db_length


class AgentsForm(FlaskForm):
    """Class representing an Agent Forms"""

    name = StringField('Agent Name', validators=[DataRequired(), db_length(Agents, 'name')])
    id = StringField('agent_id', validators=[DataRequired()])

    submit = SubmitField('Update')
