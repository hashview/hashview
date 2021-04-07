from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, ValidationError, Optional
from hashview.models import Agents

class AgentsForm(FlaskForm):
    name = StringField('Agent Name', validators=[DataRequired()])
    id = StringField('agent_id', validators=[DataRequired()])
    
    submit = SubmitField('Update')
