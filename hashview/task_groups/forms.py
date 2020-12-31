from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField
from wtforms.validators import DataRequired, ValidationError
from hashview.models import Wordlists, Rules, Tasks
from wtforms_sqlalchemy.fields import QuerySelectField


class TaskGroupsForm(FlaskForm):
    name = StringField('Name', validators=([DataRequired()]))
    submit = SubmitField('Create')  

    def validate_task(self, name):
        task = Tasks.query.filter_by(name = name.data).first()
        if task:
            raise ValidationError('That task name is taken. Please choose a different one.')
