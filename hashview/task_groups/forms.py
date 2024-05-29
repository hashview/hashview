"""Forms Page to manage Setup"""
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, ValidationError
from hashview.models import Tasks


class TaskGroupsForm(FlaskForm):
    """Class representing Task Group Forms"""

    name = StringField('Name', validators=[DataRequired()])
    submit = SubmitField('Create')  

    def validate_task(self, name):
        """Function to validate task"""

        task = Tasks.query.filter_by(name = name.data).first()
        if task:
            raise ValidationError('That task name is taken. Please choose a different one.')
