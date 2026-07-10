"""Forms Page to manage Setup"""
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, ValidationError

from hashview.models import TaskGroups


class TaskGroupsForm(FlaskForm):
    """Class representing Task Group Forms"""

    name = StringField('Name', validators=[DataRequired()])
    submit = SubmitField('Create')

    def validate_name(self, name):
        """Reject a duplicate task-group name.

        Was validate_task querying Tasks — which both never ran (WTForms needs
        validate_<fieldname>) and checked the wrong table. Named validate_name and
        scoped to TaskGroups so group names are actually unique.
        """
        task_group = TaskGroups.query.filter_by(name = name.data).first()
        if task_group and task_group.id != getattr(self, '_editing_id', None):
            raise ValidationError('That task group name is taken. Please choose a different one.')
