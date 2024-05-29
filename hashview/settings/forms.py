"""Forms Page to manage Settings"""
from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, SubmitField, ValidationError
from wtforms.validators import DataRequired


class HashviewSettingsForm(FlaskForm):
    """Class representing an Settings Forms"""

    retention_period = StringField('Retention Period (in days)', validators=[DataRequired()])
    max_runtime_jobs = StringField('Maximum runtime per Job in hours. (0 = infinate)', validators=[DataRequired()])
    max_runtime_tasks = StringField('Maximum runtime per Task in hours. (0 = infinate)', validators=[DataRequired()])
    enabled_job_weights = BooleanField('Allow users to set job priority during job creations.')
    submit = SubmitField('Update')

    def validate_rention_period(self, retention_period):
        """Function to validate retention period range"""
        if int(retention_period.data) < 1 or int(retention_period.data) > 65535:
            raise ValidationError('Range must be between 1 and 65535.')

    def validate_max_runtime(self, max_runtime_jobs, max_runtime_tasks):
        """Function to validate max runtime period range"""
        if max_runtime_jobs < 0 or max_runtime_jobs > 65535:
            raise ValidationError('Range must be between 0 and 65535.')
        if max_runtime_tasks < 0 or max_runtime_tasks > 65535:
            raise ValidationError('Range must be between 0 and 65535.')
