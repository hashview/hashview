from flask_wtf import FlaskForm
from wtforms import SubmitField, SelectField
from wtforms.validators import DataRequired, ValidationError
from hashview.models import Jobs, Hashfiles, HashfileHashes, Hashes

class NotificationsForm(FlaskForm):
    job_completion = SelectField('Notify when Job Complets?', choices=[('no', 'No'),
                                                                        ('email', 'Send Summary Email'),
                                                                        ('push', 'Push Notification')], validators=[DataRequired()])

    recovered_hashes = SelectField('Notify when specifc Hash has been recovered?', choices=[('no', 'No'),
                                                                                            ('email', 'Send Summary Email'),
                                                                                            ('push', 'Push Notification')], validators=[DataRequired()])