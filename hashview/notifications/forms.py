"""Forms Page to manage Notifications"""
from flask_wtf import FlaskForm
from wtforms import SelectField
from wtforms.validators import DataRequired

class NotificationsForm(FlaskForm):
    """Class representing an Notifications Forms"""
    job_completion = SelectField('Notify when Job Complets?', choices=[('no', 'No'),
                                                                        ('email', 'Send Summary Email'),
                                                                        ('push', 'Push Notification')], validators=[DataRequired()])

    recovered_hashes = SelectField('Notify when specifc Hash has been recovered?', choices=[('no', 'No'),
                                                                                            ('email', 'Send Summary Email'),
                                                                                            ('push', 'Push Notification')], validators=[DataRequired()])
    