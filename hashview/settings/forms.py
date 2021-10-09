import os
from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, SubmitField, ValidationError, PasswordField, SelectField
from wtforms.validators import Email, DataRequired, NumberRange


class HashviewSettingsForm(FlaskForm):
    retention_period = StringField('Retention Period (in days)', validators=[DataRequired()])
    hashcat_path = StringField('Path to hashcat bin', validators=[DataRequired()])
    submit = SubmitField('Update')

    def validate_rention_period(self, retention_period):
        if int(retention_period.data) < 1 or int(retention_period.data) > 65535:
            raise ValidationError('Range must be between 1 and 65535.')

    def validate_hashcat_path(self, hashcat_path):
        exists = os.path.isfile(str(hashcat_path.data))
        print(str(hashcat_path.data))
        if not exists:
            raise ValidationError('Could not find hashcat at that location. Enter full path plus executible name.')