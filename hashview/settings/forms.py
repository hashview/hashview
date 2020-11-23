import os
from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, SubmitField, ValidationError, PasswordField, SelectField
from wtforms.validators import Email, DataRequired, NumberRange

class SettingsForm(FlaskForm):
    smtp_server = StringField('SMTP Server')
    smtp_sender = StringField('SMTP Sender Address', validators=[Email()])
    smtp_user = StringField('SMTP Username')
    smtp_password = PasswordField('SMTP Password')
    smtp_use_tls = BooleanField('Use TLS')
    smtp_auth_type = SelectField('Auth Type', choices=[('none', 'none'), ('plain', 'plain'), ('login', 'login'), ('cram_md5', 'cram_md5')])  # plain, login, cram_md5, none
    retention_period = StringField('Retention Period (in days)', validators=[DataRequired(), NumberRange(min=0, max=65535, message="Range must be between 0 and 65,535. 0 Days means indefiant")])
    hashcat_path = StringField('Path to hashcat bin', validators=[DataRequired()])
    submit = SubmitField('Update')

    def validate_hashcat_path(self, hashcat_path):
        exists = os.path.isfile(hashcat_path)
        if not exists:
            raise ValidationError('Could not find hashcat at that location. Enter full path plus executible name.')