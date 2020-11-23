import os
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField
from flask_wtf.file import FileField, FileAllowed
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, NumberRange
from hashview.models import Users

class UsersForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=1, max=20)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=1, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=14)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    pushover_id = StringField('Pushover Id (optional)')
    pushover_key = PasswordField('Pushover Key (optional)')
    submit = SubmitField('Register')

    def validate_email(self, email):
        user = Users.query.filter_by(email_address = email.data).first()
        if user:
            raise ValidationError('That email address is taken. Please choose a different one.')

    def validate_pushover(self, pushover_id, pushover_key):
        if len(pushover_id.data) > 0 and len(pushover_key.data) == 0:
            raise ValidationError('You must supply both options to use.')
        if len(pushover_id.data) == 0 and len(pushover_key.data) > 0:
            raise ValidationError('You must supply both options to use.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class ProfileForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=1, max=20)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=1, max=20)])
    pushover_id = StringField('Pushover Id (optional)')
    pushover_key = PasswordField('Pushover Key (optional)')
    submit = SubmitField('Update')

class JobsForm(FlaskForm):
    name = StringField('Job Name', validator=[DataRequired()])

class HashfilesForm(FlaskForm):
    name = StringField('Hashfile Name', validator=[DataRequired()])
    hashfile = FileField('Upload Hashfile')
    submit = SubmitField('Upload')

class CustomersForm(FlaskForm):
    name = StringField('Customer Name', validators=[DataRequired()])

    def validate_name(self, name):
        customer = Customers.query.filter_by(name = name.data).first()
        if customer:
            raise ValidationError('That customer already exists. Please choose a different one.')

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

class WordlistsForm(FlaskForm):
    name = StringField('Name', validators=([DataRequired()]))
    wordlist = FileField('Upload Wordlist')
    submit = SubmitField('upload')      

class RulesForm(FlaskForm):
    name = StringField('Name', validators=([DataRequired()]))
    rules = FileField('Upload Rules')
    submit = SubmitField('upload')      