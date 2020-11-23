from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, ValidationError, SubmitField
from wtforms.validators import DataRequired, EqualTo, Email, Length
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
