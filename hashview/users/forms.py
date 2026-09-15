"""Forms Page to manage Users"""
from flask_wtf import FlaskForm
from wtforms import (
    BooleanField,
    PasswordField,
    StringField,
    SubmitField,
    ValidationError,
)
from wtforms.validators import DataRequired, Email, EqualTo, Length

from hashview.models import Users
from hashview.utils.form_limits import db_length


class UsersForm(FlaskForm):
    """Class representing Users Form"""

    first_name = StringField('First Name',
                             validators=[DataRequired(), db_length(Users, 'first_name', minimum=1)])
    last_name = StringField('Last Name',
                            validators=[DataRequired(), db_length(Users, 'last_name', minimum=1)])
    email = StringField('Email',
                        validators=[DataRequired(), Email(), db_length(Users, 'email_address')])
    is_admin = BooleanField('Is Admin')
    password = PasswordField('Password', validators=[DataRequired(), Length(min=14)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    # Pushover is intentionally NOT collected when creating a user: each user
    # sets their own Pushover app token / user key from their profile after
    # logging in (see ProfileForm).

    def validate_email(self, email):
        """Function to validate email address"""
        user = Users.query.filter_by(email_address = email.data).first()
        if user:
            raise ValidationError('That email address is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    """Class representing Login Form"""

    email = StringField('Email',
                        validators=[DataRequired(), Email(), db_length(Users, 'email_address')])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Crack the planet!')

class ProfileForm(FlaskForm):
    """Class representing Profile Form"""

    first_name = StringField('First Name',
                             validators=[DataRequired(), db_length(Users, 'first_name', minimum=1)])
    last_name = StringField('Last Name',
                            validators=[DataRequired(), db_length(Users, 'last_name', minimum=1)])
    email = StringField('Email',
                        validators=[DataRequired(), Email(), db_length(Users, 'email_address')])
    pushover_user_key = StringField('Pushover User Key (optional)',
                                    validators=[db_length(Users, 'pushover_user_key')])
    pushover_app_id = StringField('Pushover App Id (optional)',
                                  validators=[db_length(Users, 'pushover_app_id')])
    slack_id = StringField('Slack Member ID (optional)', validators=[db_length(Users, 'slack_id')])
    # Administrative notifications (agent errors) — admin-only; the route ignores
    # these for non-admins. The channel sub-options apply when the master is on.
    admin_notifications_enabled = BooleanField('Receive administrative notifications')
    admin_notify_email = BooleanField('Email')
    admin_notify_pushover = BooleanField('Pushover')
    admin_notify_slack = BooleanField('Slack')
    submit = SubmitField('Update')

class ThemeForm(FlaskForm):
    """Minimal CSRF-carrying form for the account theme control. Presence is
    enforced here; the value is validated against the allowed set in the route."""
    theme = StringField('Theme', validators=[DataRequired(), db_length(Users, 'theme')])

class RequestResetForm(FlaskForm):
    """Class representing Password Reset Request Form"""

    email = StringField('Email',
                        validators=[DataRequired(), Email(), db_length(Users, 'email_address')])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    """Class representing Password Reset Form"""

    password = PasswordField('Password', validators=[DataRequired(), Length(min=14)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')
