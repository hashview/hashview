"""Forms Page to manage Setup"""
from flask_wtf import FlaskForm
from wtforms import IntegerField, PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, NumberRange

from hashview.models import Users
from hashview.utils.form_limits import db_length


class SetupAdminPassForm(FlaskForm):
    """Class representing an Admin Pass Forms"""

    first_name = StringField(
        'First Name', validators=[DataRequired(), db_length(Users, 'first_name', minimum=1)])
    last_name = StringField(
        'Last Name', validators=[DataRequired(), db_length(Users, 'last_name', minimum=1)])
    email_address = StringField(
        'Email', validators=[DataRequired(), Email(), db_length(Users, 'email_address')])
    password = PasswordField(
        'Password', validators=[DataRequired(), Length(min=14)])
    confirm_password = PasswordField(
        'Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Update')


class SetupSettingsForm(FlaskForm):
    """Class representing an Settings Forms"""

    retention_period = IntegerField(
        'Retention Period', validators=[DataRequired(), NumberRange(min=1, max=65535)])
    max_runtime_tasks = IntegerField('Max Runtime Tasks')
    max_runtime_jobs  = IntegerField('Max Runtime Jobs')
    submit            = SubmitField('Save')
