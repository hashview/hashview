"""Forms Page to manage Setup"""
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms import SubmitField
from wtforms import IntegerField
from wtforms import PasswordField
from wtforms.validators import Email
from wtforms.validators import Length
from wtforms.validators import EqualTo
from wtforms.validators import NumberRange
from wtforms.validators import DataRequired


class SetupAdminPassForm(FlaskForm):
    """Class representing an Admin Pass Forms"""

    first_name       = StringField('First Name',         validators=[DataRequired(), Length(min=1, max=20)])
    last_name        = StringField('Last Name',          validators=[DataRequired(), Length(min=1, max=20)])
    email_address    = StringField('Email',              validators=[DataRequired(), Email()])
    password         = PasswordField('Password',         validators=[DataRequired(), Length(min=14)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit           = SubmitField('Update')


class SetupSettingsForm(FlaskForm):
    """Class representing an Settings Forms"""

    retention_period  = IntegerField('Retention Period',   validators=[DataRequired(), NumberRange(min=1, max=65535)])
    max_runtime_tasks = IntegerField('Max Runtime Tasks')
    max_runtime_jobs  = IntegerField('Max Runtime Jobs')
    submit            = SubmitField('Save')
