"""Forms Page to manage Searches"""
from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, SubmitField
from wtforms.validators import DataRequired


class SearchForm(FlaskForm):
    """Class representing an Search Forms"""

    search_type = SelectField('Search Type', choices=[('user', 'user'), ('hash', 'hash'), ('password', 'password')], validators=[DataRequired()])
    query = StringField('', validators=[DataRequired()])
    submit = SubmitField('Search')
