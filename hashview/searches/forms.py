from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField, TextAreaField
from wtforms.validators import DataRequired


class SearchForm(FlaskForm):
    search_type = SelectField('Search Type', choices=[('hash', 'hash'), ('user', 'user'), ('password', 'password')], validators=[DataRequired()])
    query = StringField('', validators=([DataRequired()]))
    submit = SubmitField('Search')  