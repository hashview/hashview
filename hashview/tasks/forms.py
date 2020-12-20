from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField
from wtforms.validators import DataRequired
from hashview.models import Wordlists, Rules, Tasks
#from wtforms.ext.sqlalchemy.fields import QuerySelectField
from wtforms_sqlalchemy.fields import QuerySelectField

def get_wordlists():
    return Wordlists.query

def get_rules():
    return Rules.query

class TasksForm(FlaskForm):
    name = StringField('Name', validators=([DataRequired()]))
    hc_attackmode = SelectField('Attack Mode', choices=[('', '--SELECT--'), ('dictionary', 'dictionary'), ('maskmode', 'maskmode'), ('bruteforce', 'bruteforce'), ('combinator', 'combinator')], validators=[DataRequired()])  # dictionary, maskmode, bruteforce, combinator
    wl_id = QuerySelectField('Wordlist',query_factory=get_wordlists, get_label='name')
    rule_id = QuerySelectField('Rules', query_factory=get_rules, get_label='name')
    mask = StringField('Hashcat Mask')
    submit = SubmitField('Create')  

    def validate_task(self, name):
        task = Tasks.query.filter_by(name = name.data).first()
        if task:
            raise ValidationError('That task name is taken. Please choose a different one.')
