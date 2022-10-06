from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField
from wtforms.validators import DataRequired, ValidationError
from hashview.models import Wordlists, Rules, Tasks
from wtforms_sqlalchemy.fields import QuerySelectField


class TasksForm(FlaskForm):
    name = StringField('Name', validators=([DataRequired()]))
    hc_attackmode = SelectField('Attack Mode', choices=[('', '--SELECT--'), ('dictionary', 'dictionary'), ('maskmode', 'maskmode'), ('bruteforce', 'bruteforce'), ('combinator', 'combinator')], validators=[DataRequired()])  # dictionary, maskmode, bruteforce, combinator
    wl_id = SelectField('Wordlist', choices=[])
    rule_id = SelectField('Rules', choices=[])
    mask = StringField('Hashcat Mask')
    submit = SubmitField('Create')  

    def validate_task(self, name):
        task = Tasks.query.filter_by(name = name.data).first()
        if task:
            raise ValidationError('That task name is taken. Please choose a different one.')
