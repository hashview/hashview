from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField
from wtforms.validators import DataRequired

class TasksForm(FlaskForm):
    name = StringField('Name', validators=([DataRequired()]))
    hc_attackmode = SelectField('Attack Mode', choices=[('dictionary', 'dictionary'), ('maskmode', 'maskmode'), ('bruteforce', 'bruteforce'), ('combinator', 'combinator')])  # dictionary, maskmode, bruteforce, combinator
    submit = SubmitField('upload')      