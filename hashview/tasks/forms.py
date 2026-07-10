"""Forms Page to manage Tasks"""
from flask_wtf import FlaskForm
from wtforms import BooleanField, SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, InputRequired, ValidationError

from hashview.models import Tasks


class TasksForm(FlaskForm):
    name = StringField('Name', validators=([DataRequired()]))
    hc_attackmode = SelectField('Attack Mode', choices=[(0, 'Straight (Wordlist w/Rules)'),
                                                        (1, 'Combination (Wordlist1, Rule1, Wordlist2, Rule2)'),
                                                        (3, 'Brute-force (A.K.A. Maskmode)'),
                                                        (6, 'Hybrid (Wordlist + Mask)'),
                                                        (7, 'Hybrid (Mask + Wordlist)')], coerce=int, validators=[InputRequired()])  # dictionary, maskmode, bruteforce, combinator
    wl_id = SelectField('Wordlist', choices=[])
    wl_id_2 = SelectField('Second Wordlist', choices=[])
    rule_id = SelectField('Rules', choices=[])
    j_rule = StringField('-j rule (i.e. $-)')
    k_rule = StringField('-k rule (i.e. $!)')
    mask = StringField('Hashcat Mask')
    loopback = BooleanField('Enable loopback')
    submit = SubmitField('Create')

    def validate_name(self, name):
        """Reject a duplicate task name.

        Named validate_name (not validate_task) so WTForms actually invokes it —
        inline validators must be validate_<fieldname>, and the field is `name`.
        On edit, set ``form._editing_id`` to the task's id so keeping its own name
        isn't flagged as a collision with itself.
        """
        task = Tasks.query.filter_by(name = name.data).first()
        if task and task.id != getattr(self, '_editing_id', None):
            raise ValidationError('That task name is taken. Please choose a different one.')
