"""Forms Page to manage Rules"""
from flask_wtf import FlaskForm
from wtforms import FileField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired


class RulesForm(FlaskForm):
    """Class representing an Rules Forms"""

    name = StringField('Name', validators=[DataRequired()])
    rules = FileField('Upload Rules')
    submit = SubmitField('upload')

class RulesEditForm(FlaskForm):
    """Class representing a Rules Edit Form"""
    name = StringField('Name', validators=[DataRequired()])
    content = TextAreaField('Contents', validators=[DataRequired()])
    submit = SubmitField('update')

class RuleRestoreForm(FlaskForm):
    """Upload a replacement file for an EXISTING rule row (issue #383).

    No name field: restoring keeps the row's identity, including its name, path
    and id -- that is the whole point, since every Tasks.rule_id reference has
    to stay valid. Exists as a form (rather than a bare <input>) so the route
    can gate on validate_on_submit() and get real CSRF validation; there is no
    global CSRFProtect, so a hidden token alone would be decorative.
    """

    rules = FileField('Replacement rule file', validators=[DataRequired()])
    submit = SubmitField('restore')
