from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField, TextAreaField, FileField, SelectMultipleField, widgets
from wtforms.validators import DataRequired, ValidationError
from hashview.models import Jobs


class JobsForm(FlaskForm):
    name = StringField('Job Name', validators=[DataRequired()])
    customer_id = StringField('Customer ID (unused)', validators=[DataRequired()])
    customer_name = StringField('Customer Name (unused)')
    submit = SubmitField('Next')

    def validate_job(self, name):
        job = Jobs.query.filter_by(name = name.data).first()
        if job:
            raise ValidationError('That job name is taken. Please choose a different one.')

class JobsNewHashFileForm(FlaskForm):
    name = StringField('Hashfile Name') # While required we may dynamically create this based on file upload
    file_type = SelectField('Hash Format', choices=[('', '--SELECT--'), 
                                                    ('hash_only', '$hash'), 
                                                    #('user_hash', '$user:$hash'), 
                                                    ('pwdump', 'pwdump()'), 
                                                    ('NetNTLM', 'NetNTLMv1, NetNTLMv1+ESS or NetNTLMv2'), 
                                                    ('kerberos', 'Kerberos')], validators=[DataRequired()])
    hash_type = SelectField('Hash Type', choices=[  ('', '--SELECT--'),
                                                    ('0', '(0) MD5'),
                                                    ('1000', '(1000) NTLM '),
                                                    ('5500', '(5500) NetNTLMv1 / NetNTLMv1+ESS'),
                                                    ('5600', '(5600) NetNTLMv2'),
                                                    ('7500', '(7500) Kerberos 5 AS-REQ Pre-Auth etype 23'),
                                                    ('13100', '(13100) Kerberos 5 TGS-REP etype 23'),
                                                    ('18200', '(19200) Kerberos 5 AS-REP etype 23'),
                                                    ('19600', '(19600) Kerberos 5 TGS-REP etype 17 (AES128-CTS-HMAC-SHA1-96)'),
                                                    ('19700', '(19700) Kerberos 5 TGS-REP etype 18 (AES256-CTS-HMAC-SHA1-96)'),
                                                    ('19800', '(19800) Kerberos 5 TGS-REP etype 18 (AES256-CTS-HMAC-SHA1-96)'),
                                                    ('19900', '(19900) Kerberos 5 TGS-REP etype 18 (AES256-CTS-HMAC-SHA1-96)'),
                                                    ('other', 'Other')], validators=[DataRequired()])
    hashfilehashes = TextAreaField('Hashes')
    hashfile = FileField('Upload Hashfile')
    submit = SubmitField('Next')

class JobsNotifyHashes(SelectMultipleField):
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()

class JobsNotificationsForm(FlaskForm):
    job_completion = SelectField('Notify when Job completes', choices=[('none', 'No'),
                                                                        ('email', 'Send Email'),
                                                                        ('push', 'Send Push Notification')], validators=[DataRequired()])
    hash_completion = SelectField('Notify when specific hashes crack', choices=[('none', 'No'),
                                                                        ('email', 'Send Email'),
                                                                        ('push', 'Send Push Notification')], validators=[DataRequired()])
    hashes = JobsNotifyHashes('Select Hashes', coerce=str)
    submit = SubmitField('Next')

class JobSummaryForm(FlaskForm):
    submit = SubmitField('Complete')