"""Forms Page to manage Jobs"""
from flask_wtf import FlaskForm
from wtforms import (
	BooleanField,
	FileField,
	SelectField,
	StringField,
	SubmitField,
	TextAreaField,
)
from wtforms.validators import DataRequired, ValidationError

from hashview.models import Jobs
from hashview.utils.hashcat_modes import (
	HASH_TYPE_CHOICES,
	KERBEROS_HASH_TYPE_CHOICES,
	NETNTLM_HASH_TYPE_CHOICES,
	SHADOW_HASH_TYPE_CHOICES,
)


class JobsForm(FlaskForm):
	"""Class representing an Jobs Forms"""

	name = StringField('Job Name', validators=[DataRequired()])
	priority = SelectField('Job Priority', choices=[('5', '5 - highest'),
													('4', '4 - higher'),
													('3', '3 - normal'),
													('2', '2 - lower'),
													('1', '1 - lowest')], default=3, validators=[DataRequired()])
	customer_id = StringField('Customer ID (unused)', validators=[DataRequired()])
	customer_name = StringField('Customer Name (unused)')
	limit_recovered = BooleanField('Stop job after single hash has been recovered.')
	submit = SubmitField('Next')

	def validate_name(self, name):
		# Named validate_name (not validate_job) so WTForms actually runs it —
		# inline validators must be validate_<fieldname>, and the field is `name`.
		job = Jobs.query.filter_by(name = name.data).first()
		if job:
			raise ValidationError('That job name is taken. Please choose a different one.')

class JobsNewHashFileForm(FlaskForm):
    """Class representing an Jobs New Hashfile Form"""

    name = StringField('Hashfile Name') # While required we may dynamically create this based on file upload
    file_type = SelectField('Hash File Format', choices=[('', '--SELECT--'),
													('pwdump', 'pwdump()'), 
													('NetNTLM', 'NetNTLMv1, NetNTLMv1+ESS or NetNTLMv2'), 
													('kerberos', 'Kerberos'),
													('shadow', 'Linux / Unix Shadow File'),
													('user_hash', '$user:$hash'),
													('hash_only', '$hash')], validators=[DataRequired()])
													
    hash_type = SelectField('Hash Type', choices=HASH_TYPE_CHOICES)

    shadow_hash_type = SelectField('Hash Type', choices=SHADOW_HASH_TYPE_CHOICES)

    pwdump_hash_type = SelectField('Hash Type', choices=[  ('', '------SELECT------'),
													('1000', '(1000) NTLM')], default='1000')

    netntlm_hash_type = SelectField('Hash Type', choices=NETNTLM_HASH_TYPE_CHOICES)

    kerberos_hash_type = SelectField('Hash Type', choices=KERBEROS_HASH_TYPE_CHOICES)													

    hashfilehashes = TextAreaField('Hashes')
    hashfile = FileField('Upload Hashfile')
    # Only meaningful for the colon-delimited hash_only / user_hash formats; the
    # template shows the toggle only for those and the route ignores it otherwise.
    hex_salt = BooleanField('Salts are hex-encoded')
    submit = SubmitField('Next')

class JobsNotificationsForm(FlaskForm):
    job_completion_email = BooleanField('Send an email when job completes?')
    job_completion_pushover = BooleanField('Send a Pushover message when job completes?')
    job_completion_slack = BooleanField('Send a Slack message when job completes?')
    hash_completion_email = BooleanField('Send an email when a specific hash is recovered?')
    hash_completion_pushover = BooleanField('Send a Pushover message when a specific has is recovered?')
    hash_completion_slack = BooleanField('Send a Slack message when a specific hash is recovered?')
    # job_completion = SelectField('Notify when Job completes', choices=[('none', 'No'),
	# 												                    ('email', 'Send Email'),
	# 												                    ('push', 'Send Push Notification')], validators=[DataRequired()])
    # hash_completion = SelectField('Notify when specific hashes crack', choices=[('none', 'No'),
	# 												                    ('email', 'Send Email'),
	# 												                    ('push', 'Send Push Notification')], validators=[DataRequired()])
    submit = SubmitField('Next')

class JobSummaryForm(FlaskForm):
    """Class representing an Jobs Summary"""

    submit = SubmitField('Create & Queue Job')
