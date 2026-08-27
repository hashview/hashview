"""Forms Page to manage Settings"""
from flask_wtf import FlaskForm
from wtforms import (
    BooleanField,
    IntegerField,
    PasswordField,
    SelectField,
    StringField,
    SubmitField,
    ValidationError,
)
from wtforms.validators import DataRequired, NumberRange


class HashviewSettingsForm(FlaskForm):
    """Class representing an Settings Forms"""

    retention_period = StringField('Retention Period (in days)', validators=[DataRequired()])
    max_runtime_jobs = StringField('Maximum runtime per Job in hours. (0 = infinate)', validators=[DataRequired()])
    max_runtime_tasks = StringField('Maximum runtime per Task in hours. (0 = infinate)', validators=[DataRequired()])
    agent_timeout_minutes = IntegerField('Agent timeout (minutes)',
                                         validators=[DataRequired(), NumberRange(min=1, max=525600)])
    enabled_job_weights = BooleanField('Allow users to set job priority during job creations.')
    # Task chunking
    enabled_chunking = BooleanField('Split tasks into smaller chunks across agents (sized from agent benchmarks).')
    chunk_target_duration = IntegerField('Target chunk runtime in seconds (on the slowest agent).',
                                         validators=[DataRequired(), NumberRange(min=1, max=2147483647)])
    # Notification channel master switches
    email_enabled = BooleanField('Enable Email notifications.')
    pushover_enabled = BooleanField('Enable Pushover notifications.')
    slack_enabled = BooleanField('Enable Slack notifications.')
    slack_bot_token = StringField('Slack bot token (xoxb-…)')
    # Room (channel id) for administrative notifications (agent errors).
    slack_admin_channel = StringField('Slack room for administrative messages')
    # Authentication — local (default) or Microsoft Entra ID SSO. No DataRequired
    # on the azure fields: local mode must validate with them blank. The route
    # enforces completeness when azure is selected. The client secret is a
    # write-only PasswordField (rendered blank; only overwrites when re-typed).
    # validate_choice=False so a POST that omits this field (e.g. an older form
    # or a partial save) still validates; the route only assigns it when it's a
    # valid choice, otherwise the stored value is preserved.
    auth_method = SelectField('Authentication method',
                              choices=[('local', 'Local (username & password)'),
                                       ('azure', 'Microsoft Entra ID (SSO)')],
                              default='local', validate_choice=False)
    azure_tenant_id = StringField('Directory (tenant) ID')
    azure_client_id = StringField('Application (client) ID')
    azure_client_secret = PasswordField('Client secret', render_kw={'autocomplete': 'new-password'})
    azure_redirect_uri = StringField('Redirect URI')
    azure_allowed_groups = StringField('Allowed group Object IDs (comma-separated)')
    submit = SubmitField('Update')

    def validate_rention_period(self, retention_period):
        """Function to validate retention period range"""
        if int(retention_period.data) < 1 or int(retention_period.data) > 65535:
            raise ValidationError('Range must be between 1 and 65535.')

    def validate_max_runtime(self, max_runtime_jobs, max_runtime_tasks):
        """Function to validate max runtime period range"""
        if max_runtime_jobs < 0 or max_runtime_jobs > 65535:
            raise ValidationError('Range must be between 0 and 65535.')
        if max_runtime_tasks < 0 or max_runtime_tasks > 65535:
            raise ValidationError('Range must be between 0 and 65535.')


class DatabaseBackupForm(FlaskForm):
    """CSRF-only form backing the (fetch-driven) database backup action."""

    submit = SubmitField('Back up database')
