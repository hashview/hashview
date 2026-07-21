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
from wtforms.validators import URL, DataRequired, NumberRange, Optional


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
    # Website-keywords crawler settings
    crawl_min_word_length = IntegerField('Minimum word length', validators=[DataRequired(), NumberRange(min=1, max=65535)])
    crawl_user_agent = StringField('Crawler user-agent', validators=[DataRequired()])
    crawl_force_lowercase = BooleanField('Force crawled words to lowercase.')
    crawl_depth = IntegerField('Crawl depth', validators=[DataRequired(), NumberRange(min=1, max=100)])
    crawl_threads = IntegerField('Crawler threads', validators=[DataRequired(), NumberRange(min=1, max=256)])
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


class WordlistProviderForm(FlaskForm):
    """Add/edit a remote wordlist provider (Settings -> Wordlist Providers).

    ``provider_secret`` is a write-only PasswordField (rendered blank; the route
    only overwrites the stored value when a new one is typed). ``username`` is
    required only for HTTP Basic; the secret is required only when adding a new
    provider (blank on edit keeps the existing secret) — the route passes
    ``is_add`` so validation can distinguish the two.
    """

    name = StringField('Name', validators=[DataRequired()])
    description = StringField('Description', validators=[Optional()])
    base_url = StringField('Base URL', validators=[DataRequired(), URL()])
    auth_type = SelectField('Authentication',
                            choices=[('bearer', 'Bearer token'),
                                     ('basic', 'HTTP Basic (username & password)')],
                            default='bearer')
    username = StringField('Username (HTTP Basic only)', validators=[Optional()])
    provider_secret = PasswordField('Token / password', render_kw={'autocomplete': 'new-password'})
    verify_tls = BooleanField('Verify TLS certificate', default=True)
    enabled = BooleanField('Enabled', default=True)
    submit = SubmitField('Save provider')

    def __init__(self, *args, is_add=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.is_add = is_add

    def validate_username(self, username):
        """HTTP Basic needs a username."""
        if self.auth_type.data == 'basic' and not (username.data or '').strip():
            raise ValidationError('A username is required for HTTP Basic authentication.')

    def validate_provider_secret(self, provider_secret):
        """A secret is required when adding; on edit, blank keeps the existing one."""
        if self.is_add and not (provider_secret.data or '').strip():
            raise ValidationError('A token / password is required.')


class DatabaseBackupForm(FlaskForm):
    """CSRF-only form backing the (fetch-driven) database backup action."""

    submit = SubmitField('Back up database')
