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

from hashview.models import Settings
from hashview.utils.form_limits import db_length


class HashviewSettingsForm(FlaskForm):
    """Class representing an Settings Forms"""

    retention_period = StringField('Retention Period (in days)', validators=[DataRequired()])
    max_runtime_jobs = StringField('Maximum runtime per Job in hours. (0 = infinate)', validators=[DataRequired()])
    max_runtime_tasks = StringField('Maximum runtime per Task in hours. (0 = infinate)', validators=[DataRequired()])
    agent_timeout_minutes = IntegerField('Agent timeout (minutes)',
                                         validators=[DataRequired(), NumberRange(min=1, max=525600)])
    enabled_job_weights = BooleanField('Allow users to set job priority during job creations.')
    catalog_prune_orphans = BooleanField(
        'Automatically remove rule/wordlist entries whose file is gone and that no task uses.')
    # Task chunking
    enabled_chunking = BooleanField('Split tasks into smaller chunks across agents (each sized from that agent\'s own benchmark).')
    chunk_target_duration = IntegerField('Target chunk runtime in seconds.',
                                         validators=[DataRequired(), NumberRange(min=1, max=2147483647)])
    # Notification channel master switches
    email_enabled = BooleanField('Enable Email notifications.')
    pushover_enabled = BooleanField('Enable Pushover notifications.')
    slack_enabled = BooleanField('Enable Slack notifications.')
    slack_bot_token = StringField('Slack bot token (xoxb-…)',
                                  validators=[db_length(Settings, 'slack_bot_token')])
    # Room (channel id) for administrative notifications (agent errors).
    slack_admin_channel = StringField('Slack room for administrative messages',
                                      validators=[db_length(Settings, 'slack_admin_channel')])
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
    azure_tenant_id = StringField('Directory (tenant) ID',
                                  validators=[db_length(Settings, 'azure_tenant_id')])
    azure_client_id = StringField('Application (client) ID',
                                  validators=[db_length(Settings, 'azure_client_id')])
    azure_client_secret = PasswordField('Client secret',
                                        render_kw={'autocomplete': 'new-password'},
                                        validators=[db_length(Settings, 'azure_client_secret')])
    azure_redirect_uri = StringField('Redirect URI',
                                     validators=[db_length(Settings, 'azure_redirect_uri')])
    azure_allowed_groups = StringField('Allowed group Object IDs (comma-separated)',
                                       validators=[db_length(Settings, 'azure_allowed_groups')])
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


class CatalogPruneForm(FlaskForm):
    """CSRF-only form backing the manual catalog prune action (#502).

    This app has no global CSRFProtect; CSRF protection is only via
    FlaskForm.validate_on_submit(). This form exists solely to carry and
    validate the CSRF token, exactly like DatabaseBackupForm.
    """

    submit = SubmitField('Prune')
