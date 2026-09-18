"""A Flask-Mail that cannot block a request thread forever.

Flask-Mail 0.10 builds its SMTP connection as ``smtplib.SMTP(server, port)``
with no ``timeout=``, so the socket inherits Python's global default of "block
indefinitely" -- on connect AND on every command read. Hashview sends mail
synchronously from request handlers (stopping a job notifies its owner; an
agent's crack upload can fire job-completion mail), and the server runs with
werkzeug's threaded mode, so an SMTP relay that accepts a connection and then
goes quiet parks that worker thread with no way back. A tarpit, a black-holed
port 25, or a relay that fails over mid-session are all enough.

Flask-Mail exposes no configuration for this, so the timeout is threaded in by
overriding the one method that builds the socket. Everything else -- STARTTLS,
login, send, the suppression and record_messages behaviour -- is inherited
unchanged.

MAIL_TIMEOUT is in seconds and applies to the connect and to each subsequent
read, not to the whole session: smtplib passes it to socket.create_connection
and then to the socket, so a slow-but-progressing relay is not cut off.
"""

import smtplib

from flask_mail import Connection, Mail

# Long enough for a healthy relay that is merely busy, short enough that a dead
# one cannot outlast a user's patience. Overridable per install via
# [SMTP] timeout in config.conf.
DEFAULT_MAIL_TIMEOUT = 10


class TimeoutConnection(Connection):
    """A Flask-Mail Connection whose SMTP socket has a deadline."""

    def configure_host(self):
        timeout = self.mail.timeout or DEFAULT_MAIL_TIMEOUT
        if self.mail.use_ssl:
            host = smtplib.SMTP_SSL(self.mail.server, self.mail.port,
                                    timeout=timeout)
        else:
            host = smtplib.SMTP(self.mail.server, self.mail.port,
                                timeout=timeout)

        host.set_debuglevel(int(self.mail.debug))

        if self.mail.use_tls:
            host.starttls()

        if self.mail.username and self.mail.password:
            host.login(self.mail.username, self.mail.password)

        return host


class TimeoutMail(Mail):
    """Flask-Mail that hands out TimeoutConnection instead of Connection.

    There are TWO objects that can open a connection, and both must be covered.
    ``Mail`` is what the app constructs, but ``init_app`` returns a separate
    ``_Mail`` state object which is what lands in ``app.extensions['mail']`` --
    and that is the one application code actually sends through
    (``current_app.extensions['mail'].send(msg)``, as utils.send_email does).
    Both inherit ``connect()`` from ``_MailMixin``, which hard-codes
    ``Connection(...)``, so overriding it on the Mail class alone leaves every
    real send on the unbounded path. Overriding it on the state instance is what
    makes the timeout actually apply; a test asserts the send path is bounded so
    this cannot silently regress.
    """

    def init_app(self, app):
        state = super().init_app(app)
        # Read once here rather than per-connection: the state object is what
        # Connection sees as `self.mail`, and it is built from config at
        # init_app time, exactly like every other Flask-Mail setting.
        timeout = app.config.get('MAIL_TIMEOUT') or DEFAULT_MAIL_TIMEOUT
        state.timeout = timeout
        self.timeout = timeout
        state.connect = lambda: TimeoutConnection(state)
        return state

    def connect(self):
        from flask import current_app

        app = getattr(self, 'app', None) or current_app
        try:
            return TimeoutConnection(app.extensions['mail'])
        except KeyError as err:
            raise RuntimeError(
                'The current application was not configured with Flask-Mail'
            ) from err
