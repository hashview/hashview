from flask import Blueprint

settings = Blueprint('settings', __name__)


#############################################
# Settings
#############################################

@settings.route("/settings", methods=['GET', 'POST'])
@login_required
def settings():
    if current_user.admin:
        form = SettingsForm()
        settings = Settings.query.all()
        return render_template('settings.html', title='settings', settings=settings, form=form)
    else:
        abort(403)
