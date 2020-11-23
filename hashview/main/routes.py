from flask import Blueprint, render_template
from flask_login import login_required

main = Blueprint('main', __name__)

#############################################
# Main
#############################################

@main.route("/")
@login_required
def home():
    return render_template('home.html')