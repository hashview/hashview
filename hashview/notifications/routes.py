"""Flask routes to handle Notifications"""
from flask import Blueprint, render_template, redirect, flash, url_for
from flask_login import login_required, current_user
from hashview.models import JobNotifications, HashNotifications, Jobs, Hashes, Hashfiles
from hashview.models import db


notifications = Blueprint('notifications', __name__)


@notifications.route("/notifications", methods=['GET', 'POST'])
@login_required
def notifications_list():
    """Function to return list of notifications"""
    job_notifications = JobNotifications.query.filter_by(owner_id=current_user.id).all()
    hash_notifications = HashNotifications.query.filter_by(owner_id=current_user.id).all()
    hashfiles = Hashfiles.query.all()
    jobs = Jobs.query.all()
    hashes = db.session.query(Hashes).join(HashNotifications, Hashes.id == HashNotifications.hash_id).all()

    return render_template('notifications.html', title='Notifications', job_notifications=job_notifications, hash_notifications=hash_notifications, jobs=jobs, hashes=hashes, hashfiles=hashfiles)


@notifications.route("/notifications/delete/job/<int:notification_id>", methods=['GET'])
@login_required
def notifications_job_delete(notification_id):
    """Function to delete a job notification"""
    notification = JobNotifications.query.get(notification_id)
    if current_user.admin or notification.owner_id == current_user.id:
        db.session.delete(notification)
        db.session.commit()
    else:
        flash('You do not have rights to delete this notification!', 'danger')
    return redirect(url_for('notifications.notifications_list'))

@notifications.route("/notifications/delete/hash/<int:notification_id>", methods=['GET'])
@login_required
def notifications_hash_delete(notification_id):
    """Function to delete a recovered hash notification"""
    notification = HashNotifications.query.get(notification_id)
    if current_user.admin or notification.owner_id == current_user.id:
        db.session.delete(notification)
        db.session.commit()
    else:
        flash('You do not have rights to delete this notification!', 'danger')
    return redirect(url_for('notifications.notifications_list'))
