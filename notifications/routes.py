from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from common.decorators import role_required
from common.logging import log_audit_event, LOGIN_EVENT
from datetime import datetime
from sqlalchemy.exc import IntegrityError
from models import User, Role, StoreSettings, db, DriverApplication, Sponsor, Notification
from extensions import db
from datetime import datetime
from .forms import SendNotificationForm

# Blueprint for notification-related routes
notification_bp = Blueprint('notification_bp', __name__, template_folder="../templates")


@notification_bp.route('/notifications')
@login_required
def notifications():
    # Use consistent filtering by code/PK
    notifs = (
        Notification.query
        .filter_by(RECIPIENT_CODE=current_user.USER_CODE)
        .order_by(Notification.READ_STATUS.asc(), Notification.TIMESTAMP.desc())
        .limit(50)
        .all()
    )

    # Mark unread as read (bulk)
    updated = (
        Notification.query
        .filter_by(RECIPIENT_CODE=current_user.USER_CODE, READ_STATUS=False)
        .update({Notification.READ_STATUS: True}, synchronize_session=False)
    )
    if updated:
        db.session.commit()

    return render_template('notifications/list.html', notifications=notifs)

# In your notifications Blueprint file (e.g., notify_bp.py)

# In your notifications Blueprint file (e.g., notify_bp.py)

# notifications/routes.py
@notification_bp.route('/message/send', methods=['GET', 'POST'])
@login_required
def send_message():
    # Only admins/sponsors can send
    if current_user.USER_TYPE not in (Role.SPONSOR, Role.ADMINISTRATOR):
        flash("You don’t have permission to send messages.", "danger")
        return redirect(url_for('notification_bp.notifications'))

    # Read role filter from GET/POST (default: all)
    role_filter = (request.values.get("role") or "all").lower()

    def base_query_for_role():
        q = User.query.filter(User.IS_ACTIVE == 1)
        # don’t let someone message themselves by mistake
        q = q.filter(User.USER_CODE != current_user.USER_CODE)
        if role_filter in ("driver", "sponsor", "administrator"):
            return q.filter(User.USER_TYPE == getattr(Role, role_filter.upper()))
        return q  # "all"
    
    if request.method == "POST":
        body = (request.form.get("message") or "").strip()
        send_all = bool(request.form.get("send_all"))
        selected_ids = request.form.getlist("recipients")  # checkbox values -> list[str|int]

        if not body:
            flash("Message cannot be empty.", "warning")
            return redirect(url_for("notification_bp.send_message", role=role_filter))

        q = base_query_for_role().with_entities(User.USER_CODE, User.USERNAME)

        if send_all:
            recipients = q.all()
        else:
            if not selected_ids:
                flash("Select at least one recipient or choose 'Send to all'.", "warning")
                return redirect(url_for("notification_bp.send_message", role=role_filter))
            recipients = q.filter(User.USER_CODE.in_(selected_ids)).all()

        if not recipients:
            flash("No valid recipients found.", "warning")
            return redirect(url_for("notification_bp.send_message", role=role_filter))

        #rows = [
            #Notification(
                #RECIPIENT_CODE=rc,
                #SENDER_CODE=current_user.USER_CODE,
                #MESSAGE=body,
                #READ_STATUS=False,
                #TIMESTAMP=datetime.utcnow(),
            #)
            #for (rc, _name) in recipients
        #]

        for (rc, _name) in recipients:
            Notification.create_notification(
                recipient_code=rc,
                sender_code=current_user.USER_CODE,
                message=body
            )
        #db.session.add_all(rows)
        db.session.commit()
        #flash(f"Sent message to {len(rows)} user(s).", "success")
        return redirect(url_for('notification_bp.notifications'))

    # GET: build checkbox list for current role filter
    users = (
        base_query_for_role()
        .with_entities(User.USER_CODE, User.USERNAME, User.USER_TYPE)
        .order_by(User.USERNAME)
        .all()
    )
    return render_template('notifications/send_message.html',
                           users=users, role=role_filter)



@notification_bp.route('/notifications/unread_count', methods=['GET'])
@login_required
def get_unread_count():
    # Ensure current_user.USER_CODE is the primary key for the recipient filter
    if not current_user.is_authenticated:
        return jsonify({'count': 0})
        
    count = Notification.query.filter_by(
        RECIPIENT_CODE=current_user.USER_CODE,
        READ_STATUS=False
    ).count()
    return jsonify({'count': count})