from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from common.decorators import role_required
from common.logging import log_audit_event, LOGIN_EVENT
from datetime import datetime
from sqlalchemy.exc import IntegrityError
from sqlalchemy import or_, and_
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


@notification_bp.route('/notifications/conversations')
@login_required
def conversations():
    search = (request.args.get('q') or '').strip()

    recent_messages = (
        Notification.query
        .filter(or_(
            Notification.SENDER_CODE == current_user.USER_CODE,
            Notification.RECIPIENT_CODE == current_user.USER_CODE
        ))
        .order_by(Notification.TIMESTAMP.desc())
        .limit(200)
        .all()
    )

    latest_by_partner = {}
    for message in recent_messages:
        other_id = message.SENDER_CODE if message.SENDER_CODE != current_user.USER_CODE else message.RECIPIENT_CODE
        if not other_id:
            continue
        if other_id not in latest_by_partner:
            latest_by_partner[other_id] = message

    partner_entries = []
    if latest_by_partner:
        partner_users = {
            user.USER_CODE: user
            for user in User.query.filter(User.USER_CODE.in_(latest_by_partner.keys())).all()
        }
        for partner_id, last_message in latest_by_partner.items():
            partner = partner_users.get(partner_id)
            if partner:
                partner_entries.append({
                    'user': partner,
                    'last_message': last_message
                })

    partner_entries.sort(key=lambda entry: entry['last_message'].TIMESTAMP, reverse=True)

    user_query = User.query.filter(
        User.IS_ACTIVE == 1,
        User.USER_CODE != current_user.USER_CODE
    )
    if search:
        like = f"%{search}%"
        user_query = user_query.filter(or_(
            User.USERNAME.ilike(like),
            User.FNAME.ilike(like),
            User.LNAME.ilike(like)
        ))

    available_users = user_query.order_by(User.USERNAME.asc()).limit(25).all()

    return render_template(
        'notifications/conversations.html',
        threads=partner_entries,
        available_users=available_users,
        search=search
    )


@notification_bp.route('/notifications/dm/<int:user_id>', methods=['GET', 'POST'])
@login_required
def direct_message(user_id):
    partner = User.query.get_or_404(user_id)

    if partner.USER_CODE == current_user.USER_CODE:
        flash("You can’t message yourself.", "warning")
        return redirect(url_for('notification_bp.conversations'))

    if not partner.IS_ACTIVE:
        flash("That user is no longer active.", "warning")
        return redirect(url_for('notification_bp.conversations'))

    if request.method == 'POST':
        body = (request.form.get('message') or '').strip()
        if not body:
            flash("Message cannot be empty.", "warning")
            return redirect(url_for('notification_bp.direct_message', user_id=user_id))

        Notification.create_notification(
            recipient_code=partner.USER_CODE,
            sender_code=current_user.USER_CODE,
            message=body
        )
        flash("Message sent.", "success")
        return redirect(url_for('notification_bp.direct_message', user_id=user_id))

    updated = (
        Notification.query
        .filter(
            Notification.SENDER_CODE == partner.USER_CODE,
            Notification.RECIPIENT_CODE == current_user.USER_CODE,
            Notification.READ_STATUS == False
        )
        .update({Notification.READ_STATUS: True}, synchronize_session=False)
    )
    if updated:
        db.session.commit()

    messages = (
        Notification.query
        .filter(or_(
            and_(
                Notification.SENDER_CODE == current_user.USER_CODE,
                Notification.RECIPIENT_CODE == partner.USER_CODE
            ),
            and_(
                Notification.SENDER_CODE == partner.USER_CODE,
                Notification.RECIPIENT_CODE == current_user.USER_CODE
            )
        ))
        .order_by(Notification.TIMESTAMP.asc())
        .all()
    )

    return render_template(
        'notifications/direct_message.html',
        partner=partner,
        messages=messages
    )



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