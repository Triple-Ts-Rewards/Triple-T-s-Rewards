from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from models import User, db, ImpersonationLog, DriverSponsorAssociation


def allowed_to_impersonate(target_user):
    """
    Determines if the current_user is allowed to impersonate the target_user.
    - Admins can impersonate anyone.
    - Sponsors can impersonate drivers they are associated with in DRIVER_SPONSOR_ASSOCIATIONS.
    """
    # Admins can impersonate anyone
    if current_user.USER_TYPE.lower() in ['admin', 'administrator']:
        return True

    # Sponsors can impersonate their own drivers
    if current_user.USER_TYPE.lower() == 'sponsor':
        target_type = getattr(target_user, 'USER_TYPE', '').lower()
        if target_type != 'driver':
            return False

        # Check association between sponsor and driver
        association = DriverSponsorAssociation.query.filter_by(
            driver_id=target_user.USER_CODE,
            sponsor_id=current_user.USER_CODE
        ).first()

        return association is not None

    # Everyone else cannot impersonate
    return False

impersonation_bp = Blueprint('impersonation_bp', __name__)

def log_impersonation(actor_id, target_id, action):
    """Create a log entry for impersonation actions."""
    entry = ImpersonationLog(
        actor_id=actor_id,
        target_id=target_id,
        action=action
    )
    db.session.add(entry)
    db.session.commit()

@impersonation_bp.route('/impersonate/start/<int:target_id>', methods=['POST'])
@login_required
def start_impersonation(target_id):
    actor = current_user
    if actor.USER_CODE == target_id or actor.USERNAME == User.query.filter_by(USER_CODE=target_id).first().USERNAME:
        flash("You cannot impersonate yourself.", "warning")
        log_impersonation(actor.USER_CODE, actor.USER_CODE, 'self-impersonation-attempt')
        return redirect(request.referrer or url_for('common.index'))

    target = User.query.filter_by(USER_CODE=target_id).first_or_404()
    if not allowed_to_impersonate(target):
        flash("You are not authorized to impersonate that user.", "danger")
        return redirect(request.referrer or url_for('common.index'))

    # Store original user info in session
    session['original_user_code'] = actor.USER_CODE
    session['impersonating'] = True
    session.permanent = True

    # Log start of impersonation
    log_impersonation(actor.USER_CODE, target.USER_CODE, 'start')

    # Switch to target user
    login_user(target)
    flash(f"You are now impersonating {target.USERNAME}", "info")
    return redirect(url_for('common.index'))

@impersonation_bp.route('/impersonate/stop', methods=['POST'])
@login_required
def stop_impersonation():
    orig_code = session.pop('original_user_code', None)
    session.pop('impersonating', None)

    if not orig_code:
        flash("No impersonation session was active.", "warning")
        return redirect(url_for('common.index'))

    actor = User.query.filter_by(USER_CODE=orig_code).first()
    if not actor:
        flash("Original user not found. Please log in again.", "danger")
        return redirect(url_for('auth.login'))

    # Log stop of impersonation
    log_impersonation(actor.USER_CODE, current_user.USER_CODE, 'stop')

    # Switch back to the original user
    login_user(actor)
    flash("Stopped impersonation and returned to your account.", "info")
    return redirect(url_for('common.index'))