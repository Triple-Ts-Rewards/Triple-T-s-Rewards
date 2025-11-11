# auth/routes.py
import base64
from io import BytesIO
from urllib.parse import urlparse, urljoin
from flask_login import login_user, logout_user, login_required, current_user
import pyotp
import qrcode
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from common.second_factor import create_email_code, verify_email_code, send_email
from models import User, Role, Notification  # Role has DRIVER, SPONSOR, ADMINISTRATOR
from datetime import datetime, timedelta
from extensions import db
from sqlalchemy import or_
from common.emailer import send_email
from common.logging import log_audit_event, LOGIN_EVENT

auth_bp = Blueprint("auth", __name__, template_folder="../templates")


LOCKOUT_ATTEMPTS = 3
RESET_TOKEN_TTL_MINUTES = 30

def issue_reset_link(user: User):
    token = user.generate_reset_token()
    db.session.commit()

    # If you email the link (prod):
    reset_url = url_for("auth.reset_token", token=token, _external=True)
    try:
        send_email(
            to=user.EMAIL,
            subject="Password reset",
            body=f"Click to reset your password:\n{reset_url}\nThis link may expire."
        )
        flash("If an account exists, we emailed a reset link.", "info")
        session.pop("pw_reset_user_id", None)
        return redirect(url_for("auth.login"))
    except Exception:
        # Dev fallback: just redirect straight to the token page
        session.pop("pw_reset_user_id", None)
        flash("Reset link generated.", "info")
        return redirect(url_for("auth.reset_token", token=token))

@auth_bp.route('/settings')
@login_required
def settings():
    return render_template('auth/settings.html')

@auth_bp.post("/2fa/totp/disable")
@login_required
def disable_totp():
    current_user.TOTP_SECRET = None
    # if you added this flag
    if hasattr(current_user, "TOTP_ENABLED"):
        current_user.TOTP_ENABLED = False
    db.session.commit()
    log_audit_event("TOTP_DISABLED", f"user={current_user.USERNAME}")
    flash("Authenticator app 2FA disabled.", "info")
    return redirect(url_for("auth.settings"))

@auth_bp.route("/twofa/setup", methods=["GET"])
@login_required
def twofa_setup():
    if not current_user.TOTP_SECRET:
        current_user.TOTP_SECRET = pyotp.random_base32()
        from extensions import db
        db.session.commit()

    uri = f"otpauth://totp/TripleTsRewards:{current_user.USERNAME}?secret={current_user.TOTP_SECRET}&issuer=TripleTsRewards"
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    qr_data_url = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("utf-8")

    return render_template("auth/setup_2fa.html", qr_data_url=qr_data_url, secret=current_user.TOTP_SECRET)

def dashboard_endpoint_redirect(user) -> str:
    mapping = {
        Role.ADMINISTRATOR: "administrator_bp.dashboard",
        Role.SPONSOR: "sponsor_bp.dashboard",
        Role.DRIVER: "driver_bp.dashboard",
    }
    return mapping.get(user.USER_TYPE, "common.index")

@auth_bp.get("/2fa/challenge")
def twofa_challenge():
    # user just passed password but hasn't completed 2FA yet
    uid = session.get("pre_2fa_user_id")
    if not uid:
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("auth.login"))
    return render_template("auth/totp_challenge.html")

@auth_bp.post("/2fa/verify")
def twofa_verify_login():
    uid = session.get("pre_2fa_user_id")
    if not uid:
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("auth.login"))

    user = db.session.get(User, uid)
    token = (request.form.get("token") or "").strip()

    if not (user and user.TOTP_SECRET):
        flash("Two-factor is not enabled for this account.", "warning")
        return redirect(url_for("auth.login"))

    totp = pyotp.TOTP(user.TOTP_SECRET)
    if totp.verify(token, valid_window=1):
        session.pop("pre_2fa_user_id", None)
        login_user(user)
        flash("Login successful.", "success")
        endpoint = dashboard_endpoint_redirect(user)
        return redirect(url_for(endpoint))
    else:
        flash("Invalid code. Please try again.", "danger")
        return render_template("auth/totp_challenge.html"), 400

@auth_bp.post("/2fa/verify-setup")
@login_required
def twofa_verify_setup():
    token = (request.form.get("token") or "").strip()
    if not current_user.TOTP_SECRET:
        flash("No 2FA setup in progress.", "warning")
        return redirect(url_for("auth.twofa_setup"))

    totp = pyotp.TOTP(current_user.TOTP_SECRET)
    if totp.verify(token, valid_window=1):
        current_user.TOTP_ENABLED = True  # if you have this column
        db.session.commit()
        flash("Two-factor authentication is enabled.", "success")
        return redirect(url_for("auth.settings"))
    else:
        flash("Invalid code. Please try again.", "danger")
        return redirect(url_for("auth.twofa_setup"))


@auth_bp.get("/2fa/email/setup")
@login_required
def email_2fa_setup():
    if not current_user.EMAIL:
        flash("Add an email to your profile before enabling Email 2FA.", "warning")
        return redirect(url_for("auth.settings"))
    # send code
    code = create_email_code(current_user, "setup")
    send_email(
        current_user.EMAIL,
        "Your Email 2FA verification code",
        f"Your {current_user.USERNAME} 2FA setup code is: {code}\nThis code expires in 10 minutes."
    )
    flash("We sent a 6-digit code to your email. Enter it below to enable Email 2FA.", "info")
    return render_template("auth/email_2fa_setup.html")

@auth_bp.post("/2fa/email/verify")
@login_required
def email_2fa_verify():
    code = (request.form.get("code") or "").strip()
    if not code:
        flash("Enter the 6-digit code.", "warning")
        return redirect(url_for("auth.email_2fa_setup"))

    ok = verify_email_code(current_user, "setup", code)
    if not ok:
        flash("Invalid or expired code.", "danger")
        return redirect(url_for("auth.email_2fa_setup"))

    current_user.EMAIL_VERIFIED = True
    current_user.EMAIL_2FA_ENABLED = True
    db.session.commit()
    log_audit_event("EMAIL_2FA_ENABLED", f"user={current_user.USERNAME}")
    flash("Email 2FA enabled!", "success")
    return redirect(url_for("auth.settings"))


def _is_safe_url(target: str) -> bool:
    ref = urlparse(request.host_url)
    test = urlparse(urljoin(request.host_url, target))
    return test.scheme in ("http", "https") and ref.netloc == test.netloc

def _redirect_by_role(user):
    role = getattr(user, "USER_TYPE", None)
    if role == Role.ADMINISTRATOR:
        return redirect(url_for("administrator_bp.dashboard"))
    if role == Role.SPONSOR:
        return redirect(url_for("sponsor_bp.dashboard"))
    # default → driver
    return redirect(url_for("driver_bp.dashboard"))


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return _redirect_by_role(current_user)

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(USERNAME=username).first()
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        
        if not user:
            flash("Invalid username or password", "danger")
            log_audit_event(LOGIN_EVENT, f"FAIL user={username} ip={ip}")
            return render_template("common/login.html")
        
        if user.is_account_locked():
            if user.LOCKED_REASON == "admin":
                until = user.LOCKOUT_TIME.strftime("%Y-%m-%d %H:%M:%S") if user.LOCKOUT_TIME else "later"
                flash(f"Your account has been locked by an administrator until {until}.", "danger")
                log_audit_event(LOGIN_EVENT, f"user={user.USERNAME} ip={ip} reason=locked")
                return render_template("common/login.html")
            else:
                flash("Account locked. Please Contact your Administrator.", "danger")
                log_audit_event(LOGIN_EVENT, f"user={user.USERNAME} ip={ip} reason=locked")
                return render_template("common/login.html")
        
        if not user.check_password(password):
            user.register_failed_attempt()
            db.session.commit()
            remaining = max(0, LOCKOUT_ATTEMPTS - user.FAILED_ATTEMPTS)
            flash(f"Invalid username or password. {remaining} attempts remaining.", "danger")
            log_audit_event(LOGIN_EVENT, f"user={user.USERNAME} ip={ip} attempts={user.FAILED_ATTEMPTS}")
            
            # Send security notification for failed login attempts
            if user.wants_security_notifications:
                attempt_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
                message = f"Suspicious login activity detected on your account at {attempt_time}. Failed login attempt from IP: {ip}. If this wasn't you, please contact support immediately."
                try:
                    Notification.create_notification(
                        recipient_code=user.USER_CODE,
                        sender_code=user.USER_CODE,  # System notification from user to self
                        message=message
                    )
                except Exception as e:
                    # Log the error but don't fail the login process
                    log_audit_event("SECURITY_NOTIFICATION_FAILED", f"Failed to send security notification to user {user.USERNAME}: {str(e)}")
            
            return render_template("common/login.html")
        
        needs_totp = bool(user.TOTP_SECRET)
        needs_email = bool(user.EMAIL_2FA_ENABLED)
        
        if needs_totp or needs_email:
            session["pre_2fa_user_id"] = user.USER_CODE
            if needs_totp:
                return redirect(url_for("auth.twofa_prompt"))
            
            code = create_email_code(user, purpose="login")
            send_email(
                user.EMAIL,
                subject="Your Login 2FA Code",
                body=f"Your {user.USERNAME} login 2FA code is: {code}\nThis code expires in 10 minutes."
            )
            return redirect(url_for("auth.email_2fa_prompt"))

        # on successful login
        user.clear_failed_attempts()
        db.session.commit()
        login_user(user)
        flash("Login successful!", "success")
        log_audit_event(LOGIN_EVENT, f"user={user.USERNAME} role={user.USER_TYPE} ip={ip}")
        
        next_page = request.args.get("next")
        if next_page and _is_safe_url(next_page):
            return redirect(next_page)
        return _redirect_by_role(user)
    return render_template("common/login.html")  # a shared login template
    
@auth_bp.get("/2fa/email")
def email_2fa_prompt():
    uid = session.get("pre_2fa_user_id")
    if not uid:
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("auth.login"))
    return render_template("auth/email_2fa_prompt.html")

@auth_bp.get("/2fa/prompt")
def twofa_prompt():
    uid = session.get("pre_2fa_user_id")
    if not uid:
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("auth.login"))
    user = db.session.get(User, uid)
    if user and user.TOTP_SECRET:
        return redirect(url_for("auth.twofa_challenge"))
    return redirect(url_for("auth.email_2fa_prompt"))

@auth_bp.post("/2fa/email")
def email_2fa_challenge_verify():
    uid = session.get("pre_2fa_user_id")
    if not uid:
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("auth.login"))

    user = db.session.get(User, uid)
    code = (request.form.get("code") or "").strip()

    if verify_email_code(user, "login", code):
        session.pop("pre_2fa_user_id", None)
        login_user(user)
        flash("Login successful.", "success")
        endpoint = dashboard_endpoint_redirect(user)
        return redirect(url_for(endpoint))

    flash("Invalid or expired code.", "danger")
    return render_template("auth/email_2fa_prompt.html"), 400

@auth_bp.post("/2fa/email/resend")
def email_2fa_resend():
    uid = session.get("pre_2fa_user_id")
    if not uid:
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("auth.login"))
    user = db.session.get(User, int(uid))
    code = create_email_code(user, "login")
    send_email(user.EMAIL, "Your login code", f"Your login code is: {code}\nExpires in 10 minutes.")
    flash("A new code was sent.", "info")
    return redirect(url_for("auth.email_2fa_prompt"))

@auth_bp.post("/settings/2fa/email/enable")
@login_required
def email_2fa_enable():
    if not current_user.EMAIL_VERIFIED:
        flash("Verify your email before enabling Email 2FA.", "warning")
        return redirect(url_for("auth.settings"))
    current_user.EMAIL_2FA_ENABLED = 1
    db.session.commit()
    flash("Email 2FA enabled.", "success")
    return redirect(url_for("auth.settings"))

@auth_bp.post("/settings/2fa/email/disable")
@login_required
def email_2fa_disable():
    current_user.EMAIL_2FA_ENABLED = 0
    db.session.commit()
    flash("Email 2FA disabled.", "success")
    return redirect(url_for("auth.settings"))
    
@auth_bp.get("/logout")
@login_required
def logout():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    # capture BEFORE logging out
    uname = current_user.USERNAME
    urole = current_user.USER_TYPE

    # log first while we still have the user info
    log_audit_event(LOGIN_EVENT, f"user={uname} role={urole} ip={ip}")

    # then perform the logout
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))

@auth_bp.get("/reset/2fa/totp")
def reset_totp_prompt():
    uid = session.get("pw_reset_user_id")
    if not uid:
        flash("Session expired. Please try again.", "warning")
        return redirect(url_for("auth.login"))
    return render_template("auth/reset_totp_prompt.html")

@auth_bp.post("/reset/2fa/totp")
def reset_totp_verify():
    uid = session.get("pw_reset_user_id")
    if not uid:
        flash("Session expired. Please try again.", "warning")
        return redirect(url_for("auth.login"))

    user = db.session.get(User, uid)
    token = (request.form.get("token") or "").strip()

    if not (user and user.TOTP_SECRET):
        flash("2FA not enabled for this account.", "danger")
        return redirect(url_for("auth.login"))

    totp = pyotp.TOTP(user.TOTP_SECRET)
    if totp.verify(token, valid_window=1):
        return issue_reset_link(user)

    flash("Invalid or expired code.", "danger")
    return render_template("auth/reset_totp_prompt.html"), 400



@auth_bp.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "GET":
        return render_template("common/reset_password.html")

    # POST
    identifier = (request.form.get("username") or request.form.get("email") or "").strip()

    # Do not leak if user exists or not
    user = None
    if identifier:
        user = (User.query
                .filter( (User.USERNAME == identifier) | (User.EMAIL == identifier) )
                .first())

    if not user:
        # Same response either way
        flash("If an account exists, we emailed a reset link.", "info")
        return redirect(url_for("auth.login"))

    # Gate with 2FA when enabled
    needs_totp  = bool(user.TOTP_SECRET)
    needs_email = bool(user.EMAIL_2FA_ENABLED)

    if needs_totp or needs_email:
        session["pw_reset_user_id"] = user.USER_CODE
        if needs_totp:
            return redirect(url_for("auth.reset_totp_prompt"))
        else:
            # send email 2FA code specifically for 'reset'
            create_email_code(user, "reset", minutes=10)
            return redirect(url_for("auth.reset_email_prompt"))

    # No 2FA → issue link immediately
    return issue_reset_link(user)


def reset_request():
    if request.method == "POST":
        identifier = request.form.get("username", "").strip()
        user = User.query.filter(or_(User.USERNAME == identifier, User.USERNAME== identifier)).first()
        if not user:
            flash("Username not found.", "danger")
            return render_template("common/reset_password.html")
        token = user.generate_reset_token()
        db.session.commit()
        
        reset_url = url_for("auth.reset_token", token=token, _external=True)
        flash(f"Password reset link (valid for {RESET_TOKEN_TTL_MINUTES} minutes): {reset_url}", "info")
        return redirect(url_for("auth.reset_password"))

@auth_bp.route("/reset/<token>", methods=["GET", "POST"])
def reset_token(token: str):
    user = User.query.filter_by(RESET_TOKEN=token).first()

    if not user or not user.RESET_TOKEN_CREATED_AT:
        flash("Invalid or expired token.", "danger")
        return redirect(url_for("auth.reset_password"))

    if datetime.utcnow() > user.RESET_TOKEN_CREATED_AT + timedelta(minutes=RESET_TOKEN_TTL_MINUTES):
        user.clear_reset_token()
        db.session.commit()
        flash("Token has expired Please request a new one.", "warning")
        log_audit_event("RESET EXPIRED", f"Password reset token expired for user {user.USERNAME}.")
        return redirect(url_for("auth.reset_password"))
    
    if request.method == "POST":
        new_password = request.form.get("password","")
        confirm_password = request.form.get("confirm_password","")
        
        if not new_password or new_password != confirm_password:
            flash("Passwords do not match or are empty.", "danger")
            return render_template("common/reset_with_token.html", token=token)
        
        if user.PASS and user.check_password(new_password.strip()):
            flash("New password cannot be the same as the old password.", "danger")
            return render_template("common/reset_with_token.html", token=token)
        
        user.set_password(new_password)
        user.clear_reset_token()
        user.clear_failed_attempts()  # also clear failed attempts on password reset
        db.session.commit()
        
        flash("Password has been reset. You can now log in.", "success")
        log_audit_event("RESET SUCCESS", f"Password reset successful for user {user.USERNAME}.")
        return redirect(url_for("auth.login"))
    
    return render_template("common/reset_with_token.html", token=token)
