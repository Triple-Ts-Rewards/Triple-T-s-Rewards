from urllib.parse import urlencode
from flask import Blueprint, render_template, request, redirect, url_for, flash, Response
from flask_login import login_user, logout_user, login_required, current_user
from common.decorators import role_required
from models import DriverSponsorAssociation, User, Role, AuditLog, Notification, LOCKOUT_ATTEMPTS
from extensions import db
from extensions import bcrypt
from sqlalchemy import or_
from common.logging import (LOGIN_EVENT, SALES_BY_SPONSOR, SALES_BY_DRIVER, INVOICE_EVENT, DRIVER_POINTS, log_audit_event, DRIVER_DROPPED, ACCOUNT_DISABLED, ACCOUNT_ENABLED, ADMIN_TIMEOUT_EVENT, ADMIN_CLEAR_TIMEOUT, ACCOUNT_UNLOCKED, ACCOUNT_UNLOCKED_ALL, ACCOUNT_DELETED)
from datetime import datetime, timedelta
from models import db, Sponsor, Driver, Admin,  User, Role, AuditLog, Organization, DriverApplication
import csv
from io import StringIO
from audit_types import AUDIT_CATEGORIES
from common.logging import log_audit_event

# Blueprint for administrator-related routes
administrator_bp = Blueprint('administrator_bp', __name__, template_folder="../templates")

@administrator_bp.get("/audit_logs/export")
@role_required(Role.ADMINISTRATOR, allow_admin=False)
def export_audit_csv():
    category_key = request.args.get("event_type") or request.args.get("type", "")
    start_str = request.args.get("start")
    end_str = request.args.get("end")

    def parse_date(s):
        for fmt in ("%m/%d/%Y", "%Y-%m-%d"):
            try:
                return datetime.strptime(s, fmt)
            except (ValueError, TypeError):
                pass
        return None

    start_dt = parse_date(start_str)
    end_dt = parse_date(end_str)

    if category_key and category_key in AUDIT_CATEGORIES:
        event_types = list(AUDIT_CATEGORIES[category_key])
    else:
        event_types = None  # export all

    q = AuditLog.query.order_by(AuditLog.CREATED_AT.desc())
    if event_types:
        q = q.filter(AuditLog.EVENT_TYPE.in_(event_types))
    if start_dt:
        q = q.filter(AuditLog.CREATED_AT >= start_dt)
    if end_dt:
        q = q.filter(AuditLog.CREATED_AT < end_dt + timedelta(days=1))

    rows = q.all()

    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(["created_at", "event_type", "details", "id"])
    for row in rows:
        cw.writerow([
            row.CREATED_AT.strftime("%Y-%m-%d %H:%M:%S") if row.CREATED_AT else "",
            row.EVENT_TYPE or "",
            row.DETAILS or "",
            row.EVENT_ID or "",
        ])

    filename = f"audit_logs_{category_key or 'all'}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(si.getvalue().encode("utf-8"),
                    mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={filename}"})

@administrator_bp.route("/audit_logs")
@role_required(Role.ADMINISTRATOR, allow_admin=False)
def audit_menu():
    return render_template("administrator/audit_menu.html")

# Login
@administrator_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(USERNAME=username).first()
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        
        if not user:
            flash("Invalid username or password", "danger")
            log_audit_event(LOGIN_EVENT, f"FAIL user={username} ip={ip}")
            return render_template('administrator/login.html')
        
        if user.is_account_locked():
            if user.LOCKED_REASON == "admin":
                until = user.LOCKOUT_TIME.strftime("%Y-%m-%d %H:%M:%S") if user.LOCKOUT_TIME else "later"
                flash(f"Your account has been locked by an administrator until {until}.", "danger")
                log_audit_event(LOGIN_EVENT, f"user={user.USERNAME} ip={ip} reason=locked")
                return render_template('administrator/login.html')
            else:
                flash("Account locked. Please Contact your Administrator.", "danger")
                log_audit_event(LOGIN_EVENT, f"user={user.USERNAME} ip={ip} reason=locked")
                return render_template('administrator/login.html')
        
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
            
            return render_template('administrator/login.html')
        
        # On successful login
        user.clear_failed_attempts()
        db.session.commit()
        login_user(user)
        flash("Login successful!", "success")
        log_audit_event(LOGIN_EVENT, f"user={user.USERNAME} role={user.USER_TYPE} ip={ip}")
        return redirect(url_for('administrator_bp.dashboard'))

    # Looks inside templates/administrator/login.html
    return render_template('administrator/login.html')

# Dashboard
@administrator_bp.route('/dashboard')
@role_required(Role.ADMINISTRATOR, allow_admin=False)
def dashboard():
    # Looks inside templates/administrator/dashboard.html
    return render_template('administrator/dashboard.html', user=current_user)

@administrator_bp.get('/audit_logs/view')
@role_required(Role.ADMINISTRATOR, allow_admin=False)
def view_audit_logs():
    # category key from menu: "login", "driver_points", etc.
    category_key = (request.args.get("event_type") or "").strip()

    if category_key not in AUDIT_CATEGORIES:
        flash("Unknown audit log type.", "warning")
        return redirect(url_for("administrator_bp.audit_menu"))

    # ---- parse filters ----
    def parse_date(s):
        if not s:
            return None
        for fmt in ("%Y-%m-%d", "%m/%d/%Y"):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                pass
        return None

    start_str = request.args.get("start")
    end_str   = request.args.get("end")
    username  = (request.args.get("username") or "").strip()
    contains  = (request.args.get("q") or "").strip()

    start_dt = parse_date(start_str)
    end_dt   = parse_date(end_str)

    # ---- ALWAYS initialize q first ----
    q = AuditLog.query

    # limit to the event types in this category
    event_types = list(AUDIT_CATEGORIES[category_key])
    q = q.filter(AuditLog.EVENT_TYPE.in_(event_types))

    # apply optional date filters
    if start_dt:
        q = q.filter(AuditLog.CREATED_AT >= start_dt)
    if end_dt:
        # include entire end day
        q = q.filter(AuditLog.CREATED_AT < end_dt + timedelta(days=1))

    # optional username / contains (DETAILS) filters, if you store such info in DETAILS
    if username:
        # naive contains match; adapt to your schema as needed
        q = q.filter(AuditLog.DETAILS.ilike(f"%{username}%"))
    if contains:
        q = q.filter(AuditLog.DETAILS.ilike(f"%{contains}%"))

    # ---- pagination ----
    try:
        page = int(request.args.get("page", 1))
    except ValueError:
        page = 1
    try:
        per_page = int(request.args.get("per_page", 25))
    except ValueError:
        per_page = 25
    per_page = max(1, min(per_page, 200))  # sane bounds

    q = q.order_by(AuditLog.CREATED_AT.desc())
    pagination = q.paginate(page=page, per_page=per_page, error_out=False)
    logs = pagination.items

    # ---- build pagination helper params for template ----
    # base_url is the path; url_params_qs is the preserved query without page/per_page
    base_url = url_for('administrator_bp.view_audit_logs')
    url_params = request.args.to_dict()
    url_params.pop("page", None)
    url_params_qs = "&".join(f"{k}={v}" for k, v in url_params.items() if v)

    titles = {
        "login": "Login Activity",
        "driver_points": "Driver Point Tracking",
        "sales_by_sponsor": "Sales by Sponsor",
        "sales_by_driver": "Sales by Driver",
        "invoices": "Invoices",
        "bulk_load": "Bulk Loading",
    }

    return render_template(
        "administrator/audit_list.html",
        # data
        logs=logs,
        title=titles.get(category_key, "Audit Logs"),
        event_type=category_key,

        # filters back into the template (so inputs keep their values)
        start=start_str, end=end_str, username=username, q=contains,

        # pagination context
        pagination=pagination,
        per_page=per_page,
        base_url=base_url,
        url_params_qs=url_params_qs,
    )
# Logout
@administrator_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('auth.login'))

# Add User
@administrator_bp.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if request.method == 'POST':
        # Get form data
        name = request.form['name']
        email = request.form['email']
        username = request.form['username']
        role = request.form['role']

        #split the name into first and last
        name_parts = name.split(' ', 1)
        first_name = name_parts[0]
        last_name = name_parts[1]
        
        # Check if the user already exists
        existing_user = User.query.filter_by(USERNAME=username).first()
        if existing_user:
            flash("Username already exists.", "danger")
            return redirect(url_for('administrator_bp.add_user'))

        # Find the highest existing USER_CODE and increment it
        last_user = User.query.order_by(User.USER_CODE.desc()).first()
        if last_user:
            new_user_code = last_user.USER_CODE + 1
        else:
            # Starting code for the first user if the table is empty
            new_user_code = 1
        
        # Create a new User instance with the generated USER_CODE and hashed password
        new_user = User(
            USER_CODE=new_user_code, 
            USERNAME=username,  
            USER_TYPE=role,
            FNAME=first_name,
            LNAME=last_name,
            EMAIL=email,
            IS_LOCKED_OUT=0,
            CREATED_AT=datetime.now(),
            IS_ACTIVE=1,
            wants_point_notifications=True,
            wants_order_notifications=True,
            wants_security_notifications=True
        )
        new_pass = new_user.admin_set_new_pass()

        flash_message = (
        f"🚨 **TEMPORARY PASSWORD FOR TESTING:** `{new_pass}`. "
        f"This should be replaced by a secure notification system in production. 🚨"
        )
        flash(flash_message, "warning")

        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        if role == "driver":
            driver = Driver(DRIVER_ID=new_user.USER_CODE, LICENSE_NUMBER="temp_license")
            db.session.add(driver)
        elif role == "sponsor":
            # Create a temporary organization for this sponsor
            temp_org = Organization(
                ORG_NAME="Temp Organization - " + new_user.USERNAME,
                STATUS="Pending",
                CREATED_AT=datetime.utcnow()
            )
            db.session.add(temp_org)
            db.session.flush()  # Get the ORG_ID
            
            sponsor = Sponsor(USER_CODE=new_user.USER_CODE, ORG_ID=temp_org.ORG_ID)
            db.session.add(sponsor)
        elif role == "admin":
            admin = Admin(ADMIN_ID=new_user.USER_CODE)
            db.session.add(admin)

        db.session.commit()

        flash(f"User '{username}' created successfully with role '{role}' and code '{new_user_code}'.", "success")
        return redirect(url_for('administrator_bp.dashboard'))

    return render_template('administrator/add_user.html')

@administrator_bp.route('/locked_users', methods=['GET'])
def locked_users():
    locked_users = User.query.filter_by(IS_LOCKED_OUT=1).all()
    return render_template('administrator/locked_users.html', locked_users=locked_users)


@administrator_bp.route('/unlock/<int:user_id>', methods=['POST'])
def unlock(user_id):
    user = User.query.get_or_404(user_id)
    user.clear_failed_attempts()
    user.IS_LOCKED_OUT = 0
    db.session.commit()
    log_audit_event(ACCOUNT_UNLOCKED, f"admin={current_user.USERNAME} unlocked_user={user.USERNAME} code={user.USER_CODE}")
    flash(f'Account for {user.USERNAME} has been unlocked.', 'success')
    return redirect(url_for('administrator_bp.locked_users'))



@administrator_bp.route('/unlock_all', methods=['POST'])
def unlock_all():
    locked_users = User.query.filter_by(IS_LOCKED_OUT=1).all()
    for user in locked_users:
        user.clear_failed_attempts()
        user.IS_LOCKED_OUT = 0
    db.session.commit()
    log_audit_event(ACCOUNT_UNLOCKED_ALL, f"admin={current_user.USERNAME} unlocked_all_accounts")
    flash('All locked accounts have been unlocked.', 'success')
    return redirect(url_for('administrator_bp.locked_users'))

@administrator_bp.route("/accounts")
@login_required
def accounts():
    search_query = request.args.get("search", "").strip()
    role_filter = request.args.get("role", "").strip()

    query = User.query
    if search_query:
        query = query.filter(User.USERNAME.ilike(f"%{search_query}%"))
    if role_filter:
        query = query.filter(User.USER_TYPE == role_filter)

    accounts = query.order_by(User.USER_TYPE).all()
    return render_template("administrator/accounts.html", accounts=accounts)

@administrator_bp.route('/disabled_accounts', methods=['GET'])
def disabled_accounts():
    search_query = request.args.get("search", "").strip()
    role_filter = request.args.get("role", "").strip()

    query = User.query.filter_by(IS_ACTIVE=0)
    if search_query:
        query = query.filter(User.USERNAME.ilike(f"%{search_query}%"))
    if role_filter:
        query = query.filter(User.USER_TYPE == role_filter)

    users = query.order_by(User.USER_TYPE).all()
    return render_template('administrator/disabled_accounts.html', accounts=users)



# ----------------------------------------------------------------------
## User Management Routes
# ----------------------------------------------------------------------

@administrator_bp.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@role_required(Role.ADMINISTRATOR, allow_admin=False)
def edit_user(user_id):
    # Retrieve the user or return a 404 error if not found
    user = User.query.get_or_404(user_id)
    
    # Exclude the current user from being edited/disabled by themselves
    if user.USER_CODE == current_user.USER_CODE:
        flash("You cannot edit or disable your own account.", "danger")
        return redirect(url_for('administrator_bp.accounts'))

    if request.method == 'POST':
        # Handle form submission for updating user details
        
        # 1. Get form data
        new_username = request.form.get('username')
        new_email = request.form.get('email')
        new_fname = request.form.get('fname')
        new_lname = request.form.get('lname')
        new_user_type = request.form.get('user_type')

        try:
            # 2. Check for duplicate username/email (excluding the current user)
            username_check = User.query.filter(
                User.USERNAME == new_username, 
                User.USER_CODE != user_id
            ).first()
            if username_check:
                flash(f"Username '{new_username}' is already taken.", "danger")
                return redirect(url_for('administrator_bp.edit_user', user_id=user_id))

            email_check = User.query.filter(
                User.EMAIL == new_email, 
                User.USER_CODE != user_id
            ).first()
            if email_check:
                flash(f"Email '{new_email}' is already in use.", "danger")
                return redirect(url_for('administrator_bp.edit_user', user_id=user_id))

            # 3. Update the user object
            user.USERNAME = new_username
            user.EMAIL = new_email
            user.FNAME = new_fname
            user.LNAME = new_lname
            user.USER_TYPE = new_user_type
            
            # 4. Commit changes to the database
            db.session.commit()
            flash(f'User **{user.USERNAME}** updated successfully!', 'success')
            return redirect(url_for('administrator_bp.accounts'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error updating user: {str(e)}', 'danger')
            # Redirect back to the form on error
            return redirect(url_for('administrator_bp.edit_user', user_id=user_id))

    # GET request: Display the edit form
    return render_template('administrator/edit_user.html', user=user, roles=Role)

@administrator_bp.route('/disable_user/<int:user_id>', methods=['POST'])
@role_required(Role.ADMINISTRATOR, allow_admin=False)
def disable_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Prevent admin from disabling themselves
    if user.USER_CODE == current_user.USER_CODE:
        flash("You cannot disable your own account.", "danger")
        return redirect(url_for('administrator_bp.accounts'))

    # Check if the user is already disabled/inactive
    if user.IS_ACTIVE == 0:
        flash(f"User **{user.USERNAME}** is already disabled.", "warning")
    else:
        # Set the user to inactive and clear any lockouts
        user.IS_ACTIVE = 0
        user.IS_LOCKED_OUT = 0
        user.clear_failed_attempts()
        db.session.commit()
        log_audit_event(ACCOUNT_DISABLED, f"admin={current_user.USERNAME} disabled_user={user.USERNAME} code={user.USER_CODE}")
        flash(f'User **{user.USERNAME}** has been disabled.', 'info')
        
    return redirect(url_for('administrator_bp.accounts'))

@administrator_bp.route('/enable_user/<int:user_id>', methods=['POST'])
@role_required(Role.ADMINISTRATOR, allow_admin=False)
def enable_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.IS_ACTIVE == 1:
        flash(f"User **{user.USERNAME}** is already enabled.", "warning")
    else:
        user.IS_ACTIVE = 1
        user.clear_failed_attempts()
        db.session.commit()
        log_audit_event(ACCOUNT_ENABLED, f"admin={current_user.USERNAME} enabled_user={user.USERNAME} code={user.USER_CODE}")
        flash(f'User **{user.USERNAME}** has been enabled.', 'success')
        
    return redirect(url_for('administrator_bp.accounts'))

@administrator_bp.route('/delete_user/<int:user_id>', methods=['POST'])
@role_required(Role.ADMINISTRATOR, allow_admin=False)
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Prevent admin from deleting themselves
    if user.USER_CODE == current_user.USER_CODE:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for('administrator_bp.accounts'))

    if user.USER_TYPE == Role.DRIVER:
        DriverSponsorAssociation.query.filter_by(driver_id=user.USER_CODE).delete()
        DriverApplication.query.filter_by(DRIVER_ID=user.USER_CODE).delete()
        Driver.query.filter_by(DRIVER_ID=user.USER_CODE).delete()
    
    elif user.USER_TYPE == Role.SPONSOR:
        Sponsor.query.filter_by(USER_CODE=user.USER_CODE).delete()
    
    elif user.USER_TYPE == Role.ADMINISTRATOR:
        Admin.query.filter_by(ADMIN_ID=user.USER_CODE).delete()
    
    Notification.query.filter(or_(
        Notification.RECIPIENT_CODE == user.USER_CODE,
        Notification.SENDER_CODE == user.USER_CODE
    )).delete()
    
    log_audit_event(ACCOUNT_DELETED, f"admin={current_user.USERNAME} deleted_user={user.USERNAME} code={user.USER_CODE}")
    db.session.delete(user)
    db.session.commit()
    flash(f'User **{user.USERNAME}** has been deleted.', 'info')
    return redirect(url_for('administrator_bp.accounts'))

@administrator_bp.route('/reset_user_password/<int:user_id>', methods=['POST'])
@role_required(Role.ADMINISTRATOR, allow_admin=False)
def reset_user_password(user_id):
    user = User.query.get_or_404(user_id)

    new_pass = user.admin_set_new_pass()
    db.session.commit()

    flash_message = (
        f"Password for user '{user.USERNAME}' has been successfully reset. "
        f"🚨 **TEMPORARY PASSWORD FOR TESTING:** `{new_pass}`. "
        f"This should be replaced by a secure notification system in production. 🚨"
    )
    flash(flash_message, "warning")
    
    return redirect(url_for('administrator_bp.edit_user', user_id=user_id))

@administrator_bp.route("/sponsors")
@login_required
@role_required(Role.ADMINISTRATOR)
def review_sponsors():
    # Get all organizations with pending status
    pending_organizations = Organization.query.filter_by(STATUS="Pending").all()
    return render_template("administrator/review_sponsor.html", organizations=pending_organizations)

@administrator_bp.route("/sponsors/<int:ORG_ID>/<decision>", methods=["POST"])
@login_required
@role_required(Role.ADMINISTRATOR)
def sponsor_decision(ORG_ID, decision):
    organization = Organization.query.get_or_404(ORG_ID)
    if decision == "approve":
        organization.STATUS = "Approved"
        flash(f"Organization '{organization.ORG_NAME}' approved!", "success") 
    elif decision == "reject":
        organization.STATUS = "Rejected"
        flash(f"Organization '{organization.ORG_NAME}' rejected.", "warning") 
    else:
        flash("Invalid decision.", "danger")
        return redirect(url_for("administrator_bp.review_sponsors"))

    db.session.commit()
    return redirect(url_for("administrator_bp.review_sponsors"))

@administrator_bp.get("/timeouts")
@role_required(Role.ADMINISTRATOR)
def timeout_users():
    users = User.query.order_by(User.USERNAME.asc()).all()
    return render_template("administrator/timeout_users.html", users=users)

@administrator_bp.post("/set_timeout/<int:user_id>")
@role_required(Role.ADMINISTRATOR)
def set_timeout(user_id):
    minutes = int(request.form.get("minutes", 0))
    user = User.query.get_or_404(user_id)
    
    if minutes <= 0:
        flash("Duration must be greater than zero.", "danger")
        return redirect(url_for("administrator_bp.timeout_users"))
    
    user.IS_LOCKED_OUT = 1
    user.LOCKOUT_TIME = datetime.utcnow() + timedelta(minutes=minutes)
    user.LOCKED_REASON = "admin"
    db.session.commit()
    
    log_audit_event(ADMIN_TIMEOUT_EVENT, f"User {user.USERNAME} timed out for {minutes} minutes.")
    flash(f"User {user.USERNAME} has been timed out for {minutes} minutes.", "info")
    return redirect(url_for("administrator_bp.timeout_users"))

@administrator_bp.route("/clear_timeout/<int:user_id>", methods=["POST"])
@login_required
def clear_timeout(user_id):
    user = User.query.get_or_404(user_id)
    user.FAILED_ATTEMPTS = 0
    user.LOCKOUT_TIME = None
    user.IS_LOCKED_OUT = 0
    user.LOCKED_REASON = None
    db.session.commit()
    log_audit_event(ADMIN_CLEAR_TIMEOUT, f"Timeout cleared for user {user.USERNAME}.")
    flash(f"Timeout cleared for user {user.USERNAME}.", "success")
    return redirect(url_for("administrator_bp.timeout_users"))


@administrator_bp.route("/application-oversight")
@login_required
@role_required(Role.ADMINISTRATOR)
def application_oversight():
    """
    Admin view of all driver applications, status, and decision maker.
    """
    # Query all applications, joining with Organization for the name 
    # and User (via SPONSOR_RESPONSIBLE_ID) for the decision-maker's name.
    applications = DriverApplication.query.outerjoin(
        DriverApplication.organization
    ).outerjoin(
        DriverApplication.sponsor_responsible
    ).order_by(
        DriverApplication.RESPONDED_AT.desc(),
        DriverApplication.APPLIED_AT.desc() 
    ).all()
    
    return render_template("administrator/application_oversight.html", applications=applications)


# Update Contact Information
@administrator_bp.route('/update_info', methods=['GET', 'POST'])
@role_required(Role.ADMINISTRATOR, allow_admin=False)
def update_info():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()

        # Basic email validation
        if not email or '@' not in email:
            flash('Please enter a valid email address.', 'danger')
            return redirect(url_for('administrator_bp.update_info'))

        # Check if email already exists for another user
        if User.query.filter(User.EMAIL == email, User.USER_CODE != current_user.USER_CODE).first():
            flash('Email already in use.', 'danger')
            return redirect(url_for('administrator_bp.update_info'))

        # Basic phone validation (optional)
        if phone and (not phone.isdigit() or len(phone) < 10):
            flash('Please enter a valid phone number.', 'danger')
            return redirect(url_for('administrator_bp.update_info'))
        
        # Check if phone already exists for another user
        if phone and User.query.filter(User.PHONE == phone, User.USER_CODE != current_user.USER_CODE).first():
            flash('Phone number already in use.', 'danger')
            return redirect(url_for('administrator_bp.update_info'))
        
        try:
            current_user.EMAIL = email
            current_user.PHONE = phone

            db.session.commit()
            log_audit_event("ADMIN_INFO_UPDATE", f"Administrator {current_user.USERNAME} updated contact information")
            flash('Contact information updated successfully!', 'success')
            return redirect(url_for('administrator_bp.dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while updating your information', 'danger')
            return redirect(url_for('administrator_bp.update_info'))

    return render_template('administrator/update_info.html', user=current_user)

# Update Password
@administrator_bp.route('/change_password', methods=['GET', 'POST'])
@role_required(Role.ADMINISTRATOR, allow_admin=False)
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Verify current password
        if not bcrypt.check_password_hash(current_user.PASS, current_password):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('administrator_bp.change_password'))

        # Validate new password
        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('administrator_bp.change_password'))

        if len(new_password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return redirect(url_for('administrator_bp.change_password'))

        # Update password
        try:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            current_user.PASS = hashed_password
            db.session.commit()
            log_audit_event("ADMIN_PASSWORD_CHANGE", f"Administrator {current_user.USERNAME} changed password")
            flash('Password updated successfully!', 'success')
            return redirect(url_for('administrator_bp.dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while updating your password', 'danger')
            return redirect(url_for('administrator_bp.change_password'))

    return render_template('administrator/update_info.html', user=current_user)
