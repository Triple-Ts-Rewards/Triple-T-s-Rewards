from flask import Blueprint, render_template, request, redirect, url_for, flash, Response
from flask_login import login_user, logout_user, login_required, current_user
from common.decorators import role_required
from models import User, Role, AuditLog, Driver
from extensions import db
from sqlalchemy import or_
from datetime import datetime, timedelta
from models import db, Sponsor
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
        username = request.form['username']
        password = request.form['password']

        # Look up user by USERNAME
        user = User.query.filter_by(USERNAME=username).first()

        # Check password with bcrypt
        if user and user.check_password(password):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('administrator_bp.dashboard'))
        else:
            flash("Invalid username or password", "danger")

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
    category_key = (request.args.get("event_type") or "").strip()

    if category_key not in AUDIT_CATEGORIES:
        flash("Unknown audit log type.", "warning")
        return redirect(url_for("administrator_bp.audit_menu"))

    start_str = request.args.get("start")
    end_str   = request.args.get("end")

    def parse_date(s):
        if not s:
            return None
        for fmt in ("%m/%d/%Y", "%Y-%m-%d"):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                pass
        return None

    start_dt = parse_date(start_str)
    end_dt   = parse_date(end_str)

    # Base query by category
    if category_key == "bulk_load":
        # Capture all known variants + any future "*bulk_load*"
        q = AuditLog.query.filter(
            or_(
                AuditLog.EVENT_TYPE.in_(list(AUDIT_CATEGORIES["bulk_load"])),
                AuditLog.EVENT_TYPE.ilike("bulk_load%"),
                AuditLog.EVENT_TYPE.ilike("%_bulk_load%"),
            )
        )
    else:
        q = AuditLog.query.filter(AuditLog.EVENT_TYPE.in_(list(AUDIT_CATEGORIES[category_key])))

    if start_dt:
        q = q.filter(AuditLog.CREATED_AT >= start_dt)
    if end_dt:
        q = q.filter(AuditLog.CREATED_AT < end_dt + timedelta(days=1))

    logs = q.order_by(AuditLog.CREATED_AT.desc()).limit(500).all()

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
        logs=logs,                       # <— make sure your template iterates 'logs'
        title=titles.get(category_key, "Audit Logs"),
        event_type=category_key,
        start=start_str,
        end=end_str,
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
            IS_ACTIVE=1
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
            sponsor = Sponsor(SPONSOR_ID=new_user.USER_CODE, ORG_NAME="Temp Org", STATUS="Pending")
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
    flash(f'Account for {user.USERNAME} has been unlocked.', 'success')
    return redirect(url_for('administrator_bp.locked_users'))



@administrator_bp.route('/unlock_all', methods=['POST'])
def unlock_all():
    locked_users = User.query.filter_by(IS_LOCKED_OUT=1).all()
    for user in locked_users:
        user.clear_failed_attempts()
        user.IS_LOCKED_OUT = 0
    db.session.commit()
    flash('All locked accounts have been unlocked.', 'success')
    return redirect(url_for('administrator_bp.locked_users'))

@administrator_bp.route('/accounts', methods=['GET'])
def accounts():
    users = User.query.filter_by(IS_ACTIVE=1).all()
    return render_template('administrator/accounts.html', accounts=users)

@administrator_bp.route('/disabled_accounts', methods=['GET'])
def disabled_accounts():
    users = User.query.filter_by(IS_ACTIVE=0).all()
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
        flash(f'User **{user.USERNAME}** has been enabled.', 'success')
        
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
    sponsors = Sponsor.query.filter_by(STATUS="Pending").all()
    return render_template("administrator/review_sponsor.html", sponsors=sponsors)

@administrator_bp.route("/sponsors/<int:sponsor_id>/<decision>", methods=['POST'])
@login_required
@role_required(Role.ADMINISTRATOR)
def sponsor_decision(sponsor_id, decision):
    sponsor = Sponsor.query.get_or_404(sponsor_id)
    if decision == "approve":
        sponsor.STATUS = "Approved"
        # Removed: if sponsor_user: sponsor_user.IS_ACTIVE = 1 
        flash(f"Sponsor '{sponsor.ORG_NAME}' approved!", "success") 
    elif decision == "reject":
        sponsor.STATUS = "Rejected"
        # Removed: if sponsor_user: sponsor_user.IS_ACTIVE = 0
        flash(f"Sponsor '{sponsor.ORG_NAME}' rejected.", "warning") 
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
    
    log_audit_event("ADMIN_TIMEOUT", f"User {user.USERNAME} timed out for {minutes} minutes.")
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
    log_audit_event("ADMIN_CLEAR_TIMEOUT", f"Timeout cleared for user {user.USERNAME}.")
    flash(f"Timeout cleared for user {user.USERNAME}.", "success")
    return redirect(url_for("administrator_bp.timeout_users"))