# triple-ts-rewards/triple-t-s-rewards/Triple-T-s-Rewards-72ca7a46f1915a7f669f3692e9b77d23b248eaee/driver/routes.py
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from common.decorators import role_required
from common.logging import DRIVER_POINTS, log_audit_event, LOGIN_EVENT
from models import Role, AuditLog, User, db, Sponsor, DriverApplication, Address, StoreSettings, Driver, Notification, LOCKOUT_ATTEMPTS, Organization, DriverSponsorAssociation
from extensions import bcrypt
from datetime import datetime

# Blueprint for driver-related routes
driver_bp = Blueprint('driver_bp', __name__, template_folder="../templates")

# Login
@driver_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(USERNAME=username).first()
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        
        if not user:
            flash("Invalid username or password", "danger")
            log_audit_event(LOGIN_EVENT, f"FAIL user={username} ip={ip}")
            return render_template('driver/login.html')
        
        if user.is_account_locked():
            if user.LOCKED_REASON == "admin":
                until = user.LOCKOUT_TIME.strftime("%Y-%m-%d %H:%M:%S") if user.LOCKOUT_TIME else "later"
                flash(f"Your account has been locked by an administrator until {until}.", "danger")
                log_audit_event(LOGIN_EVENT, f"user={user.USERNAME} ip={ip} reason=locked")
                return render_template('driver/login.html')
            else:
                flash("Account locked. Please Contact your Administrator.", "danger")
                log_audit_event(LOGIN_EVENT, f"user={user.USERNAME} ip={ip} reason=locked")
                return render_template('driver/login.html')
        
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
            
            return render_template('driver/login.html')
        
        # On successful login
        user.clear_failed_attempts()
        db.session.commit()
        login_user(user)
        flash("Login successful!", "success")
        log_audit_event(LOGIN_EVENT, f"user={user.USERNAME} role={user.USER_TYPE} ip={ip}")
        return redirect(url_for('driver_bp.dashboard'))

    # Looks inside templates/driver/login.html
    return render_template('driver/login.html')

# Dashboard
@driver_bp.route('/dashboard')
@role_required(Role.DRIVER, Role.SPONSOR, allow_admin=True, redirect_to='auth.login')
def dashboard():
    if current_user.USER_TYPE == Role.DRIVER:
        # Fetch all associations for the current driver
        associations = DriverSponsorAssociation.query.filter_by(driver_id=current_user.USER_CODE).all()
        
        # Calculate the total points from all associations
        total_points = sum(assoc.points for assoc in associations)
        
        # We can pass the associations directly to the template
        return render_template('driver/dashboard.html', user=current_user, associations=associations, total_points=total_points)

    # Fallback for other user types (sponsors, admins)
    sponsors = [] # Define sponsors as an empty list for non-drivers
    if current_user.USER_TYPE == Role.SPONSOR:
        # Your existing logic for sponsors can go here if needed
        pass

    return render_template('driver/dashboard.html', user=current_user, sponsors=sponsors)

# Point History
@driver_bp.route('/point_history')
@role_required(Role.DRIVER, allow_admin=True)
def point_history():
    events = AuditLog.query.filter(
        AuditLog.EVENT_TYPE == DRIVER_POINTS,
        AuditLog.DETAILS.like(f"%{current_user.USERNAME}%")
    ).order_by(AuditLog.CREATED_AT.desc()).all()
    return render_template("driver/point_history.html", events=events)

# Logout
@driver_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('auth.login'))

# Settings Page
@driver_bp.route('/settings', methods=['GET', 'POST'])
@role_required(Role.DRIVER, allow_admin=True)
def settings():
    if request.method == 'POST':
        wants_points = request.form.get('wants_point_notifications') == 'on'
        wants_orders = request.form.get('wants_order_notifications') == 'on'
        wants_security = request.form.get('wants_security_notifications') == 'on'
        
        current_user.wants_point_notifications = wants_points
        current_user.wants_order_notifications = wants_orders
        current_user.wants_security_notifications = wants_security
        db.session.commit()

        flash('Your settings have been updated!', 'success')
        return redirect(url_for('driver_bp.dashboard'))

    return render_template('driver/settings.html')

# Update Contact Information
@driver_bp.route('/update_info', methods=['GET', 'POST'])
@role_required(Role.DRIVER, Role.SPONSOR, allow_admin=True, redirect_to='auth.login')
def update_contact():
    from extensions import db

    driver = None
    if current_user.USER_TYPE == "driver":
        driver = Driver.query.get(current_user.USER_CODE)

    if request.method == 'POST':
        email = request.form.get('email')
        phone = request.form.get('phone')
        license_number = request.form.get('license_number') if driver else None

        # Basic email validation
        if not email or '@' not in email:
            flash('Please enter a valid email address.', 'danger')
            return redirect(url_for('driver_bp.update_contact'))

        # Check if email already exists for another user
        if User.query.filter(User.EMAIL == email, User.USER_CODE != current_user.USER_CODE).first():
            flash('Email already in use.', 'danger')
            return redirect(url_for('driver_bp.update_contact'))

        # Basic phone validation (optional)
        if phone and (not phone.isdigit() or len(phone) < 10):
            flash('Please enter a valid phone number.', 'danger')
            return redirect(url_for('driver_bp.update_contact'))

        # Check if phone already exists for another user
        if phone and User.query.filter(User.PHONE == phone, User.USER_CODE != current_user.USER_CODE).first():
            flash('Phone number already in use.', 'danger')
            return redirect(url_for('driver_bp.update_contact'))

        try:
            current_user.EMAIL = email
            current_user.PHONE = phone

            # Only drivers update license number
            if driver is not None and license_number is not None:
                driver.LICENSE_NUMBER = license_number

            db.session.commit()
            flash('Contact information updated successfully!', 'success')
            return redirect(url_for('driver_bp.dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while updating your information', 'danger')
            return redirect(url_for('driver_bp.update_info'))

    return render_template('driver/update_info.html', user=current_user, driver=driver)

# Update Password
@driver_bp.route('/change_password', methods=['GET', 'POST'])
@role_required(Role.DRIVER, Role.SPONSOR, allow_admin=True, redirect_to='auth.login')
def change_password():
    from extensions import db

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Verify current password
        if not bcrypt.check_password_hash(current_user.PASS, current_password):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('driver_bp.change_password'))

        # Validate new password
        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('driver_bp.change_password'))

        if len(new_password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return redirect(url_for('driver_bp.change_password'))

        # Update password and email
        try:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            current_user.PASS = hashed_password
            db.session.commit()
            flash('Information updated successfully!', 'success')
            return redirect(url_for('driver_bp.dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while updating your information', 'danger')
            return redirect(url_for('driver_bp.change_password'))

    return render_template('driver/update_info.html', user=current_user)

# Driver Application
@driver_bp.route("/driver_app", methods=["GET", "POST"])
@login_required
def apply_driver():
    # Get all approved organizations
    organizations = Organization.query.filter(Organization.STATUS == "Approved").all()

    if request.method == "POST":
        org_id = request.form["org_id"]
        reason = request.form.get("reason", "")
        
        driver_profile = Driver.query.get(current_user.USER_CODE)
        license_number = driver_profile.LICENSE_NUMBER if driver_profile else None

        existing = DriverApplication.query.filter_by(
            DRIVER_ID=current_user.USER_CODE,
            ORG_ID=org_id
        ).first()

        if existing:
            flash("You already applied to this organization.", "warning")
        else:
            application = DriverApplication(
                DRIVER_ID=current_user.USER_CODE,
                ORG_ID=org_id,
                REASON=reason,
                STATUS="Pending"
            )
            db.session.add(application)
            db.session.commit()
            flash("Application submitted successfully! Await sponsor review.", "success")
        return redirect(url_for("driver_bp.dashboard"))

    return render_template("driver/driver_app.html", organizations=organizations)

# Address Management
@driver_bp.route('/addresses')
@role_required(Role.DRIVER, allow_admin=True)
def addresses():
    return render_template('driver/addresses.html')

@driver_bp.route('/addresses/add', methods=['GET', 'POST'])
@role_required(Role.DRIVER, allow_admin=True)
def add_address():
    if request.method == 'POST':
        new_address = Address(
            user_id=current_user.USER_CODE,
            street=request.form['street'],
            city=request.form['city'],
            state=request.form['state'],
            zip_code=request.form['zip_code'],
            is_default=request.form.get('is_default') == 'on'
        )
        db.session.add(new_address)
        db.session.commit()
        flash('Address added successfully!', 'success')
        return redirect(url_for('driver_bp.addresses'))
    return render_template('driver/address_form.html')

@driver_bp.route('/addresses/edit/<int:address_id>', methods=['GET', 'POST'])
@role_required(Role.DRIVER, allow_admin=True)
def edit_address(address_id):
    address = Address.query.get_or_404(address_id)
    if request.method == 'POST':
        address.street = request.form['street']
        address.city = request.form['city']
        address.state = request.form['state']
        address.zip_code = request.form['zip_code']
        address.is_default = request.form.get('is_default') == 'on'
        db.session.commit()
        flash('Address updated successfully!', 'success')
        return redirect(url_for('driver_bp.addresses'))
    return render_template('driver/address_form.html', address=address)

@driver_bp.route('/addresses/delete/<int:address_id>', methods=['POST'])
@role_required(Role.DRIVER, allow_admin=True)
def delete_address(address_id):
    address = Address.query.get_or_404(address_id)
    db.session.delete(address)
    db.session.commit()
    flash('Address deleted successfully!', 'success')
    return redirect(url_for('driver_bp.addresses'))

@driver_bp.route('/addresses/set_default/<int:address_id>', methods=['POST'])
@role_required(Role.DRIVER, allow_admin=True)
def set_default_address(address_id):
    # First, unset any other default addresses
    Address.query.filter_by(user_id=current_user.USER_CODE, is_default=True).update({'is_default': False})
    # Then, set the new default address
    address = Address.query.get_or_404(address_id)
    address.is_default = True
    db.session.commit()
    flash('Default address has been updated!', 'success')
    return redirect(url_for('driver_bp.addresses'))


@driver_bp.route('/truck_rewards_store/<int:org_id>')
@role_required(Role.DRIVER)
def truck_rewards_store(org_id):
    association = DriverSponsorAssociation.query.filter_by(driver_id=current_user.USER_CODE, ORG_ID=org_id).first()
    if not association:
        flash("You do not have access to this organization's store.", "danger")
        return redirect(url_for('driver_bp.dashboard'))

    # Proceed to show the store for the given organization
    # You will need a template for this.
    return render_template('driver/truck_rewards_store.html', org_id=org_id)

@driver_bp.route('/redirect_to_store')
@login_required
@role_required(Role.DRIVER)
def redirect_to_store():
    """
    Finds the first sponsor a driver is associated with and redirects to their store.
    If no sponsors are found, redirects to the application page.
    """
    # Find the first association for the current driver.
    association = DriverSponsorAssociation.query.filter_by(driver_id=current_user.USER_CODE).first()

    if association:
        # If an organization is found, redirect to their store.
        return redirect(url_for('driver_bp.truck_rewards_store', org_id=association.ORG_ID))
    else:
        # If no organizations are found, send them to the application page with a helpful message.
        flash("You are not yet a member of any sponsor organizations. Apply to one to get access to a store!", "info")
        return redirect(url_for('driver_bp.apply_driver'))
    
@driver_bp.route('/redirect_to_cart')
@login_required
@role_required(Role.DRIVER)
def redirect_to_cart():
    """
    Finds the first sponsor a driver is associated with and redirects to their cart.
    If no sponsors are found, redirects to the application page.
    """
    # Find the first association for the current driver.
    association = DriverSponsorAssociation.query.filter_by(driver_id=current_user.USER_CODE).first()

    if association:
        # If an organization is found, redirect to their cart page.
        return redirect(url_for('rewards_bp.view_cart', org_id=association.ORG_ID))
    else:
        # If no organizations are found, send them to the application page with a helpful message.
        flash("You must join a sponsor's organization to have a cart.", "info")
        return redirect(url_for('driver_bp.apply_driver'))