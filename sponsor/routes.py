# triple-ts-rewards/triple-t-s-rewards/Triple-T-s-Rewards-72ca7a46f1915a7f669f3692e9b77d23b248eaee/sponsor/routes.py
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from common.decorators import role_required
from common.logging import log_audit_event, DRIVER_POINTS, DRIVER_DROPPED, log_driver_dropped, log_points_debit
from datetime import datetime
from sqlalchemy.exc import IntegrityError
from extensions import db
from models import AuditLog, User, Role, StoreSettings, WeeklyPointsLog, db, DriverApplication, Sponsor, Notification, DriverSponsorAssociation, Driver, Organization, PointRequest
from extensions import db, bcrypt
from datetime import datetime, timedelta
import secrets
import string

# Blueprint for sponsor-related routes
sponsor_bp = Blueprint('sponsor_bp', __name__, template_folder="../templates")

@sponsor_bp.get("/reports/organization")
@login_required
@role_required(Role.SPONSOR, allow_admin=True)
def organization_reports():
    # Find this sponsor's organization
    sponsor = Sponsor.query.filter_by(USER_CODE=current_user.USER_CODE).first()
    if sponsor is None:
        flash("Sponsor record not found.", "danger")
        return redirect(url_for("sponsor_bp.dashboard"))

    # Pull ONLY logs where this sponsor’s org was involved
    logs = (
        AuditLog.query
        .filter(AuditLog.EVENT_TYPE == DRIVER_DROPPED)
        .filter(AuditLog.DETAILS.ilike(f"%org={sponsor.ORG_ID}%"))
        .order_by(AuditLog.CREATED_AT.desc())
        .all()
    )

    return render_template(
        "sponsor/organization_reports.html",
        logs=logs,
        sponsor=sponsor,
    )


@sponsor_bp.route("/apply-for-organization", methods=["GET", "POST"])
@role_required(Role.SPONSOR)
def apply_for_organization():
    # Get the current sponsor record
    sponsor = Sponsor.query.filter_by(USER_CODE=current_user.USER_CODE).first()

    available_orgs = Organization.query.filter(Organization.STATUS != 'Rejected').order_by(Organization.ORG_NAME).all()
    
    if request.method == 'POST':
        org_name = request.form.get('org_name', '').strip()
        
        if not org_name:
            flash("Organization name is required.", "danger")
            return redirect(url_for('sponsor_bp.apply_for_organization'))
        
        try:
            # Check if organization already exists
            existing_org = Organization.query.filter_by(ORG_NAME=org_name).first()
            
            if existing_org:
                # Organization exists, link sponsor to it
                org_id = existing_org.ORG_ID
                # If organization is already approved, sponsor is immediately approved
                if existing_org.STATUS == "Approved":
                    flash(f"You have been linked to the approved organization '{org_name}'.", "success")
                else:
                    flash(f"You have been linked to organization '{org_name}'. Status: {existing_org.STATUS}", "info")
            else:
                # Create new organization with pending status
                new_org = Organization(
                    ORG_NAME=org_name,
                    STATUS="Pending",
                    CREATED_AT=datetime.utcnow()
                )
                db.session.add(new_org)
                db.session.flush()  # Get the ORG_ID
                org_id = new_org.ORG_ID
                flash(f"New organization '{org_name}' created and submitted for review.", "success")
            
            # Update or create sponsor record
            if sponsor:
                sponsor.ORG_ID = org_id
            else:
                sponsor = Sponsor(
                    USER_CODE=current_user.USER_CODE,
                    ORG_ID=org_id
                )
                db.session.add(sponsor)
            
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            flash("An error occurred while submitting your application.", "danger")
        
        return redirect(url_for('sponsor_bp.apply_for_organization'))
    
    # GET request - render the form
    return render_template("sponsor/apply_for_organization.html", sponsor=sponsor, available_orgs=available_orgs)


def driver_query_for_sponsor(organization_id):
    return db.session.query(User).filter(User.USER_TYPE == Role.DRIVER, User.ORG_ID == organization_id).all()

def next_user_code():
    last_user = User.query.order_by(User.USER_CODE.desc()).first()
    return (last_user.USER_CODE + 1) if last_user else 1

def generate_temp_password(length: int = 10) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))

@sponsor_bp.route("/users/new", methods=["GET", "POST"])
@role_required(Role.SPONSOR, allow_admin=True)
def _next_user_code():
    last = User.query.order_by(User.USER_CODE.desc()).first()
    return (last.USER_CODE + 1) if last else 1

@sponsor_bp.route("/sponsor/users/new", methods=["GET", "POST"])
@role_required(Role.SPONSOR, allow_admin=True)
def create_sponsor_user():
    if request.method == "GET":
        return render_template("sponsor/create_user.html")

    # POST
    username = (request.form.get("username") or "").strip()

    if not username:
        flash("Username is required.", "danger")
        return redirect(url_for("sponsor_bp.create_sponsor_user"))

    # 1) Explicit duplicate check first
    if User.query.filter_by(USERNAME=username).first():
        flash("That username is already taken. Please pick another.", "danger")
        return redirect(url_for("sponsor_bp.create_sponsor_user"))

    # 2) Build the user with ALL required fields filled
    new_user = User(
        USER_CODE=_next_user_code(),
        USERNAME=username,
        USER_TYPE=Role.SPONSOR,
        FNAME="Sponsor",
        LNAME="User",
        EMAIL=f"{username}@example.com",   # or collect a real email in the form
        CREATED_AT=datetime.utcnow(),
        IS_ACTIVE=1,
        FAILED_ATTEMPTS=0,
        LOCKOUT_TIME=None,
        RESET_TOKEN=None,
        RESET_TOKEN_CREATED_AT=None,
        IS_LOCKED_OUT=0,
    )

    # Set a temporary password the sponsor can share with the new user
    # (Or generate one elsewhere and display it.)
    temp_password = "P@ssw0rd123"  # replace with your generator
    new_user.set_password(temp_password)

    try:
        db.session.add(new_user)
        db.session.commit()
    except IntegrityError as e:
        db.session.rollback()
        # Surface the REAL reason to your logs; keep message friendly to user
        print("IntegrityError creating sponsor user:", repr(e))
        flash("Could not create user (constraint error). Check required fields or username.", "danger")
        return redirect(url_for("sponsor_bp.create_sponsor_user"))
    except Exception as e:
        db.session.rollback()
        print("Error creating sponsor user:", repr(e))
        flash("Unexpected error creating user.", "danger")
        return redirect(url_for("sponsor_bp.create_sponsor_user"))

    log_audit_event("SPONSOR_CREATE_USER", f"by={current_user.USERNAME} new_user={username} role=sponsor")
    flash(f"Sponsor account created for '{username}'. Temporary password: {temp_password}", "success")
    return redirect(url_for("sponsor_bp.list_sponsor_users"))


@sponsor_bp.route("/users", methods=["GET"])
@role_required(Role.SPONSOR, allow_admin=True)
def list_sponsor_users():
    sponsors = User.query.filter_by(USER_TYPE=Role.SPONSOR).order_by(User.USERNAME.asc()).all()
    return render_template("sponsor/list_users.html", users=sponsors)


# Dashboard
@sponsor_bp.route('/dashboard')
@role_required(Role.SPONSOR, allow_admin=True)
def dashboard():
    # --- ADD THIS LOGIC ---
    # Fetch the sponsor record for the current user
    sponsor = Sponsor.query.filter_by(USER_CODE=current_user.USER_CODE).first()
    organization = None
    if sponsor and sponsor.organization: #
        organization = sponsor.organization #
    
    # Pass the sponsor and organization objects to the template
    return render_template('sponsor/dashboard.html', sponsor=sponsor, organization=organization)
    # --- END OF CHANGE ---

# Update Store Settings
@sponsor_bp.route('/settings', methods=['GET', 'POST'])
@role_required(Role.SPONSOR, allow_admin=True)
def update_settings():
    # Get the sponsor's organization ID
    sponsor = Sponsor.query.filter_by(USER_CODE=current_user.USER_CODE).first()
    if not sponsor:
        flash("Sponsor record not found.", "danger")
        return redirect(url_for('sponsor_bp.dashboard'))
        
    settings = StoreSettings.query.filter_by(ORG_ID=sponsor.ORG_ID).first()
    if not settings:
        settings = StoreSettings(ORG_ID=sponsor.ORG_ID)
        db.session.add(settings)
        db.session.commit()

    if request.method == 'POST':
        settings.ebay_category_id = request.form.get('ebay_category_id')
        settings.point_ratio = int(request.form.get('point_ratio'))
        db.session.commit()
        flash("Store settings updated successfully!", "success")
        return redirect(url_for('sponsor_bp.update_settings'))

    return render_template("sponsor/settings.html", settings=settings)


@sponsor_bp.route('/points', methods=['GET'])
@role_required(Role.SPONSOR, allow_admin=True)
def manage_points_page():
    """Display all drivers for awarding or removing points, with search and active/inactive filtering."""
    search_query = request.args.get("search", "").strip()
    status_filter = request.args.get("status", "").strip()
    sort_by = request.args.get("sort", "username_asc")

    # Fetch all associations for this sponsor
    sponsor = Sponsor.query.filter_by(USER_CODE=current_user.USER_CODE).first()

    # Restrict access if sponsor has no organization or no drivers
    if not sponsor or not sponsor.ORG_ID:
        flash("You must belong to an organization to access this page.", "warning")
        return redirect(url_for('sponsor_bp.dashboard'))

    # Check if sponsor has any drivers under their organization
    driver_count = DriverSponsorAssociation.query.filter_by(ORG_ID=sponsor.ORG_ID).count()
    if driver_count == 0:
        flash("You must have at least one driver in your organization to access this page.", "warning")
        return redirect(url_for('sponsor_bp.dashboard'))

    associations = DriverSponsorAssociation.query.filter_by(ORG_ID=sponsor.ORG_ID).all()

    # Combine driver user info with their points
    driver_data = [
        {"user": assoc.driver.user_account, "points": assoc.points}
        for assoc in associations
        if assoc.driver and assoc.driver.user_account
    ]

    # Apply exact username filter (case-insensitive)
    if search_query:
        driver_data = [
            d for d in driver_data
            if getattr(d["user"], "USERNAME", "").lower() == search_query.lower()
        ]

    # Apply active/inactive filter directly on User objects
    if status_filter == "active":
        driver_data = [
            d for d in driver_data
            if getattr(d["user"], "IS_ACTIVE", 0) == 1
        ]
    elif status_filter == "inactive":
        driver_data = [
            d for d in driver_data
            if getattr(d["user"], "IS_ACTIVE", 1) == 0
        ]

    if sort_by == 'points_desc':
        driver_data = sorted(driver_data, key=lambda d: d['points'], reverse=True)
    elif sort_by == 'points_asc':
        driver_data = sorted(driver_data, key=lambda d: d['points'])
    elif sort_by == 'username_desc': 
        driver_data = sorted(driver_data, key=lambda d: d['user'].USERNAME.lower(), reverse=True)
    else: 
        driver_data = sorted(driver_data, key=lambda d: d['user'].USERNAME.lower())

    # Calculate total and average points
    total_points = sum(d["points"] for d in driver_data)
    avg_points = round(total_points / len(driver_data), 2) if driver_data else 0
    points_given_this_week = get_points_given_this_week(current_user.USER_CODE)

    return render_template('sponsor/points.html', drivers=driver_data, total_points=total_points, avg_points=avg_points, points_given_this_week=points_given_this_week, current_sort=sort_by, search_query=search_query, status_filter=status_filter)


@sponsor_bp.route('/points/<int:driver_id>', methods=['POST'])
@role_required(Role.SPONSOR, allow_admin=True)
def manage_points(driver_id):
    """
    Allows sponsors to award or remove points from a driver.
    The form must include:
      - 'action' = 'award' or 'remove'
      - 'points' = integer value
      - optional 'reason' (for removals)
    """
    driver = User.query.get_or_404(driver_id)
    action = request.form.get('action')
    points = request.form.get('points', type=int)
    reason = request.form.get('reason', '').strip() or "No reason provided."
    

    # Validate
    if not action or action not in ("award", "remove") or points is None or points <= 0:
        flash("Invalid request. Please provide an action (award/remove) and valid point amount.", "danger")
        return redirect(url_for('sponsor_bp.manage_points_page'))

    # Get the sponsor record to access ORG_ID
    sponsor = Sponsor.query.filter_by(USER_CODE=current_user.USER_CODE).first()
    if not sponsor:
        flash("Sponsor record not found.", "danger")
        return redirect(url_for('sponsor_bp.manage_points_page'))
        
    association = DriverSponsorAssociation.query.filter_by(
        driver_id=driver_id, ORG_ID=sponsor.ORG_ID
    ).first()

    if not association:
        flash("Driver is not associated with your organization.", "danger")
        return redirect(url_for('sponsor_bp.manage_points_page'))

    if action == "award":
        association.points += points
        db.session.commit()

        log_audit_event(
            DRIVER_POINTS,
            f"Sponsor {current_user.USERNAME} awarded {points} points to {driver.USERNAME}."
        )
        
        log_points_debit(
            order_id=None,
            driver_user_id=driver.USER_CODE,
            sponsor_user_id=current_user.USER_CODE,
            points=points
        )

        if getattr(driver, "wants_point_notifications", False):
            Notification.create_notification(
                recipient_code=driver.USER_CODE,
                sender_code=current_user.USER_CODE,
                message=f"You have been awarded {points} points by {current_user.USERNAME}."
            )

        flash(f"✅ Successfully awarded {points} points to {driver.USERNAME}.", "success")

    elif action == "remove":
        if association.points < points:
            flash(f"Cannot remove {points} points. Driver only has {association.points} points.", "danger")
            
            # Need to return the redirect with the filter/sort state
            search = request.form.get('search_query', '')
            status = request.form.get('status_filter', '')
            sort = request.form.get('current_sort', 'username_asc')
            return redirect(url_for('sponsor_bp.manage_points_page', search=search, status=status, sort=sort))
        
        association.points -= points
        db.session.commit()

        log_audit_event(
            DRIVER_POINTS,
            f"Sponsor {current_user.USERNAME} removed {points} points from {driver.USERNAME}. Reason: {reason}"
        )

        if getattr(driver, "wants_point_notifications", False):
            Notification.create_notification(
                recipient_code=driver.USER_CODE,
                sender_code=current_user.USER_CODE,
                message=f"{points} points were removed from your account by {current_user.USERNAME}. Reason: {reason}"
            )

        flash(f"⚠️ Removed {points} points from {driver.USERNAME}.", "info")

    search = request.form.get('search_query', '')
    status = request.form.get('status_filter', '')
    sort = request.form.get('current_sort', 'username_asc')

    return redirect(url_for('sponsor_bp.manage_points_page', search=search, status=status, sort=sort))



# Add a New Driver
@sponsor_bp.route('/add_user', methods=['GET', 'POST'])
@role_required(Role.SPONSOR, allow_admin=True)
def add_user():
    if request.method == 'POST':
        name = request.form.get('name')
        username = request.form.get('username')
        email = request.form.get('email')

        existing_user = User.query.filter(
            (User.USERNAME == username) | (User.EMAIL == email)
        ).first()
        if existing_user:
            flash(f"Username or email already exists.", "danger")
            return redirect(url_for('sponsor_bp.add_user'))

        # Find the highest existing USER_CODE and increment it
        last_user = User.query.order_by(User.USER_CODE.desc()).first()
        if last_user:
            new_user_code = last_user.USER_CODE + 1
        else:
            # Starting code for the first user if the table is empty
            new_user_code = 1

        new_driver_user = User(
            USER_CODE=new_user_code,
            USERNAME=username,
            EMAIL=email,
            USER_TYPE=Role.DRIVER,
            FNAME="New",
            LNAME="Driver",
            CREATED_AT=datetime.utcnow(),
            IS_ACTIVE=1,
            IS_LOCKED_OUT=0
        )
        new_pass = new_driver_user.set_password()
        
        db.session.add(new_driver_user)
        db.session.commit()
        
        # Create a driver instance
        new_driver = Driver(DRIVER_ID=new_driver_user.USER_CODE, LICENSE_NUMBER="000000") # Placeholder
        db.session.add(new_driver)
        
        # Associate driver with sponsor's organization
        sponsor = Sponsor.query.filter_by(USER_CODE=current_user.USER_CODE).first()
        if sponsor:
            association = DriverSponsorAssociation(
                driver_id=new_driver_user.USER_CODE,
                ORG_ID=sponsor.ORG_ID,
                points=0
            )
        else:
            flash("Sponsor record not found.", "danger")
            return redirect(url_for('sponsor_bp.dashboard'))
        db.session.add(association)
        db.session.commit()


        flash(f"Driver '{username}' has been created and associated with your organization! Temporary Password: {new_pass}", "success")
        return redirect(url_for('sponsor_bp.dashboard'))

    # Show the form to add a new driver
    return render_template('sponsor/add_user.html')

def get_accepted_drivers_for_sponsor(org_id):
    """
    Retrieves all drivers who have an 'Accepted' application status 
    with the given organization ID using a two-step query for stability.
    """
    # Step 1: Filter the DriverApplication table for accepted apps for this organization
    accepted_apps = DriverApplication.query.filter(
        DriverApplication.ORG_ID == org_id,
        DriverApplication.STATUS == "Accepted" 
    ).all()

    # If no accepted applications, return an empty list immediately
    if not accepted_apps:
        return []

    # Step 2: Get the list of DRIVER_ID codes from the accepted applications
    driver_codes = [app.DRIVER_ID for app in accepted_apps]

    # Step 3: Filter the User table to get the full driver objects
    drivers = User.query.filter(User.USER_CODE.in_(driver_codes)).all()

    return drivers

@sponsor_bp.route('/drivers', methods=['GET'])
@role_required(Role.SPONSOR, allow_admin=True)
def driver_management():
    # Get the sponsor record to access ORG_ID
    sponsor = Sponsor.query.filter_by(USER_CODE=current_user.USER_CODE).first()
    if not sponsor:
        flash("Sponsor record not found.", "danger")
        return redirect(url_for('sponsor_bp.dashboard'))
    
    sort_by = request.args.get('sort', 'username_asc')
    search_query = request.args.get("search", "").strip()
    
    # Get all accepted driver IDs for this sponsor's organization (This was already in your function)
    accepted_drivers = get_accepted_drivers_for_sponsor(sponsor.ORG_ID)

    if not accepted_drivers:
        print("⚠️ No accepted drivers found.")
        return render_template('sponsor/my_organization_drivers.html', 
                               drivers_with_points=[], 
                               current_sort=sort_by, 
                               search_query=search_query)

    points_associations = DriverSponsorAssociation.query.filter_by(ORG_ID=sponsor.ORG_ID).all()
    points_map = {assoc.driver_id: assoc.points for assoc in points_associations}

    print(f"Points map: {points_map}")

    driver_data = [
        {
            "user": driver,
            "points": points_map.get(driver.USER_CODE, 0) # Get points from map, default to 0
        }
        for driver in accepted_drivers
    ]


    if search_query:
        driver_data = [
            d for d in driver_data
            if getattr(d["user"], "USERNAME", "").lower() == search_query.lower()
        ]

    print("Driver data being sent to template:")
    for d in driver_data:
        print(f"  {d['user'].USERNAME} -> {d['points']} points")

    if sort_by == 'points_desc':
        driver_data.sort(key=lambda d: d['points'], reverse=True)
    elif sort_by == 'points_asc':
        driver_data.sort(key=lambda d: d['points'])
    elif sort_by == 'username_desc': 
        driver_data.sort(key=lambda d: d['user'].USERNAME.lower(), reverse=True)
    else: 
        driver_data.sort(key=lambda d: d['user'].USERNAME.lower())

    print(f"✅ Final sorted driver list ({sort_by}): {[d['user'].USERNAME for d in driver_data]}")
    print("===========================================\n")

    return render_template('sponsor/my_organization_drivers.html', 
                           drivers_with_points=driver_data, 
                           current_sort=sort_by, 
                           search_query=search_query)
    
@sponsor_bp.get("/organization/reports")
@login_required
@role_required(Role.SPONSOR, allow_admin=True)
def organization_reports_menu():
    return render_template("sponsor/organization_reports.html")

@sponsor_bp.get("/organization/reports/dropped_drivers")
@login_required
@role_required(Role.SPONSOR, allow_admin=True)
def dropped_drivers_report():
    sponsor = Sponsor.query.filter_by(USER_CODE=current_user.USER_CODE).first()
    if not sponsor:
        flash("Sponsor record not found.", "danger")
        return redirect(url_for("sponsor_bp.dashboard"))

    org_id = sponsor.ORG_ID

    # Pull audit logs where EVENT_TYPE = DRIVER_DROPPED and org matches this sponsor's org
    rows = (
        AuditLog.query
        .filter(AuditLog.EVENT_TYPE == DRIVER_DROPPED)
        .filter(AuditLog.DETAILS.ilike(f"%org={org_id}%"))
        .order_by(AuditLog.CREATED_AT.desc())
        .all()
    )

    # Parse out driver / sponsor ids and join to User for nice display
    parsed = []
    for row in rows:
        parts = {}
        for token in (row.DETAILS or "").split():
            if "=" in token:
                k, v = token.split("=", 1)
                parts[k] = v

        driver_user = None
        sponsor_user = None
        try:
            driver_id = int(parts.get("driver", "0"))
            sponsor_id = int(parts.get("sponsor", "0"))
        except ValueError:
            driver_id = sponsor_id = 0

        if driver_id:
            driver_user = User.query.get(driver_id)
        if sponsor_id:
            sponsor_user = User.query.get(sponsor_id)

        parsed.append({
            "log": row,
            "driver": driver_user,
            "sponsor": sponsor_user,
            "org_id": org_id,
        })

    return render_template(
        "sponsor/report_dropped_drivers.html",
        rows=parsed,
        org_id=org_id,
    )

@sponsor_bp.route("/reports/weekly_points", methods=["GET"])
@login_required
@role_required(Role.SPONSOR, allow_admin=True)
def weekly_points_report():
    sponsor_id = current_user.USER_CODE
    one_week_ago = datetime.utcnow() - timedelta(days=7)
    
    logs = (
        AuditLog.query.filter(
            AuditLog.EVENT_TYPE == DRIVER_POINTS,
            AuditLog.CREATED_AT >= one_week_ago,
            AuditLog.DETAILS.ilike(f"%sponsor={sponsor_id}%")
        ).order_by(AuditLog.CREATED_AT.desc()).all()
    )
    total = 0
    parsed_logs = []
    
    for log in logs:
        parts = log.DETAILS.split()
        pts = 0
        driver_id = None
        
        for p in parts:
            if p.startswith("points_debited="):
                pts = int(p.split("=")[1])
            if p.startswith("driver_user_id="):
                driver_id = int(p.split("=")[1])
        
        total += pts
        parsed_logs.append({
            "date": log.CREATED_AT,
            "driver_id": driver_id,
            "points": pts
        })
    return render_template(
        "sponsor/weekly_points_report.html",
        logs=parsed_logs,
        total_points=total
    )

# POST /sponsor/drivers/<driver_id>/drop
@sponsor_bp.route("/drivers/<int:driver_id>/drop", methods=["POST"], endpoint="drop_driver")
@login_required
@role_required(Role.SPONSOR, allow_admin=True)
def drop_driver(driver_id: int):
    sponsor = Sponsor.query.filter_by(USER_CODE=current_user.USER_CODE).first()
    if not sponsor:
        flash("Sponsor record not found.", "danger")
        return redirect(url_for("sponsor_bp.driver_management"))

    driver_user = User.query.get(driver_id)
    if not driver_user or driver_user.USER_TYPE != Role.DRIVER:
        flash("Driver not found.", "danger")
        return redirect(url_for("sponsor_bp.driver_management"))

    # IMPORTANT: use ORG_ID here (matches your schema)
    app = DriverApplication.query.filter_by(
        DRIVER_ID=driver_id,           # DRIVER_ID matches USERS.USER_CODE in your schema
        ORG_ID=sponsor.ORG_ID,
        STATUS="Accepted"
    ).first()
    
    if app and app.STATUS == "Accepted":
        app.STATUS = "Dropped"
        if hasattr(app, 'UPDATED_AT'):
            app.UPDATED_AT = datetime.utcnow()
    
     # IMPORTANT: use ORG_ID here (matches your schema)
    assoc = DriverSponsorAssociation.query.filter_by(
        driver_id=driver_id,
        ORG_ID=sponsor.ORG_ID
    ).first()


    if not app and not assoc:
        flash("That driver is not currently in your organization.", "warning")
        return redirect(url_for("sponsor_bp.driver_management"))

     # 5) Mark the application as no longer accepted (you can use 'Rejected' or 'Dropped')
    if app:
        app.STATUS = "Rejected"  # or "Dropped" if you add that to the Enum

    # 6) Delete the association row so points link is gone
    if assoc:
        db.session.delete(assoc)
        
    db.session.commit()

    # notify driver (non-blocking if you like)
    try:
        Notification.create_notification(
            recipient_code=driver_user.USER_CODE,
            sender_code=current_user.USER_CODE,
            message=(
            f"You have been removed from the organization "
            f"{sponsor.organization.ORG_NAME} by {current_user.USERNAME}."
            )
        )
    except Exception as e:
        log_driver_dropped("DROP_DRIVER_NOTIFY_FAIL",
                        f"driver={driver_user.USERNAME} err={e}")

    log_driver_dropped(
    sponsor_id=current_user.USER_CODE,
    org_id=sponsor.ORG_ID,
    driver_id=driver_id,
)

    flash(f"Driver '{driver_user.USERNAME}' has been removed from your organization.", "info")
    return redirect(url_for("sponsor_bp.driver_management"))

# Sponsor Review Applications
@sponsor_bp.route("/applications")
@login_required
def review_driver_applications():
    # Get the sponsor record to access ORG_ID
    sponsor = Sponsor.query.filter_by(USER_CODE=current_user.USER_CODE).first()
    if not sponsor:
        flash("Sponsor record not found.", "danger")
        return redirect(url_for('sponsor_bp.dashboard'))
    
    apps = DriverApplication.query.filter_by(ORG_ID=sponsor.ORG_ID, STATUS="Pending").all()
    return render_template("sponsor/review_driver_applications.html", applications=apps)

@sponsor_bp.route("/applications/<int:app_id>/<decision>", methods=['POST']) # <-- ADD THIS
@login_required
def driver_decision(app_id, decision):
    app = DriverApplication.query.get_or_404(app_id)
    # Note: app.sponsor relationship may not exist anymore, check organization instead
    sponsor = Sponsor.query.filter_by(USER_CODE=current_user.USER_CODE).first()
    if not sponsor or app.ORG_ID != sponsor.ORG_ID:
        flash("You do not have permission to modify this application.", "danger")
        return redirect(url_for("sponsor_bp.review_driver_applications"))

    if decision == "accept":
        app.STATUS = "Accepted"
        # Associate driver with organization if not already associated
        association = DriverSponsorAssociation.query.filter_by(
            driver_id=app.DRIVER_ID,
            ORG_ID=app.ORG_ID
        ).first()
        if not association:
            association = DriverSponsorAssociation(
                driver_id=app.DRIVER_ID,
                ORG_ID=app.ORG_ID,
                points=0
            )
            db.session.add(association)
    else:
        app.STATUS = "Rejected"

    app.RESPONDED_AT = datetime.utcnow()
    app.SPONSOR_RESPONSIBLE_ID = current_user.USER_CODE

    db.session.commit()

    # Send notification to the driver
    try:
        driver_user = User.query.get(app.DRIVER_ID)
        if driver_user:
            organization_name = sponsor.organization.ORG_NAME if sponsor.organization else "Your Sponsor Organization"
            
            message = (
                f"Your application to join **{organization_name}** has been "
                f"**{app.STATUS.upper()}** by {current_user.USERNAME}."
            )
            
            Notification.create_notification(
                recipient_code=driver_user.USER_CODE,
                sender_code=current_user.USER_CODE,
                message=message
            )
            
    except Exception as e:
        # Log the error, but don't stop the route from committing
        print(f"Error sending notification for application {app_id}: {e}")

    flash(f"Driver application has been {decision}ed!", "success")
    return redirect(url_for("sponsor_bp.review_driver_applications"))

# Update Contact Information
@sponsor_bp.route('/update_info', methods=['GET', 'POST'])
@role_required(Role.DRIVER, Role.SPONSOR, allow_admin=True, redirect_to='auth.login')
def update_info():
    from extensions import db

    sponsor = None
    if current_user.USER_TYPE == "sponsor":
        sponsor = Sponsor.query.get(current_user.USER_CODE)

    if request.method == 'POST':
        email = request.form.get('email').strip()
        phone = request.form.get('phone').strip()

        # Basic email validation
        if not email or '@' not in email:
            flash('Please enter a valid email address.', 'danger')
            return redirect(url_for('sponsor_bp.update_info'))

        # Check if email already exists for another user
        if User.query.filter(User.EMAIL == email, User.USER_CODE != current_user.USER_CODE).first():
            flash('Email already in use.', 'danger')
            return redirect(url_for('sponsor_bp.update_info'))

        # Basic phone validation (optional)
        if phone and (not phone.isdigit() or len(phone) < 10):
            flash('Please enter a valid phone number.', 'danger')
            return redirect(url_for('sponsor_bp.update_info'))
        
        # Check if phone already exists for another user
        if phone and User.query.filter(User.PHONE == phone, User.USER_CODE != current_user.USER_CODE).first():
            flash('Phone number already in use.', 'danger')
            return redirect(url_for('sponsor_bp.update_info'))
        
        try:
            current_user.EMAIL = email
            current_user.PHONE = phone

            db.session.commit()
            flash('Contact information updated successfully!', 'success')
            return redirect(url_for('sponsor_bp.dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while updating your information', 'danger')
            return redirect(url_for('sponsor_bp.update_info'))

    return render_template('sponsor/update_info.html', user=current_user, sponsor=sponsor)

# Reset Driver Password
@sponsor_bp.route('/reset_driver_password/<int:driver_id>', methods=['POST'])
@role_required(Role.SPONSOR, allow_admin=True)
def reset_driver_password(driver_id):
    """Reset a driver's password to a temporary password"""
    # Get the sponsor record to verify organization
    sponsor = Sponsor.query.filter_by(USER_CODE=current_user.USER_CODE).first()
    if not sponsor:
        flash("Sponsor record not found.", "danger")
        return redirect(url_for('sponsor_bp.driver_management'))
    
    # Get the driver
    driver = User.query.get_or_404(driver_id)
    
    # Verify the driver belongs to this sponsor's organization
    driver_app = DriverApplication.query.filter_by(
        DRIVER_ID=driver.USER_CODE, 
        ORG_ID=sponsor.ORG_ID, 
        STATUS="Accepted"
    ).first()
    
    if not driver_app:
        flash("You can only reset passwords for drivers in your organization.", "danger")
        return redirect(url_for('sponsor_bp.driver_management'))
    
    try:
        # Generate a new temporary password using the User model's method
        temp_password = driver.admin_set_new_pass()
        
        db.session.commit()
        
        # Log the event
        log_audit_event(
            "PASSWORD_RESET_BY_SPONSOR",
            f"Sponsor {current_user.USERNAME} reset password for driver {driver.USERNAME}"
        )
        
        # Send notification to driver if they want security notifications
        if getattr(driver, "wants_security_notifications", True):
            Notification.create_notification(
                recipient_code=driver.USER_CODE,
                sender_code=current_user.USER_CODE,
                message=f"Your password has been reset by {current_user.USERNAME}. Please log in with your new temporary password and change it immediately."
            )
        
        flash(f"✅ Password reset successfully for {driver.USERNAME}. Temporary password: {temp_password}", "success")
        
    except Exception as e:
        db.session.rollback()
        print(f"Error resetting password: {str(e)}")  # For debugging
        flash(f"An error occurred while resetting the password: {str(e)}", "danger")
    
    return redirect(url_for('sponsor_bp.driver_management'))

# Update Password
@sponsor_bp.route('/change_password', methods=['GET', 'POST'])
@role_required(Role.DRIVER, Role.SPONSOR, allow_admin=True, redirect_to='auth.login')
def change_password():
    

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Verify current password
        if not bcrypt.check_password_hash(current_user.PASS, current_password):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('sponsor_bp.change_password'))

        # Validate new password
        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('sponsor_bp.change_password'))

        if len(new_password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return redirect(url_for('sponsor_bp.change_password'))

        # Update password and email
        try:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            current_user.PASS = hashed_password
            db.session.commit()
            flash('Information updated successfully!', 'success')
            return redirect(url_for('sponsor_bp.dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while updating your information', 'danger')
            return redirect(url_for('sponsor_bp.change_password'))

    return render_template('sponsor/update_info.html', user=current_user)

# View My Store (for Sponsors)
@sponsor_bp.route('/my_store')
@role_required(Role.SPONSOR, allow_admin=True)
def view_my_store():
    """Renders the truck rewards store for the currently logged-in sponsor."""
    # Get the sponsor record to access ORG_ID
    sponsor = Sponsor.query.filter_by(USER_CODE=current_user.USER_CODE).first()
    if not sponsor:
        flash("Sponsor record not found.", "danger")
        return redirect(url_for('sponsor_bp.dashboard'))
    
    # The template needs the sponsor's organization ID to fetch the correct products
    return render_template('driver/truck_rewards_store.html', 
                         USER_CODE=current_user.USER_CODE,
                         sponsor_id=sponsor.ORG_ID,
                         ORG_ID=sponsor.ORG_ID,
                         org_id=sponsor.ORG_ID)

@sponsor_bp.route('/point_requests')
@login_required
@role_required(Role.SPONSOR)
def list_point_requests():
    sponsor = Sponsor.query.filter_by(USER_CODE=current_user.USER_CODE).first()
    if not sponsor or not sponsor.ORG_ID:
        flash("Organization not found.", "danger")
        return redirect(url_for('sponsor_bp.dashboard'))

    # Fetch pending requests for this sponsor's organization
    requests = PointRequest.query.filter_by(
        ORG_ID=sponsor.ORG_ID, 
        STATUS='Pending'
    ).order_by(PointRequest.CREATED_AT.desc()).all()

    return render_template('sponsor/point_requests.html', requests=requests)

@sponsor_bp.route('/point_requests/<int:req_id>/<action>', methods=['POST'])
@login_required
@role_required(Role.SPONSOR)
def handle_point_request(req_id, action):
    # Verify request exists
    req = PointRequest.query.get_or_404(req_id)
    
    # Verify sponsor owns this request (via Organization)
    sponsor = Sponsor.query.filter_by(USER_CODE=current_user.USER_CODE).first()
    if not sponsor or req.ORG_ID != sponsor.ORG_ID:
        flash("Permission denied.", "danger")
        return redirect(url_for('sponsor_bp.list_point_requests'))

    if action == 'approve':
        req.STATUS = 'Approved'
        
        # Find the association and add points
        assoc = DriverSponsorAssociation.query.filter_by(
            driver_id=req.DRIVER_ID, 
            ORG_ID=req.ORG_ID
        ).first()
        
        if assoc:
            assoc.points += req.POINTS
            
            # Log the event
            log_audit_event(
                DRIVER_POINTS,
                f"Sponsor {current_user.USERNAME} approved request: Awarded {req.POINTS} points to driver {req.driver.user_account.USERNAME}. Reason: {req.REASON}"
            )
            
            # Create notification
            Notification.create_notification(
                recipient_code=req.DRIVER_ID,
                sender_code=current_user.USER_CODE,
                message=f"Your request for {req.POINTS} points was APPROVED. Reason: {req.REASON}"
            )
            flash(f"Request approved. {req.POINTS} points added to driver.", "success")
        else:
            flash("Error: Driver is no longer associated with this organization.", "danger")

    elif action == 'reject':
        req.STATUS = 'Rejected'
        
        # Log
        log_audit_event(
            DRIVER_POINTS,
            f"Sponsor {current_user.USERNAME} REJECTED point request from {req.driver.user_account.USERNAME}."
        )
        
        # Notify
        Notification.create_notification(
            recipient_code=req.DRIVER_ID,
            sender_code=current_user.USER_CODE,
            message=f"Your request for {req.POINTS} points was REJECTED."
        )
        flash("Request rejected.", "warning")

    db.session.commit()
    return redirect(url_for('sponsor_bp.list_point_requests'))

@sponsor_bp.route("/application_history")
@login_required
@role_required(Role.SPONSOR, allow_admin=True)
def organization_app_history():
    """
    Sponsor view of all applications (Pending, Accepted, Rejected) for their organization.
    """
    sponsor = Sponsor.query.filter_by(USER_CODE=current_user.USER_CODE).first()
    if not sponsor:
        flash("Sponsor organization record not found.", "danger")
        return redirect(url_for('sponsor_bp.dashboard'))
    
    # Query all applications for THIS organization (ORG_ID), joining to show the decision-maker
    applications = DriverApplication.query.filter_by(
        ORG_ID=sponsor.ORG_ID
    ).outerjoin(
        DriverApplication.sponsor_responsible
    ).order_by(
        DriverApplication.RESPONDED_AT.desc(),
        DriverApplication.APPLIED_AT.desc()
    ).all()
    
    return render_template(
        "sponsor/application_history.html", 
        applications=applications,
        organization_name=sponsor.organization.ORG_NAME if sponsor.organization else "Your Organization"
    )
    
def get_points_given_this_week(sponsor_id):
    today = datetime.utcnow()
    start_of_week = today - timedelta(days=today.weekday())  # Monday
    logs = WeeklyPointsLog.query.filter(
        WeeklyPointsLog.SPONSOR_ID == sponsor_id,
        WeeklyPointsLog.CREATED_AT >= start_of_week
    ).all()
    total_points = sum(log.POINTS for log in logs)
    return total_points