from datetime import datetime
import os
from flask import Flask, redirect, render_template, request, url_for, flash, session, g
from dotenv import load_dotenv
from flask_apscheduler import APScheduler
from flask_login import current_user, logout_user
from extensions import db, migrate, login_manager, csrf
from config import Config
from models import User
from flask_wtf import CSRFProtect
from forms import AboutForm
from extensions import bcrypt, migrate, login_manager, csrf, bcrypt, db, mail, moment
from auth.routes import auth_bp

# Initialize scheduler
scheduler = APScheduler()

def create_app():
    # Load environment variables from .env file
    load_dotenv()


    # Initialize Flask app
    app = Flask(__name__)
    mail.init_app(app)
    moment.init_app(app)
    app.config.from_object("config.Config")
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")
    app.config["WTF_CSRF_TIME_LIMIT"] = None  # optional

    
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'
    csrf.init_app(app)
    bcrypt.init_app(app)
    
    @app.errorhandler(403)
    def forbidden(e):
        return render_template('common/403.html'), 403

    # Register blueprints
    from driver.routes import driver_bp
    from administrator.routes import administrator_bp
    from sponsor.routes import sponsor_bp
    from truck_rewards.routes import rewards_bp
    from common.routes import common_bp
    from about.routes import about_bp
    from about.routes import update_version
    from notifications.routes import notification_bp
    from bulk_loading.routes import bulk_loading_bp
    from impersonation.routes import impersonation_bp

    app.register_blueprint(about_bp, url_prefix='/about')
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(driver_bp, url_prefix='/driver')
    app.register_blueprint(administrator_bp, url_prefix='/administrator')
    app.register_blueprint(sponsor_bp, url_prefix='/sponsor')
    app.register_blueprint(rewards_bp, url_prefix='/truck-rewards')
    app.register_blueprint(common_bp)
    app.register_blueprint(notification_bp, url_prefix='/notifications')
    app.register_blueprint(bulk_loading_bp)
    app.register_blueprint(impersonation_bp, url_prefix='/impersonation')


    # Schedule the version update job to run weekly
    # Check version on startup
    with app.app_context():
        update_version()
    
    # Configure scheduler to check periodically
    scheduler.add_job(
        id='check_version',
        func=update_version,
        trigger='interval',
        hours=24  # Check once per day
    )

    mail.init_app(app)
    
    return app

@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))

@login_manager.unauthorized_handler
def unauth():
    return redirect(url_for("auth.login"))

app = create_app()

@app.before_request
def enforce_admin_lockouts():
    if request.endpoint and request.endpoint.startswith("static"):
        return
    if current_user.is_authenticated and current_user.is_account_locked():
        logout_user()
        return redirect(url_for("auth.login"))

@app.before_request
def load_impersonation_state():
    """Expose impersonation info to all templates."""
    g.is_impersonating = bool(session.get('impersonating'))
    g.impersonator = None

    if g.is_impersonating and session.get('original_user_code'):
        impersonator_code = session.get('original_user_code')
        g.impersonator = User.query.filter_by(USER_CODE=impersonator_code).first()

if __name__ == '__main__':
    app.run(debug=True)