# common/decorators.py
from functools import wraps
from flask import abort, redirect, url_for, flash
from flask_login import login_required, current_user
from models import Role

def role_required(*allowed_roles, allow_admin=True, redirect_to=None):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            user_role = getattr(current_user, "USER_TYPE", None)  # matches your model field
            if user_role in allowed_roles:
                return view(*args, **kwargs)
            if allow_admin and user_role == Role.ADMINISTRATOR:
                return view(*args, **kwargs)

            if redirect_to:
                flash("You do not have access to this page.", "warning")
                return redirect(url_for(redirect_to))
            abort(403)
        return wrapped
    return decorator

def unauthenticated_only(redirect_to='driver_bp.dashboard'):
    """
    Redirects an authenticated user away from a route (like /login or /signup).
    
    :param redirect_to: The endpoint to redirect the user to if they are logged in.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.is_authenticated:
                flash('You are already logged in.', 'info')
                return redirect(url_for(redirect_to))
            return f(*args, **kwargs)
        return decorated_function
    return decorator