from functools import wraps

from flask import redirect, session, url_for


def login_required(view_function):
    """Require an authenticated administrator session."""

    @wraps(view_function)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("auth.login"))

        return view_function(*args, **kwargs)

    return decorated_function
