from flask import (
    Blueprint,
    current_app,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash


auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Authenticate an administrator."""

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        admin_username = current_app.config.get("ADMIN_USERNAME")
        password_hash = current_app.config.get("ADMIN_PASSWORD_HASH")

        password_is_valid = (
            username == admin_username
            and bool(password_hash)
            and bool(password)
            and check_password_hash(password_hash, password)
        )

        if password_is_valid:
            session.clear()
            session["logged_in"] = True
            session.permanent = True

            return redirect(url_for("home"))

        return render_template(
            "login.html",
            error="Access denied. Check your credentials."
        ), 401

    return render_template("login.html")


@auth_bp.route("/logout", methods=["POST"])
def logout():
    """End the administrator session."""

    session.clear()

    return redirect(url_for("auth.login"))
