
"""SENTRIX application factory."""

from pathlib import Path

from flask import Flask, render_template

from config import Config
from app.extensions import db, migrate, csrf
from app.auth.decorators import login_required


def create_app(config_class=Config):
    project_root = Path(__file__).resolve().parent.parent

    app = Flask(
        __name__,
        instance_path=str(project_root / "instance"),
        template_folder=str(project_root / "templates"),
    )

    app.config.from_object(config_class)
    config_class.validate(app.config)
    # Protect browser-session forms against CSRF.
    csrf.init_app(app)

    # Initialize extensions.
    db.init_app(app)
    migrate.init_app(app, db)

    # Register database models.
    from app import models  # noqa: F401

    # Register authentication blueprint.
    from app.auth.routes import auth_bp
    app.register_blueprint(auth_bp)

    # Register telemetry blueprint.
    from app.telemetry.routes import telemetry_bp
    app.register_blueprint(telemetry_bp)
    # Telemetry uses API-key authentication, not browser sessions.
    csrf.exempt(telemetry_bp)

    # Register monitoring blueprint.
    from app.monitoring.routes import monitoring_bp
    app.register_blueprint(monitoring_bp)
    from app.analytics.routes import analytics_bp
    app.register_blueprint(analytics_bp)

    # Dashboard route.
    @app.route("/")
    @login_required
    def home():
        return render_template("index.html")

    return app
