
"""SENTRIX application factory."""

from pathlib import Path

from flask import Flask, render_template

from config import Config
from app.extensions import db, migrate
from app.auth.decorators import login_required


def create_app(config_class=Config):
    project_root = Path(__file__).resolve().parent.parent

    app = Flask(
        __name__,
        instance_path=str(project_root / "instance"),
        template_folder=str(project_root / "templates"),
    )

    app.config.from_object(config_class)

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

    # Register monitoring blueprint.
    from app.monitoring.routes import monitoring_bp
    app.register_blueprint(monitoring_bp)

    # Dashboard route.
    @app.route("/")
    @login_required
    def home():
        return render_template("index.html")

    return app
