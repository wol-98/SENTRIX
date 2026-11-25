import os
from datetime import timedelta

from dotenv import load_dotenv

load_dotenv()


class Config:
    # Application security
    SECRET_KEY = os.getenv("SECRET_KEY")
    API_SECRET_KEY = os.getenv("API_SECRET_KEY")

    # Administrator authentication
    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
    ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")

    # Database
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL", "sqlite:///sentinel.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Optional SMS notifications
    TWILIO_SID = os.getenv("TWILIO_SID")
    TWILIO_TOKEN = os.getenv("TWILIO_TOKEN")
    TWILIO_FROM = os.getenv("TWILIO_FROM")
    TWILIO_TO = os.getenv("TWILIO_TO")

    # Session security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = (
        os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
    )
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_REFRESH_EACH_REQUEST = True

    # Application runtime
    DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true"

    @classmethod
    def validate(cls):
        required = [
            "SECRET_KEY",
            "API_SECRET_KEY",
            "ADMIN_USERNAME",
            "ADMIN_PASSWORD_HASH",
        ]

        missing = [
            name for name in required
            if not getattr(cls, name)
        ]

        if missing:
            raise RuntimeError(
                "Missing required configuration: "
                + ", ".join(missing)
            )
