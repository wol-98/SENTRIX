"""Persistent sensor health status transitions for SENTRIX."""

from datetime import datetime

from app.extensions import db


class SensorHealthHistory(db.Model):
    """A recorded transition in a sensor's health status."""

    __tablename__ = "sensor_health_history"

    id = db.Column(db.Integer, primary_key=True)

    # Current SENTRIX supports one sensor; this key allows
    # multiple sensors to be added later without redesigning.
    sensor_key = db.Column(
        db.String(80),
        nullable=False,
        default="default",
        index=True,
    )

    status = db.Column(
        db.String(12),
        nullable=False,
    )

    # Estimated time the status became effective.
    changed_at = db.Column(
        db.DateTime,
        nullable=False,
        index=True,
    )

    # Actual time SENTRIX recorded the transition.
    recorded_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.now,
    )

    last_seen_at = db.Column(
        db.DateTime,
        nullable=True,
    )

    age_seconds = db.Column(
        db.Float,
        nullable=True,
    )

    __table_args__ = (
        db.CheckConstraint(
            "status IN ('LIVE', 'STALE', 'OFFLINE')",
            name="ck_sensor_health_status",
        ),
    )
