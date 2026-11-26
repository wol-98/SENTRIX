"""Sensor health transition recording for SENTRIX."""

from datetime import datetime, timedelta
import math

from flask import current_app

from app.extensions import db
from app.models import SensorHealthHistory


STATUS_THRESHOLDS = {
    "LIVE": 0,
    "STALE": 10,
    "OFFLINE": 60,
}


def record_sensor_health_transition(
    status,
    age_seconds=None,
    last_seen_epoch=None,
    sensor_key="default",
):
    """Persist a health transition only when status changes."""

    status = status.upper()

    if status not in STATUS_THRESHOLDS:
        raise ValueError(f"Unsupported sensor status: {status}")

    latest = (
        SensorHealthHistory.query
        .filter_by(sensor_key=sensor_key)
        .order_by(
            SensorHealthHistory.recorded_at.desc(),
            SensorHealthHistory.id.desc(),
        )
        .first()
    )

    # Do not create duplicate history rows during monitoring polls.
    if latest and latest.status == status:
        return None

    recorded_at = datetime.now()

    last_seen_at = None
    if (
        isinstance(last_seen_epoch, (int, float))
        and not isinstance(last_seen_epoch, bool)
        and math.isfinite(last_seen_epoch)
    ):
        last_seen_at = datetime.fromtimestamp(last_seen_epoch)

    # Estimate when the status became effective using the existing
    # LIVE (10s) and OFFLINE (60s) thresholds.
    if last_seen_at is not None:
        changed_at = last_seen_at + timedelta(
            seconds=STATUS_THRESHOLDS[status]
        )
    else:
        # No previous telemetry means the true outage start is unknown.
        changed_at = recorded_at

    history = SensorHealthHistory(
        sensor_key=sensor_key,
        status=status,
        changed_at=changed_at,
        recorded_at=recorded_at,
        last_seen_at=last_seen_at,
        age_seconds=(
            float(age_seconds)
            if isinstance(age_seconds, (int, float))
            and not isinstance(age_seconds, bool)
            and math.isfinite(age_seconds)
            else None
        ),
    )

    try:
        db.session.add(history)
        db.session.commit()
        return history

    except Exception:
        db.session.rollback()
        current_app.logger.exception(
            "Failed to record sensor health transition."
        )
        return None
