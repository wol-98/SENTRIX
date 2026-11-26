
"""Notification dispatcher for SENTRIX alerts."""

from datetime import datetime

from flask import current_app

from app.extensions import db
from app.models import Alert, NotificationDelivery
from app.services.notifications import send_sms_delivery


def dispatch_alert(alert_id, *, channel="SMS", now=None):
    """Dispatch an alert and persist its notification attempt.

    Returns the NotificationDelivery record, or None if the alert
    does not exist or the channel is unsupported.
    """

    channel = str(channel).upper()

    if channel != "SMS":
        current_app.logger.warning(
            "Unsupported notification channel requested: %s",
            channel,
        )
        return None

    alert = db.session.get(Alert, alert_id)

    if alert is None:
        current_app.logger.warning(
            "Cannot dispatch notification: alert not found."
        )
        return None

    # Do not send again if a previous attempt succeeded.
    previous = (
        NotificationDelivery.query
        .filter_by(alert_id=alert.id, channel=channel)
        .order_by(NotificationDelivery.attempt_number.desc())
        .first()
    )

    if previous and previous.status in {"SENT", "PENDING"}:
        return previous

    attempt_number = (
        previous.attempt_number + 1 if previous else 1
    )

    now = now or datetime.now()

    delivery = NotificationDelivery(
        alert_id=alert.id,
        channel=channel,
        destination_key="configured-sms-recipient",
        status="PENDING",
        attempt_number=attempt_number,
        attempted_at=now,
    )

    # Persist PENDING before making the external provider request.
    db.session.add(delivery)

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception(
            "Could not create notification delivery record."
        )
        return None

    try:
        result = send_sms_delivery(
            f"{alert.title}: {alert.message}"
        )

        if result.get("success"):
            delivery.status = "SENT"
            delivery.provider_message_id = (
                result.get("provider_message_id")
            )
            delivery.error_message = None
            delivery.delivered_at = datetime.now()

        else:
            delivery.status = "FAILED"
            delivery.error_message = (
                result.get("error") or "SMS request failed."
            )[:1000]

    except Exception:
        current_app.logger.exception(
            "Unexpected error while dispatching alert SMS."
        )
        delivery.status = "FAILED"
        delivery.error_message = "Unexpected SMS dispatch error."

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception(
            "Could not update notification delivery status."
        )
        return delivery

    return delivery
