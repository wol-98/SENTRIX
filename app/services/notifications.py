
"""Notification services for SENTRIX."""

import time

from flask import current_app
from twilio.rest import Client


# Notification runtime state.
last_alert_sent = "SAFE"
last_sms_time = 0

_sms_client = None
_sms_client_initialized = False


def _get_sms_client():
    """Initialize and return the Twilio client when configured."""

    global _sms_client, _sms_client_initialized

    if _sms_client_initialized:
        return _sms_client

    _sms_client_initialized = True

    sid = current_app.config.get("TWILIO_SID")
    token = current_app.config.get("TWILIO_TOKEN")

    if not sid or not token:
        return None

    try:
        _sms_client = Client(sid, token)

        current_app.logger.info(
            "SENTRIX SMS notification service initialized."
        )

    except Exception:
        current_app.logger.exception(
            "SENTRIX SMS initialization failed."
        )

        _sms_client = None

    return _sms_client


def send_sms_alert(message):
    """Send rate-limited SMS security alerts."""

    global last_alert_sent, last_sms_time

    current_time = time.time()

    # Avoid sending duplicate alerts.
    if message == last_alert_sent:
        return

    # Enforce a 60-second notification interval.
    if current_time - last_sms_time <= 60:
        return

    sms_client = _get_sms_client()

    # SMS notifications are optional.
    if sms_client is None:
        last_alert_sent = message
        return

    recipient = current_app.config.get("TWILIO_TO")
    sender = current_app.config.get("TWILIO_FROM")

    if not recipient or not sender:
        last_alert_sent = message
        return

    try:
        sms_client.messages.create(
            body=f"SENTRIX security alert: {message}",
            from_=sender,
            to=recipient
        )

        current_app.logger.info(
            "SENTRIX SMS alert sent: %s",
            message
        )

        last_alert_sent = message
        last_sms_time = current_time

    except Exception:
        current_app.logger.exception(
            "SENTRIX SMS alert failed."
        )
