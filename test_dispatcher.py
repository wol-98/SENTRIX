
"""Tests for SENTRIX notification dispatcher."""

import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

from app import create_app
from app.extensions import db
from app.models import Alert, NotificationDelivery
from config import Config


class DispatcherTestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


app = create_app(DispatcherTestConfig)


class DispatcherTests(unittest.TestCase):
    def setUp(self):
        self.app_context = app.app_context()
        self.app_context.push()
        db.create_all()
        self.now = datetime(2026, 11, 26, 10, 0, 0)

        self.alert = Alert(
            source_type="sensor",
            source_key="sensor-01",
            event_type="FIRE DETECTED",
            severity="CRITICAL",
            title="Fire detected",
            message="Gas level exceeded threshold.",
            created_at=self.now,
        )
        db.session.add(self.alert)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    @patch("app.services.dispatcher.send_sms_delivery")
    def test_successful_sms_is_recorded(self, mock_send):
        mock_send.return_value = {
            "success": True,
            "provider_message_id": "SM-test-123",
            "error": None,
        }

        from app.services.dispatcher import dispatch_alert

        delivery = dispatch_alert(self.alert.id, now=self.now)

        self.assertEqual(delivery.status, "SENT")
        self.assertEqual(
            delivery.provider_message_id,
            "SM-test-123",
        )
        self.assertIsNotNone(delivery.delivered_at)
        self.assertEqual(NotificationDelivery.query.count(), 1)
        mock_send.assert_called_once()

    @patch("app.services.dispatcher.send_sms_delivery")
    def test_failed_sms_is_recorded(self, mock_send):
        mock_send.return_value = {
            "success": False,
            "provider_message_id": None,
            "error": "SMS provider is not configured.",
        }

        from app.services.dispatcher import dispatch_alert

        delivery = dispatch_alert(self.alert.id, now=self.now)

        self.assertEqual(delivery.status, "FAILED")
        self.assertIn("not configured", delivery.error_message)
        self.assertIsNone(delivery.delivered_at)

    @patch("app.services.dispatcher.send_sms_delivery")
    def test_successful_delivery_is_not_sent_twice(self, mock_send):
        mock_send.return_value = {
            "success": True,
            "provider_message_id": "SM-test-456",
            "error": None,
        }

        from app.services.dispatcher import dispatch_alert

        first = dispatch_alert(self.alert.id, now=self.now)
        second = dispatch_alert(
            self.alert.id,
            now=self.now + timedelta(seconds=10),
        )

        self.assertEqual(first.id, second.id)
        self.assertEqual(NotificationDelivery.query.count(), 1)
        mock_send.assert_called_once()

    @patch("app.services.dispatcher.send_sms_delivery")
    def test_failed_delivery_can_be_retried(self, mock_send):
        mock_send.side_effect = [
            {
                "success": False,
                "provider_message_id": None,
                "error": "Temporary provider error.",
            },
            {
                "success": True,
                "provider_message_id": "SM-retry-789",
                "error": None,
            },
        ]

        from app.services.dispatcher import dispatch_alert

        first = dispatch_alert(self.alert.id, now=self.now)
        second = dispatch_alert(
            self.alert.id,
            now=self.now + timedelta(seconds=30),
        )

        self.assertEqual(first.status, "FAILED")
        self.assertEqual(second.status, "SENT")
        self.assertEqual(second.attempt_number, 2)
        self.assertEqual(NotificationDelivery.query.count(), 2)
        self.assertEqual(mock_send.call_count, 2)

    @patch("app.services.dispatcher.send_sms_delivery")
    def test_missing_alert_does_not_send(self, mock_send):
        from app.services.dispatcher import dispatch_alert

        delivery = dispatch_alert(999999, now=self.now)

        self.assertIsNone(delivery)
        mock_send.assert_not_called()

    @patch("app.services.dispatcher.send_sms_delivery")
    def test_unsupported_channel_does_not_send(self, mock_send):
        from app.services.dispatcher import dispatch_alert

        delivery = dispatch_alert(
            self.alert.id,
            channel="EMAIL",
            now=self.now,
        )

        self.assertIsNone(delivery)
        mock_send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
