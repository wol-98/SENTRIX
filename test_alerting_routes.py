"""Tests for SENTRIX alert-rule and notification-history routes."""

import unittest
from datetime import datetime

from app import create_app
from app.extensions import db
from app.models import Alert, AlertRule, NotificationDelivery
from config import Config


class AlertingRoutesTestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


app = create_app(AlertingRoutesTestConfig)


class AlertingRoutesTests(unittest.TestCase):
    def setUp(self):
        self.app_context = app.app_context()
        self.app_context.push()

        db.create_all()
        self.client = app.test_client()

        with self.client.session_transaction() as session:
            session["logged_in"] = True

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def add_rule(self, **overrides):
        values = {
            "rule_key": "TEST-RULE-001",
            "name": "Test alert rule",
            "event_type": "FIRE DETECTED",
            "min_severity": "HIGH",
            "enabled": True,
            "cooldown_seconds": 300,
        }
        values.update(overrides)

        rule = AlertRule(**values)
        db.session.add(rule)
        db.session.commit()
        return rule

    def add_delivery(self, *, status="SENT", channel="SMS"):
        alert = Alert(
            source_type="sensor",
            source_key="sensor-test-01",
            event_type="FIRE DETECTED",
            severity="HIGH",
            title="Test fire alert",
            message="Test alert message",
        )
        db.session.add(alert)
        db.session.flush()

        delivery = NotificationDelivery(
            alert_id=alert.id,
            channel=channel,
            status=status,
            attempt_number=1,
            attempted_at=datetime(2026, 11, 26, 10, 0, 0),
        )
        db.session.add(delivery)
        db.session.commit()

        return alert, delivery

    def test_unauthenticated_rules_request_redirects(self):
        with self.client.session_transaction() as session:
            session.clear()

        response = self.client.get("/api/alerts/rules")

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.location)

    def test_list_alert_rules(self):
        self.add_rule()

        response = self.client.get("/api/alerts/rules")

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(len(data["rules"]), 1)
        self.assertEqual(
            data["rules"][0]["rule_key"],
            "TEST-RULE-001",
        )

    def test_create_alert_rule(self):
        response = self.client.post(
            "/api/alerts/rules",
            json={
                "rule_key": "API-RULE-001",
                "name": "API test rule",
                "event_type": "fire detected",
                "min_severity": "high",
                "enabled": True,
                "cooldown_seconds": 120,
            },
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(AlertRule.query.count(), 1)

        rule = AlertRule.query.first()
        self.assertEqual(rule.event_type, "FIRE DETECTED")
        self.assertEqual(rule.min_severity, "HIGH")

    def test_create_rule_rejects_invalid_severity(self):
        response = self.client.post(
            "/api/alerts/rules",
            json={
                "rule_key": "INVALID-RULE",
                "name": "Invalid severity",
                "event_type": "FIRE DETECTED",
                "min_severity": "URGENT",
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(AlertRule.query.count(), 0)

    def test_create_rule_rejects_duplicate_rule_key(self):
        self.add_rule()

        response = self.client.post(
            "/api/alerts/rules",
            json={
                "rule_key": "TEST-RULE-001",
                "name": "Duplicate rule",
                "event_type": "FIRE DETECTED",
            },
        )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(AlertRule.query.count(), 1)

    def test_patch_rule_disables_rule(self):
        rule = self.add_rule()

        response = self.client.patch(
            f"/api/alerts/rules/{rule.id}",
            json={"enabled": False},
        )

        self.assertEqual(response.status_code, 200)
        db.session.refresh(rule)
        self.assertFalse(rule.enabled)

    def test_patch_rule_updates_cooldown(self):
        rule = self.add_rule()

        response = self.client.patch(
            f"/api/alerts/rules/{rule.id}",
            json={"cooldown_seconds": 600},
        )

        self.assertEqual(response.status_code, 200)
        db.session.refresh(rule)
        self.assertEqual(rule.cooldown_seconds, 600)

    def test_patch_missing_rule_returns_404(self):
        response = self.client.patch(
            "/api/alerts/rules/9999",
            json={"enabled": False},
        )

        self.assertEqual(response.status_code, 404)

    def test_patch_rejects_unknown_field(self):
        rule = self.add_rule()

        response = self.client.patch(
            f"/api/alerts/rules/{rule.id}",
            json={"rule_key": "CHANGED-KEY"},
        )

        self.assertEqual(response.status_code, 400)

    def test_notification_history_returns_delivery(self):
        self.add_delivery()

        response = self.client.get("/api/alerts/history")

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["deliveries"][0]["status"], "SENT")
        self.assertEqual(
            data["deliveries"][0]["alert"]["event_type"],
            "FIRE DETECTED",
        )

    def test_notification_history_filters_failed(self):
        self.add_delivery(status="SENT")
        self.add_delivery(status="FAILED", channel="EMAIL")

        response = self.client.get(
            "/api/alerts/history?status=FAILED"
        )

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["deliveries"][0]["status"], "FAILED")

    def test_notification_history_rejects_invalid_status(self):
        response = self.client.get(
            "/api/alerts/history?status=UNKNOWN"
        )

        self.assertEqual(response.status_code, 400)

    def test_notification_history_rejects_invalid_limit(self):
        response = self.client.get(
            "/api/alerts/history?limit=500"
        )

        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()

