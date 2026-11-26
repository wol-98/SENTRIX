"""Tests for SENTRIX alert rule evaluation."""

import unittest
from datetime import datetime, timedelta

from app import create_app
from app.extensions import db
from app.models import Alert, AlertRule, IncidentLog
from app.services.alerting import create_alerts_for_event
from config import Config


class AlertingTestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


app = create_app(AlertingTestConfig)


class AlertingServiceTests(unittest.TestCase):
    def setUp(self):
        self.app_context = app.app_context()
        self.app_context.push()

        db.create_all()

        self.now = datetime(2026, 11, 26, 10, 0, 0)

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def add_rule(
        self,
        *,
        rule_key="RULE-FIRE-001",
        event_type="FIRE DETECTED",
        min_severity="HIGH",
        enabled=True,
        cooldown_seconds=300,
    ):
        rule = AlertRule(
            rule_key=rule_key,
            name="Test alert rule",
            event_type=event_type,
            min_severity=min_severity,
            enabled=enabled,
            cooldown_seconds=cooldown_seconds,
        )

        db.session.add(rule)
        db.session.commit()

        return rule

    def create_alert(self, **overrides):
        arguments = {
            "event_type": "FIRE DETECTED",
            "severity": "CRITICAL",
            "title": "Fire detected",
            "message": "Gas level exceeded the threshold.",
            "source_type": "sensor",
            "source_key": "sensor-01",
            "now": self.now,
        }

        arguments.update(overrides)

        return create_alerts_for_event(**arguments)

    def test_matching_rule_creates_alert(self):
        rule = self.add_rule()

        alerts = self.create_alert()

        self.assertEqual(len(alerts), 1)
        self.assertEqual(Alert.query.count(), 1)
        self.assertEqual(alerts[0].rule_id, rule.id)
        self.assertEqual(alerts[0].severity, "CRITICAL")
        self.assertEqual(alerts[0].event_type, "FIRE DETECTED")

    def test_disabled_rule_does_not_create_alert(self):
        self.add_rule(enabled=False)

        alerts = self.create_alert()

        self.assertEqual(alerts, [])
        self.assertEqual(Alert.query.count(), 0)

    def test_event_below_minimum_severity_is_ignored(self):
        self.add_rule(min_severity="HIGH")

        alerts = self.create_alert(severity="MEDIUM")

        self.assertEqual(alerts, [])
        self.assertEqual(Alert.query.count(), 0)

    def test_event_at_minimum_severity_creates_alert(self):
        self.add_rule(min_severity="HIGH")

        alerts = self.create_alert(severity="HIGH")

        self.assertEqual(len(alerts), 1)

    def test_cooldown_suppresses_same_source(self):
        self.add_rule(cooldown_seconds=300)

        first = self.create_alert()
        second = self.create_alert(
            now=self.now + timedelta(seconds=60)
        )

        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])
        self.assertEqual(Alert.query.count(), 1)

    def test_cooldown_allows_different_source(self):
        self.add_rule(cooldown_seconds=300)

        first = self.create_alert()

        second = self.create_alert(
            source_key="sensor-02",
            now=self.now + timedelta(seconds=60),
        )

        self.assertEqual(len(first), 1)
        self.assertEqual(len(second), 1)
        self.assertEqual(Alert.query.count(), 2)

    def test_deduplication_key_prevents_duplicate_event(self):
        self.add_rule(cooldown_seconds=0)

        first = self.create_alert(
            event_dedup_key="event-123"
        )

        second = self.create_alert(
            event_dedup_key="event-123",
            now=self.now + timedelta(seconds=1),
        )

        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])
        self.assertEqual(Alert.query.count(), 1)

    def test_alert_can_link_to_incident(self):
        self.add_rule()

        incident = IncidentLog(
            event_type="FIRE DETECTED",
            value="Gas: 1200",
            severity="CRITICAL",
            description="Test incident",
        )

        db.session.add(incident)
        db.session.commit()

        alerts = self.create_alert(
            incident_id=incident.id
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0].incident_id,
            incident.id,
        )

    def test_invalid_severity_is_rejected(self):
        with self.assertRaises(ValueError):
            self.create_alert(severity="URGENT")

    def test_missing_event_type_is_rejected(self):
        with self.assertRaises(ValueError):
            self.create_alert(event_type=" ")

    def test_no_matching_rule_creates_no_alert(self):
        self.add_rule(event_type="INTRUSION DETECTED")

        alerts = self.create_alert(
            event_type="FIRE DETECTED"
        )

        self.assertEqual(alerts, [])
        self.assertEqual(Alert.query.count(), 0)


if __name__ == "__main__":
    unittest.main()
