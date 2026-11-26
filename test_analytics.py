
"""Tests for SENTRIX security analytics."""

import unittest
from datetime import datetime, timedelta

from werkzeug.security import generate_password_hash

from app import create_app
from app.extensions import db
from app.models import IncidentLog
from app.services.analytics import get_incident_analytics
from config import Config


class AnalyticsTestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    ADMIN_USERNAME = "analyticsadmin"
    ADMIN_PASSWORD_HASH = generate_password_hash(
        "AnalyticsTest123!"
    )


app = create_app(AnalyticsTestConfig)


class IncidentAnalyticsTests(unittest.TestCase):
    def setUp(self):
        self.app_context = app.app_context()
        self.app_context.push()

        db.create_all()
        self.client = app.test_client()

        self.base_time = datetime(2026, 11, 1, 10, 0, 0)

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def add_incident(
        self,
        *,
        minutes_after=0,
        event_type="FIRE DETECTED",
        severity="HIGH",
        status="OPEN",
        acknowledged_minutes=None,
        resolved_minutes=None,
    ):
        incident_time = self.base_time + timedelta(
            minutes=minutes_after
        )

        incident = IncidentLog(
            timestamp=incident_time,
            event_type=event_type,
            value="Test value",
            severity=severity,
            status=status,
        )

        if acknowledged_minutes is not None:
            incident.acknowledged_at = (
                incident_time
                + timedelta(minutes=acknowledged_minutes)
            )

        if resolved_minutes is not None:
            incident.resolved_at = (
                incident_time
                + timedelta(minutes=resolved_minutes)
            )

        db.session.add(incident)
        db.session.commit()

        return incident

    def test_empty_database_returns_zero_counts(self):
        result = get_incident_analytics()

        self.assertEqual(result["total_incidents"], 0)
        self.assertEqual(result["status_counts"], {})
        self.assertEqual(result["severity_counts"], {})
        self.assertEqual(result["event_type_counts"], {})
        self.assertIsNone(
            result["response_performance"]["mtta_minutes"]
        )
        self.assertIsNone(
            result["response_performance"]["mttr_minutes"]
        )

    def test_counts_status_severity_and_event_types(self):
        self.add_incident(
            event_type="FIRE DETECTED",
            severity="CRITICAL",
            status="OPEN",
        )
        self.add_incident(
            minutes_after=10,
            event_type="FIRE DETECTED",
            severity="HIGH",
            status="ACKNOWLEDGED",
        )
        self.add_incident(
            minutes_after=20,
            event_type="INTRUSION DETECTED",
            severity="HIGH",
            status="RESOLVED",
        )

        result = get_incident_analytics()

        self.assertEqual(result["total_incidents"], 3)
        self.assertEqual(
            result["status_counts"],
            {
                "OPEN": 1,
                "ACKNOWLEDGED": 1,
                "RESOLVED": 1,
            },
        )
        self.assertEqual(
            result["severity_counts"],
            {
                "CRITICAL": 1,
                "HIGH": 2,
            },
        )
        self.assertEqual(
            result["event_type_counts"],
            {
                "FIRE DETECTED": 2,
                "INTRUSION DETECTED": 1,
            },
        )

    def test_date_range_filters_incidents(self):
        self.add_incident(minutes_after=0)
        self.add_incident(minutes_after=60)
        self.add_incident(minutes_after=120)

        result = get_incident_analytics(
            start_date=self.base_time + timedelta(minutes=60),
            end_date=self.base_time + timedelta(minutes=60),
        )

        self.assertEqual(result["total_incidents"], 1)

    def test_severity_event_type_and_status_filters(self):
        self.add_incident(
            severity="HIGH",
            event_type="FIRE DETECTED",
            status="OPEN",
        )
        self.add_incident(
            minutes_after=10,
            severity="CRITICAL",
            event_type="FIRE DETECTED",
            status="OPEN",
        )
        self.add_incident(
            minutes_after=20,
            severity="HIGH",
            event_type="INTRUSION DETECTED",
            status="RESOLVED",
        )

        result = get_incident_analytics(
            severity="high",
            event_type="FIRE DETECTED",
            status="open",
        )

        self.assertEqual(result["total_incidents"], 1)

    def test_mtta_and_mttr_are_calculated_in_minutes(self):
        self.add_incident(
            acknowledged_minutes=10,
            resolved_minutes=40,
        )
        self.add_incident(
            minutes_after=60,
            acknowledged_minutes=20,
            resolved_minutes=60,
        )

        result = get_incident_analytics()
        performance = result["response_performance"]

        self.assertEqual(performance["mtta_minutes"], 15)
        self.assertEqual(performance["mttr_minutes"], 50)
        self.assertEqual(performance["mtta_sample_size"], 2)
        self.assertEqual(performance["mttr_sample_size"], 2)

    def test_missing_timestamps_are_excluded_from_metrics(self):
        self.add_incident()
        self.add_incident(
            minutes_after=10,
            acknowledged_minutes=5,
            resolved_minutes=30,
        )

        result = get_incident_analytics()
        performance = result["response_performance"]

        self.assertEqual(performance["mtta_minutes"], 5)
        self.assertEqual(performance["mttr_minutes"], 30)
        self.assertEqual(performance["mtta_sample_size"], 1)
        self.assertEqual(performance["mttr_sample_size"], 1)

    def test_negative_response_durations_are_excluded(self):
        incident = self.add_incident()
        incident.acknowledged_at = (
            incident.timestamp - timedelta(minutes=1)
        )
        incident.resolved_at = (
            incident.timestamp - timedelta(minutes=2)
        )
        db.session.commit()

        result = get_incident_analytics()
        performance = result["response_performance"]

        self.assertIsNone(performance["mtta_minutes"])
        self.assertIsNone(performance["mttr_minutes"])
        self.assertEqual(performance["mtta_sample_size"], 0)
        self.assertEqual(performance["mttr_sample_size"], 0)

    def test_daily_trends_group_incidents_by_date(self):
        self.add_incident(minutes_after=0)
        self.add_incident(minutes_after=30)
        self.add_incident(minutes_after=24 * 60)

        result = get_incident_analytics()

        self.assertEqual(
            result["daily_trends"],
            [
                {"date": "2026-11-01", "count": 2},
                {"date": "2026-11-02", "count": 1},
            ],
        )


if __name__ == "__main__":
    unittest.main()
