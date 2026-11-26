"""Tests for SENTRIX sensor health history."""
from app.services.sensor_health_analytics import (
    get_sensor_health_analytics,
)

import unittest
from datetime import datetime, timedelta

from app import create_app
from app.extensions import db
from app.models import SensorHealthHistory
from app.services.sensor_health import (
    record_sensor_health_transition,
)
from config import Config


class SensorHealthTestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


app = create_app(SensorHealthTestConfig)


class SensorHealthHistoryTests(unittest.TestCase):
    def setUp(self):
        self.app_context = app.app_context()
        self.app_context.push()

        db.create_all()

        self.last_seen = datetime(2026, 11, 26, 10, 0, 0)
        self.last_seen_epoch = self.last_seen.timestamp()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def history_count(self):
        return SensorHealthHistory.query.count()

    def test_records_initial_live_status(self):
        record_sensor_health_transition(
            status="LIVE",
            age_seconds=2,
            last_seen_epoch=self.last_seen_epoch,
        )

        history = SensorHealthHistory.query.one()

        self.assertEqual(history.status, "LIVE")
        self.assertEqual(history.last_seen_at, self.last_seen)
        self.assertEqual(history.changed_at, self.last_seen)
        self.assertEqual(history.age_seconds, 2)
        self.assertEqual(self.history_count(), 1)

    def test_repeated_status_does_not_create_duplicate_rows(self):
        for _ in range(5):
            record_sensor_health_transition(
                status="LIVE",
                age_seconds=1,
                last_seen_epoch=self.last_seen_epoch,
            )

        self.assertEqual(self.history_count(), 1)

    def test_records_status_transitions_and_effective_times(self):
        record_sensor_health_transition(
            status="LIVE",
            age_seconds=1,
            last_seen_epoch=self.last_seen_epoch,
        )

        record_sensor_health_transition(
            status="STALE",
            age_seconds=11,
            last_seen_epoch=self.last_seen_epoch,
        )

        record_sensor_health_transition(
            status="OFFLINE",
            age_seconds=61,
            last_seen_epoch=self.last_seen_epoch,
        )

        history = (
            SensorHealthHistory.query
            .order_by(SensorHealthHistory.id.asc())
            .all()
        )

        self.assertEqual(
            [item.status for item in history],
            ["LIVE", "STALE", "OFFLINE"],
        )

        self.assertEqual(
            history[1].changed_at,
            self.last_seen.replace(second=10),
        )

        self.assertEqual(
               history[2].changed_at,
            self.last_seen + timedelta(seconds=60),
        )

        self.assertEqual(self.history_count(), 3)

    def test_initial_offline_without_last_seen_has_unknown_start(self):
        record_sensor_health_transition(
            status="OFFLINE",
            age_seconds=None,
            last_seen_epoch=None,
        )

        history = SensorHealthHistory.query.one()

        self.assertEqual(history.status, "OFFLINE")
        self.assertIsNone(history.last_seen_at)
        self.assertIsNone(history.age_seconds)
        self.assertIsNotNone(history.changed_at)
        self.assertEqual(self.history_count(), 1)

    def test_rejects_unsupported_status(self):
        with self.assertRaises(ValueError):
            record_sensor_health_transition(
                status="UNKNOWN",
                age_seconds=0,
                last_seen_epoch=self.last_seen_epoch,
            )

        self.assertEqual(self.history_count(), 0)

    def add_history_record(
        self,
        status,
        changed_at,
        *,
        last_seen_at=None,
    ):
        record = SensorHealthHistory(
            sensor_key="default",
            status=status,
            changed_at=changed_at,
            recorded_at=changed_at,
            last_seen_at=last_seen_at,
            age_seconds=None,
        )
        db.session.add(record)
        db.session.commit()
        return record

    def test_calculates_known_offline_duration_and_uptime(self):
        start = datetime(2026, 11, 26, 10, 0, 0)

        self.add_history_record(
            "LIVE",
            start,
            last_seen_at=start,
        )
        self.add_history_record(
            "OFFLINE",
            start + timedelta(minutes=10),
            last_seen_at=start + timedelta(minutes=9),
        )
        self.add_history_record(
            "LIVE",
            start + timedelta(minutes=20),
            last_seen_at=start + timedelta(minutes=20),
        )

        result = get_sensor_health_analytics(
            start_date=start,
            end_date=start + timedelta(minutes=20),
            now=start + timedelta(minutes=20),
        )

        self.assertEqual(
            result["outages"]["completed_count"],
            1,
        )
        self.assertEqual(
            result["outages"]["total_offline_seconds"],
            600,
        )
        self.assertEqual(
            result["uptime"]["online_seconds"],
            600,
        )
        self.assertEqual(
            result["uptime"]["offline_seconds"],
            600,
        )
        self.assertEqual(
            result["uptime"]["percentage"],
            50.0,
        )

    def test_unknown_initial_offline_period_is_not_counted(self):
        start = datetime(2026, 11, 26, 10, 0, 0)

        self.add_history_record(
            "OFFLINE",
            start,
            last_seen_at=None,
        )
        self.add_history_record(
            "LIVE",
            start + timedelta(minutes=15),
            last_seen_at=start + timedelta(minutes=15),
        )

        result = get_sensor_health_analytics(
            start_date=start,
            end_date=start + timedelta(minutes=15),
            now=start + timedelta(minutes=15),
        )

        self.assertEqual(
            result["outages"]["total_offline_seconds"],
            0,
        )
        self.assertEqual(
            result["uptime"]["offline_seconds"],
            0,
        )
        self.assertIsNone(
            result["uptime"]["percentage"],
        )

    def test_reports_ongoing_offline_period(self):
        start = datetime(2026, 11, 26, 10, 0, 0)

        self.add_history_record(
            "LIVE",
            start,
            last_seen_at=start,
        )
        self.add_history_record(
            "OFFLINE",
            start + timedelta(minutes=5),
            last_seen_at=start + timedelta(minutes=4),
        )

        result = get_sensor_health_analytics(
            start_date=start,
            end_date=start + timedelta(minutes=15),
            now=start + timedelta(minutes=15),
        )

        self.assertTrue(result["outages"]["ongoing"])
        self.assertEqual(
            result["outages"]["ongoing_seconds"],
            600,
        )
        self.assertEqual(
            result["outages"]["total_offline_seconds"],
            600,
        )

if __name__ == "__main__":
    unittest.main()
