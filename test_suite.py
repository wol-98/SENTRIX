
"""SENTRIX automated test suite."""
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from werkzeug.security import generate_password_hash

from app import create_app
from app.core.state import system_state
from app.extensions import db
from app.models import SensorData
import app.monitoring.routes as monitoring_routes

from config import Config


# ============================================================
# TEST CONFIGURATION
# ============================================================

class TestConfig(Config):
    """Isolated configuration for automated tests."""

    TESTING = True

    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    ADMIN_USERNAME = "testadmin"
    ADMIN_PASSWORD_HASH = generate_password_hash(
        "TestPassword123!"
    )


# Create the test application.
# The home endpoint is already registered by create_app().
app = create_app(TestConfig)


# ============================================================
# SHARED TEST HELPERS
# ============================================================

def reset_system_state():
    """Reset shared monitoring state between tests."""

    system_state["iot_metrics"].update({
        "temperature": 25,
        "gas_level": 200,
        "motion": 0,
        "last_update": "Test",
        "last_update_epoch": time.time(),
    })

    system_state["security_metrics"].update({
        "cpu_usage": 0,
        "ram_usage": 0,
        "alert_status": "SAFE",
        "ml_prediction": "Test prediction"
    })

    system_state["system_controls"].update({
        "sprinklers": False,
        "alarm": False,
        "door_lock": True,
        "firewall": "Standard"
    })

    monitoring_routes.last_ddos_time = 0

# ============================================================
# AUTHENTICATION AND TELEMETRY TESTS
# ============================================================

class TestSENTRIX(unittest.TestCase):
    """Test authentication and telemetry functionality."""

    def setUp(self):
        self.client = app.test_client()

        with app.app_context():
            db.create_all()

        reset_system_state()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    # --------------------------------------------------------
    # AUTHORIZATION
    # --------------------------------------------------------

    def test_monitor_requires_login(self):
        response = self.client.get("/api/monitor")

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.location)

    def test_telemetry_rejects_missing_api_key(self):
        payload = {
            "temperature": 24.5,
            "gas": 200,
            "motion": 0
        }

        response = self.client.post(
            "/api/telemetry",
            json=payload
        )

        self.assertEqual(response.status_code, 403)

    def test_telemetry_rejects_invalid_api_key(self):
        response = self.client.post(
            "/api/telemetry",
            json={"temperature": 24.5},
            headers={"X-API-Key": "invalid-key"}
        )

        self.assertEqual(response.status_code, 403)

    def test_telemetry_accepts_valid_api_key(self):
        payload = {
            "temperature": 24.5,
            "gas": 200,
            "motion": 0
        }

        response = self.client.post(
            "/api/telemetry",
            json=payload,
            headers={
                "X-API-Key": app.config["API_SECRET_KEY"]
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json["status"],
            "success"
        )

        with app.app_context():
            self.assertEqual(
                SensorData.query.count(),
                1
            )

    # --------------------------------------------------------
    # TEMPERATURE VALIDATION
    # --------------------------------------------------------

    def test_rejects_temperature_out_of_range(self):
        for temperature in (-40.1, 125.1):
            with self.subTest(temperature=temperature):
                response = self.client.post(
                    "/api/telemetry",
                    json={
                        "temperature": temperature,
                        "gas": 200,
                        "motion": 0
                    },
                    headers={
                        "X-API-Key": app.config["API_SECRET_KEY"]
                    }
                )

                self.assertEqual(
                    response.status_code,
                    400
                )

    def test_accepts_boundary_values(self):
        for temperature, gas in (
            (-40, 0),
            (125, 4095)
        ):
            with self.subTest(
                temperature=temperature,
                gas=gas
            ):
                response = self.client.post(
                    "/api/telemetry",
                    json={
                        "temperature": temperature,
                        "gas": gas,
                        "motion": 1
                    },
                    headers={
                        "X-API-Key": app.config["API_SECRET_KEY"]
                    }
                )

                self.assertEqual(
                    response.status_code,
                    200
                )

    def test_rejects_non_finite_temperature(self):
        for temperature in (
            float("nan"),
            float("inf"),
            float("-inf")
        ):
            with self.subTest(temperature=temperature):
                response = self.client.post(
                    "/api/telemetry",
                    json={
                        "temperature": temperature,
                        "gas": 200,
                        "motion": 0
                    },
                    headers={
                        "X-API-Key": app.config["API_SECRET_KEY"]
                    }
                )

                self.assertEqual(
                    response.status_code,
                    400
                )

    # --------------------------------------------------------
    # GAS VALIDATION
    # --------------------------------------------------------

    def test_rejects_invalid_gas_readings(self):
        for gas in (-1, 4096, 12.5):
            with self.subTest(gas=gas):
                response = self.client.post(
                    "/api/telemetry",
                    json={
                        "temperature": 24.5,
                        "gas": gas,
                        "motion": 0
                    },
                    headers={
                        "X-API-Key": app.config["API_SECRET_KEY"]
                    }
                )

                self.assertEqual(
                    response.status_code,
                    400
                )

    # --------------------------------------------------------
    # MOTION VALIDATION
    # --------------------------------------------------------

    def test_rejects_invalid_motion_values(self):
        for motion in (-1, 2, 0.5):
            with self.subTest(motion=motion):
                response = self.client.post(
                    "/api/telemetry",
                    json={
                        "temperature": 24.5,
                        "gas": 200,
                        "motion": motion
                    },
                    headers={
                        "X-API-Key": app.config["API_SECRET_KEY"]
                    }
                )

                self.assertEqual(
                    response.status_code,
                    400
                )

    # --------------------------------------------------------
    # REQUEST VALIDATION
    # --------------------------------------------------------

    def test_rejects_missing_fields(self):
        response = self.client.post(
            "/api/telemetry",
            json={"temperature": 24.5},
            headers={
                "X-API-Key": app.config["API_SECRET_KEY"]
            }
        )

        self.assertEqual(response.status_code, 400)

    def test_rejects_malformed_json(self):
        response = self.client.post(
            "/api/telemetry",
            data="{invalid-json",
            content_type="application/json",
            headers={
                "X-API-Key": app.config["API_SECRET_KEY"]
            }
        )

        self.assertEqual(response.status_code, 400)

    # --------------------------------------------------------
    # ADMIN AUTHENTICATION
    # --------------------------------------------------------

    def test_successful_admin_login(self):
        response = self.client.post(
            "/login",
            data={
                "username": "testadmin",
                "password": "TestPassword123!"
            }
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/")

        with self.client.session_transaction() as session:
            self.assertTrue(session.get("logged_in"))

    def test_login_rejects_invalid_credentials(self):
        response = self.client.post(
            "/login",
            data={
                "username": "testadmin",
                "password": "WrongPassword"
            }
        )

        self.assertEqual(response.status_code, 401)

        with self.client.session_transaction() as session:
            self.assertFalse(session.get("logged_in"))

    def test_logout_clears_admin_session(self):
        with self.client.session_transaction() as session:
            session["logged_in"] = True

        response = self.client.post("/logout")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/login")

        with self.client.session_transaction() as session:
            self.assertFalse(session.get("logged_in"))

        protected_response = self.client.get("/api/monitor")

        self.assertEqual(
            protected_response.status_code,
            302
        )


# ============================================================
# SECURITY MONITORING TESTS
# ============================================================

class TestMonitoringBehavior(unittest.TestCase):
    """Test SENTRIX security monitoring behaviour."""

    def setUp(self):
        self.client = app.test_client()

        with app.app_context():
            db.create_all()

        # Authenticate the administrator.
        with self.client.session_transaction() as session:
            session["logged_in"] = True

        reset_system_state()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

        reset_system_state()

    # --------------------------------------------------------
    # MONITORING TEST HELPER
    # --------------------------------------------------------

    def monitor(self, cpu=10, ram=30):
        """Request monitoring with simulated system metrics."""

        # Ensure the test sensor is LIVE.
        system_state["iot_metrics"]["last_update_epoch"] = time.time()

        with (
            patch(
                "app.monitoring.routes.psutil.cpu_percent",
                return_value=cpu
            ),
            patch(
                "app.monitoring.routes.psutil.virtual_memory",
                return_value=SimpleNamespace(percent=ram)
            ),
            patch(
                "app.monitoring.routes.run_ml_prediction",
                return_value="Thermal Stability Normal"
            ),
            patch(
                "app.monitoring.routes.send_sms_alert"
            ) as sms_mock,
            patch(
                "app.monitoring.routes.ensure_open_incident",
                return_value=(SimpleNamespace(), True)
            ) as incident_mock,
            patch(
                "app.monitoring.routes.resolve_open_incidents"
            ) as resolve_mock
        ):
            response = self.client.get("/api/monitor")

        return response, sms_mock, incident_mock
    # --------------------------------------------------------
    # FIRE DETECTION
    # --------------------------------------------------------

    def test_fire_detection(self):
        system_state["iot_metrics"]["gas_level"] = 1200

        response, sms, incident = self.monitor()

        self.assertEqual(response.status_code, 200)

        self.assertIn(
            "FIRE",
            response.json["security_metrics"]["alert_status"]
        )

        controls = response.json["system_controls"]

        self.assertTrue(controls["sprinklers"])
        self.assertTrue(controls["alarm"])
        self.assertFalse(controls["door_lock"])

        incident.assert_called_once()
        sms.assert_called_once()

    # --------------------------------------------------------
    # MALWARE DETECTION
    # --------------------------------------------------------

    def test_malware_detection(self):
        system_state["iot_metrics"].update({
            "temperature": 35,
            "gas_level": 200
        })

        response, sms, incident = self.monitor(cpu=60)

        self.assertIn(
            "MALWARE",
            response.json["security_metrics"]["alert_status"]
        )

        self.assertEqual(
            response.json["system_controls"]["firewall"],
            "PROCESS ALERT"
        )

        incident.assert_called_once()
        sms.assert_called_once()

    # --------------------------------------------------------
    # RESOURCE SPIKE DETECTION
    # --------------------------------------------------------

    def test_resource_spike_detection(self):
        response, sms, incident = self.monitor(cpu=45)

        self.assertIn(
            "RESOURCE SPIKE",
            response.json["security_metrics"]["alert_status"]
        )

        self.assertEqual(
            response.json["system_controls"]["firewall"],
            "TRAFFIC REVIEW"
        )

        incident.assert_called_once()
        sms.assert_called_once()

    # --------------------------------------------------------
    # MOTION / INTRUSION DETECTION
    # --------------------------------------------------------

    def test_motion_intrusion_detection(self):
        system_state["iot_metrics"]["motion"] = 1

        response, sms, incident = self.monitor()

        self.assertIn(
            "INTRUSION",
            response.json["security_metrics"]["alert_status"]
        )

        self.assertTrue(
            response.json["system_controls"]["alarm"]
        )

        sms.assert_called_once()

        incident.assert_called_once_with(
            event_type="INTRUSION DETECTED",
            value="Motion: 1",
            severity="HIGH",
            description=(
                "Motion sensor detected unexpected movement."
            )
        )

    # --------------------------------------------------------
    # SAFE MONITORING STATE
    # --------------------------------------------------------

    def test_safe_monitoring_state(self):
        response, sms, incident = self.monitor()

        self.assertEqual(
            response.json["security_metrics"]["alert_status"],
            "SAFE"
        )

        self.assertFalse(
            response.json["system_controls"]["alarm"]
        )

        self.assertFalse(
            response.json["system_controls"]["sprinklers"]
        )

        sms.assert_not_called()
        incident.assert_not_called()


# ============================================================
# TEST EXECUTION
# ============================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
