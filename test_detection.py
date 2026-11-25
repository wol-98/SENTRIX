
import unittest

from app.services.detection import evaluate_detection


class DetectionEngineTests(unittest.TestCase):
    def evaluate(self, **overrides):
        metrics = {
            "sensor_live": True,
            "gas_level": 200,
            "temperature": 25,
            "motion_detected": 0,
            "cpu_usage": 10,
            "last_ddos_time": 0,
            "now": 100,
        }
        metrics.update(overrides)
        return evaluate_detection(**metrics)

    def test_fire_detection(self):
        detection, _ = self.evaluate(gas_level=1001)

        self.assertEqual(detection.rule_id, "DET-FIRE-001")
        self.assertEqual(detection.severity, "CRITICAL")
        self.assertTrue(detection.control_updates["sprinklers"])

    def test_fire_threshold_is_strict(self):
        detection, _ = self.evaluate(gas_level=1000)

        self.assertIsNone(detection)

    def test_malware_detection(self):
        detection, _ = self.evaluate(
            cpu_usage=51,
            temperature=31,
        )

        self.assertEqual(detection.rule_id, "DET-MALWARE-001")
        self.assertEqual(detection.event_type, "MALWARE DETECTED")

    def test_resource_spike_detection(self):
        detection, updated_time = self.evaluate(cpu_usage=41)

        self.assertEqual(detection.rule_id, "DET-RESOURCE-001")
        self.assertEqual(updated_time, 100)

    def test_motion_intrusion_detection(self):
        detection, _ = self.evaluate(motion_detected=1)

        self.assertEqual(detection.rule_id, "DET-INTRUSION-001")
        self.assertEqual(detection.severity, "HIGH")

    def test_stale_sensor_does_not_trigger_fire(self):
        detection, _ = self.evaluate(
            sensor_live=False,
            gas_level=1200,
        )

        self.assertIsNone(detection)

    def test_stale_sensor_can_trigger_resource_spike(self):
        detection, _ = self.evaluate(
            sensor_live=False,
            cpu_usage=45,
        )

        self.assertEqual(detection.rule_id, "DET-RESOURCE-001")

    def test_fire_has_priority_over_malware(self):
        detection, _ = self.evaluate(
            gas_level=1200,
            cpu_usage=60,
            temperature=35,
        )

        self.assertEqual(detection.rule_id, "DET-FIRE-001")

    def test_safe_metrics_return_no_detection(self):
        detection, _ = self.evaluate()

        self.assertIsNone(detection)


if __name__ == "__main__":
    unittest.main()
