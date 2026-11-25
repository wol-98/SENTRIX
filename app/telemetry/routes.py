from datetime import datetime
import math

from flask import Blueprint, current_app, jsonify, request

from app.extensions import db
from app.models import SensorData
from app.core.state import system_state
from app.telemetry.decorators import require_api_key


telemetry_bp = Blueprint("telemetry", __name__)


@telemetry_bp.route("/api/telemetry", methods=["POST"])
@require_api_key
def update_telemetry():
    """Receive, validate and persist device telemetry."""

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "A valid JSON object is required."
        }), 400

    required_fields = {"temperature", "gas", "motion"}

    if not required_fields.issubset(data):
        return jsonify({
            "error": "Missing required telemetry fields."
        }), 400

    temperature = data["temperature"]
    gas = data["gas"]
    motion = data["motion"]

    # Temperature validation
    if (
        isinstance(temperature, bool)
        or not isinstance(temperature, (int, float))
        or not math.isfinite(temperature)
        or not -40 <= temperature <= 125
    ):
        return jsonify({
            "error": (
                "Temperature must be between "
                "-40 and 125 Celsius."
            )
        }), 400

    # Gas sensor validation
    if (
        isinstance(gas, bool)
        or not isinstance(gas, int)
        or not 0 <= gas <= 4095
    ):
        return jsonify({
            "error": (
                "Gas must be an integer "
                "between 0 and 4095."
            )
        }), 400

    # Motion sensor validation
    if (
        isinstance(motion, bool)
        or not isinstance(motion, int)
        or motion not in (0, 1)
    ):
        return jsonify({
            "error": "Motion must be either 0 or 1."
        }), 400

    received_at = datetime.now()

    new_reading = SensorData(
        timestamp=received_at,
        temperature=temperature,
        gas=gas,
        motion=motion
    )

    try:
        db.session.add(new_reading)
        db.session.commit()

    except Exception:
        db.session.rollback()

        current_app.logger.exception(
            "Failed to persist incoming telemetry."
        )

        return jsonify({
            "error": "Telemetry could not be stored."
        }), 500

    system_state["iot_metrics"].update({
        "temperature": temperature,
        "gas_level": gas,
        "motion": motion,
        "last_update": received_at.strftime("%H:%M:%S"),
        "last_update_epoch": received_at.timestamp()
    })

    return jsonify({
        "status": "success"
    }), 200
