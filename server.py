
"""SENTRIX application entry point."""

from app.models import SensorData
from config import Config
from app import create_app
from app.auth.decorators import login_required
from app.extensions import db
from app.core.state import system_state

app = create_app()

# ============================================================
# APPLICATION ENTRY POINT
# ============================================================

if __name__ == "__main__":

    Config.validate()

    with app.app_context():
        db.create_all()

        latest_reading = (
            SensorData.query
            .order_by(SensorData.timestamp.desc(), SensorData.id.desc())
            .first()
        )

        if latest_reading:
            system_state["iot_metrics"].update({
                "temperature": latest_reading.temperature,
                "gas_level": latest_reading.gas,
                "motion": latest_reading.motion,
                "last_update": latest_reading.timestamp.strftime("%H:%M:%S"),
                "last_update_epoch": latest_reading.timestamp.timestamp(),
            })

        print("SENTRIX database initialized.")

    print("SENTRIX Security Platform starting on port 5001.")

    app.run(
        host="0.0.0.0",
        port=5001,
        debug=app.config["DEBUG"]
    )
