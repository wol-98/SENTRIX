"""Shared runtime state for SENTRIX."""

system_state = {
    "iot_metrics": {
        "temperature": 0,
        "gas_level": 0,
        "motion": 0,
        "last_update": "Waiting...",
        "last_update_epoch": None
    },

    "sensor_health": {
        "status": "OFFLINE",
        "age_seconds": None,
        "last_seen": None
    },

    "security_metrics": {
        "cpu_usage": 0,
        "ram_usage": 0,
        "alert_status": "SAFE",
        "ml_prediction": "Calibrating..."
    },

    "system_controls": {
        "sprinklers": False,
        "alarm": False,
        "door_lock": True,
        "firewall": "Standard"
    }
}
