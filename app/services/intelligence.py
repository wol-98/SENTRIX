
"""Machine-learning intelligence services for SENTRIX."""

import numpy as np
from sklearn.linear_model import LinearRegression

from app.models import SensorData


def run_ml_prediction():
    """Predict short-term temperature trends using recent readings."""

    history = (
        SensorData.query
        .order_by(SensorData.id.desc())
        .limit(20)
        .all()
    )

    if len(history) < 10:
        return "Gathering Data..."

    temperatures = [
        reading.temperature
        for reading in reversed(history)
    ]

    x_values = np.arange(
        len(temperatures)
    ).reshape(-1, 1)

    y_values = np.array(
        temperatures
    ).reshape(-1, 1)

    model = LinearRegression()
    model.fit(x_values, y_values)

    predicted_temperature = model.predict(
        np.array([[len(temperatures) + 5]])
    )[0][0]

    trend = model.coef_[0][0]

    if predicted_temperature > 50:
        return (
            f"OVERHEAT RISK "
            f"(Pred: {predicted_temperature:.1f} C)"
        )

    if trend > 0.5:
        return "Rapid Warming Detected"

    if trend < -0.5:
        return "Cooling Down"

    return "Thermal Stability Normal"
