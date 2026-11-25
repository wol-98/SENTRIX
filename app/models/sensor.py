
from datetime import datetime

from app.extensions import db


class SensorData(db.Model):
    __tablename__ = "sensordata"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(
        db.DateTime,
        default=datetime.now,
        nullable=False
    )
    temperature = db.Column(db.Float, nullable=False)
    gas = db.Column(db.Integer, nullable=False)
    motion = db.Column(db.Integer, nullable=False)





