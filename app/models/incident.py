
"""Incident management model for SENTRIX."""

import uuid
from datetime import datetime

from app.extensions import db


class IncidentLog(db.Model):
    __tablename__ = "incidentlog"

    id = db.Column(db.Integer, primary_key=True)

    incident_ref = db.Column(
        db.String(36),
        unique=True,
        nullable=False,
        default=lambda: str(uuid.uuid4())
    )

    timestamp = db.Column(
        db.DateTime,
        default=datetime.now,
        nullable=False
    )

    event_type = db.Column(
        db.String(50),
        nullable=False
    )

    value = db.Column(
        db.String(50),
        nullable=False
    )

    status = db.Column(
        db.String(20),
        nullable=False,
        default="OPEN"
    )

    severity = db.Column(
        db.String(20),
        nullable=False,
        default="MEDIUM"
    )

    description = db.Column(
        db.Text,
        nullable=True
    )

    updated_at = db.Column(
        db.DateTime,
        default=datetime.now,
        onupdate=datetime.now,
        nullable=False
    )

    resolved_at = db.Column(
        db.DateTime,
        nullable=True
    )
