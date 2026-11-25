
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
    activities = db.relationship(
        "IncidentActivity",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentActivity.timestamp"
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

    acknowledged_at = db.Column(
        db.DateTime,
        nullable=True
    )

    acknowledged_by = db.Column(
        db.String(80),
        nullable=True
    )

    resolved_by = db.Column(
        db.String(80),
        nullable=True
    )

    resolution_note = db.Column(
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

class IncidentActivity(db.Model):
    """Audit history for incident investigation and response."""

    __tablename__ = "incident_activity"

    id = db.Column(db.Integer, primary_key=True)

    incident_id = db.Column(
        db.Integer,
        db.ForeignKey("incidentlog.id"),
        nullable=False,
        index=True
    )

    action = db.Column(
        db.String(30),
        nullable=False
    )

    actor = db.Column(
        db.String(80),
        nullable=False
    )

    note = db.Column(
        db.Text,
        nullable=True
    )

    timestamp = db.Column(
        db.DateTime,
        default=datetime.now,
        nullable=False
    )

    incident = db.relationship(
        "IncidentLog",
        back_populates="activities"
    )
