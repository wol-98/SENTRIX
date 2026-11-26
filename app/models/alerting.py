"""Alerting and notification delivery models for SENTRIX."""

import uuid
from datetime import datetime

from app.extensions import db


class AlertRule(db.Model):
    """Configuration for events that should generate alerts."""

    __tablename__ = "alert_rules"

    id = db.Column(db.Integer, primary_key=True)

    rule_key = db.Column(
        db.String(80),
        unique=True,
        nullable=False,
    )

    name = db.Column(
        db.String(120),
        nullable=False,
    )

    event_type = db.Column(
        db.String(60),
        nullable=False,
    )

    min_severity = db.Column(
        db.String(20),
        nullable=True,
    )

    enabled = db.Column(
        db.Boolean,
        nullable=False,
        default=True,
    )

    cooldown_seconds = db.Column(
        db.Integer,
        nullable=False,
        default=300,
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.now,
    )

    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.now,
        onupdate=datetime.now,
    )

    alerts = db.relationship(
        "Alert",
        back_populates="rule",
    )

    __table_args__ = (
        db.CheckConstraint(
            "min_severity IS NULL OR "
            "min_severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name="ck_alert_rule_min_severity",
        ),
        db.CheckConstraint(
            "cooldown_seconds >= 0",
            name="ck_alert_rule_cooldown",
        ),
    )


class Alert(db.Model):
    """A security alert generated from an incident or system event."""

    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)

    alert_ref = db.Column(
        db.String(36),
        unique=True,
        nullable=False,
        default=lambda: str(uuid.uuid4()),
    )

    rule_id = db.Column(
        db.Integer,
        db.ForeignKey("alert_rules.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    incident_id = db.Column(
        db.Integer,
        db.ForeignKey("incidentlog.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    source_type = db.Column(
        db.String(40),
        nullable=False,
    )

    source_key = db.Column(
        db.String(100),
        nullable=True,
    )

    event_type = db.Column(
        db.String(60),
        nullable=False,
    )

    severity = db.Column(
        db.String(20),
        nullable=False,
    )

    title = db.Column(
        db.String(160),
        nullable=False,
    )

    message = db.Column(
        db.Text,
        nullable=False,
    )

    dedup_key = db.Column(
        db.String(160),
        unique=True,
        nullable=True,
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.now,
        index=True,
    )

    rule = db.relationship(
        "AlertRule",
        back_populates="alerts",
    )

    incident = db.relationship("IncidentLog")

    deliveries = db.relationship(
        "NotificationDelivery",
        back_populates="alert",
        cascade="all, delete-orphan",
        order_by="NotificationDelivery.attempted_at",
    )

    __table_args__ = (
        db.CheckConstraint(
            "severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name="ck_alert_severity",
        ),
    )


class NotificationDelivery(db.Model):
    """A single notification delivery attempt."""

    __tablename__ = "notification_deliveries"

    id = db.Column(db.Integer, primary_key=True)

    alert_id = db.Column(
        db.Integer,
        db.ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    channel = db.Column(
        db.String(20),
        nullable=False,
    )

    destination_key = db.Column(
        db.String(100),
        nullable=True,
    )

    status = db.Column(
        db.String(20),
        nullable=False,
        default="PENDING",
    )

    attempt_number = db.Column(
        db.Integer,
        nullable=False,
        default=1,
    )

    provider_message_id = db.Column(
        db.String(160),
        nullable=True,
    )

    error_message = db.Column(
        db.Text,
        nullable=True,
    )

    attempted_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.now,
    )

    delivered_at = db.Column(
        db.DateTime,
        nullable=True,
    )

    alert = db.relationship(
        "Alert",
        back_populates="deliveries",
    )

    __table_args__ = (
        db.CheckConstraint(
            "channel IN ('SMS', 'EMAIL', 'DASHBOARD')",
            name="ck_notification_channel",
        ),
        db.CheckConstraint(
            "status IN ('PENDING', 'SENT', 'FAILED')",
            name="ck_notification_status",
        ),
        db.CheckConstraint(
            "attempt_number >= 1",
            name="ck_notification_attempt_number",
        ),
        db.UniqueConstraint(
            "alert_id",
            "channel",
            "attempt_number",
            name="uq_notification_attempt",
        ),
    )

