
"""Incident management services for SENTRIX."""

from datetime import datetime

from flask import current_app

from app.extensions import db
from app.models import IncidentLog


VALID_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}


def log_incident(
    event_type,
    value,
    severity="MEDIUM",
    description=None,
):
    """Create and persist a security incident."""

    severity = severity.upper()

    if severity not in VALID_SEVERITIES:
        raise ValueError(
            f"Invalid incident severity: {severity}"
        )

    incident = IncidentLog(
        event_type=event_type,
        value=str(value),
        status="OPEN",
        severity=severity,
        description=description,
    )

    try:
        db.session.add(incident)
        db.session.commit()

        current_app.logger.info(
            "SENTRIX incident created: %s | %s | %s",
            incident.incident_ref,
            event_type,
            severity,
        )

        return incident

    except Exception:
        db.session.rollback()

        current_app.logger.exception(
            "Failed to create SENTRIX incident."
        )

        return None


def ensure_open_incident(
    event_type,
    value,
    severity="MEDIUM",
    description=None,
):
    """
    Return an existing open incident, or create one.

    If multiple open incidents already exist for the same
    event type, keep the newest open and resolve the extras.
    """

    open_incidents = (
        IncidentLog.query
        .filter_by(
            event_type=event_type,
            status="OPEN",
        )
        .order_by(IncidentLog.timestamp.desc())
        .all()
    )

    if open_incidents:
        # Keep the newest record as the active incident.
        active_incident = open_incidents[0]

        # Reconcile any duplicate open records.
        now = datetime.now()

        for duplicate in open_incidents[1:]:
            duplicate.status = "RESOLVED"
            duplicate.resolved_at = now
            duplicate.updated_at = now

        if len(open_incidents) > 1:
            db.session.commit()

        return active_incident, False

    incident = log_incident(
        event_type=event_type,
        value=value,
        severity=severity,
        description=description,
    )

    return incident, incident is not None


def resolve_open_incidents(
    event_types,
    except_event_type=None,
):
    """
    Resolve open incidents for the supplied event types.

    If except_event_type is supplied, leave that event type
    active and resolve the other event types.
    """

    query = IncidentLog.query.filter(
        IncidentLog.status == "OPEN",
        IncidentLog.event_type.in_(event_types),
    )

    if except_event_type:
        query = query.filter(
            IncidentLog.event_type != except_event_type
        )

    open_incidents = query.all()

    if not open_incidents:
        return 0

    now = datetime.now()

    for incident in open_incidents:
        incident.status = "RESOLVED"
        incident.resolved_at = now
        incident.updated_at = now

    try:
        db.session.commit()

        current_app.logger.info(
            "SENTRIX resolved %s incident(s).",
            len(open_incidents),
        )

        return len(open_incidents)

    except Exception:
        db.session.rollback()

        current_app.logger.exception(
            "Failed to resolve SENTRIX incidents."
        )

        return 0
