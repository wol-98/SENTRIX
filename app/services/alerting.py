"""Alert rule evaluation and alert creation for SENTRIX."""

import hashlib
from datetime import datetime, timedelta

from flask import current_app

from app.extensions import db
from app.models import Alert, AlertRule


VALID_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}

SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _severity_matches(event_severity, minimum_severity):
    """Return whether an event meets a rule's severity threshold."""

    if minimum_severity is None:
        return True

    return (
        SEVERITY_RANK[event_severity]
        >= SEVERITY_RANK[minimum_severity]
    )


def _build_dedup_key(rule_key, event_dedup_key):
    """Build a stable, rule-specific deduplication key."""

    if not event_dedup_key:
        return None

    digest = hashlib.sha256(
        str(event_dedup_key).encode("utf-8")
    ).hexdigest()

    return f"{rule_key}:{digest}"


def create_alerts_for_event(
    *,
    event_type,
    severity,
    title,
    message,
    source_type,
    source_key=None,
    incident_id=None,
    event_dedup_key=None,
    now=None,
):
    """
    Evaluate enabled rules and create matching alerts.

    Returns the alerts created during this call.

    This service does not create incidents or dispatch notifications.
    """

    event_type = str(event_type).strip()
    severity = str(severity).upper()
    source_type = str(source_type).strip()

    if not event_type:
        raise ValueError("event_type is required")

    if not source_type:
        raise ValueError("source_type is required")

    if severity not in VALID_SEVERITIES:
        raise ValueError(
            f"Invalid alert severity: {severity}"
        )

    if not title or not message:
        raise ValueError("title and message are required")

    now = now or datetime.now()

    rules = (
        AlertRule.query
        .filter_by(
            event_type=event_type,
            enabled=True,
        )
        .order_by(AlertRule.id.asc())
        .all()
    )

    created_alerts = []

    try:
        for rule in rules:
            minimum = rule.min_severity

            if minimum and minimum not in VALID_SEVERITIES:
                current_app.logger.warning(
                    "Skipping alert rule with invalid severity: %s",
                    rule.rule_key,
                )
                continue

            if not _severity_matches(severity, minimum):
                continue

            dedup_key = _build_dedup_key(
                rule.rule_key,
                event_dedup_key,
            )

            # Prevent the same source event from being processed
            # repeatedly for this rule.
            if dedup_key:
                existing = Alert.query.filter_by(
                    dedup_key=dedup_key
                ).first()

                if existing:
                    continue

            # Apply cooldown to alerts from the same rule and source.
            if rule.cooldown_seconds > 0:
                cutoff = now - timedelta(
                    seconds=rule.cooldown_seconds
                )

                recent_alert = (
                    Alert.query
                    .filter(
                        Alert.rule_id == rule.id,
                        Alert.source_type == source_type,
                        Alert.source_key == source_key,
                        Alert.event_type == event_type,
                        Alert.created_at >= cutoff,
                    )
                    .order_by(Alert.created_at.desc())
                    .first()
                )

                if recent_alert:
                    continue

            alert = Alert(
                rule_id=rule.id,
                incident_id=incident_id,
                source_type=source_type,
                source_key=source_key,
                event_type=event_type,
                severity=severity,
                title=str(title)[:160],
                message=str(message),
                dedup_key=dedup_key,
                created_at=now,
            )

            db.session.add(alert)
            created_alerts.append(alert)

        if created_alerts:
            db.session.commit()

            current_app.logger.info(
                "SENTRIX created %s alert(s) for %s.",
                len(created_alerts),
                event_type,
            )

        return created_alerts

    except Exception:
        db.session.rollback()

        current_app.logger.exception(
            "Failed to create SENTRIX alerts for %s.",
            event_type,
        )

        return []
