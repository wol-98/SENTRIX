"""Security monitoring routes for SENTRIX."""

from io import BytesIO
from app.models.sensor import SensorData
from reportlab.platypus import KeepTogether
from datetime import datetime
from app.extensions import db
import logging
from flask import (
    send_file,
    current_app,
    render_template,
    request,
    url_for,
    redirect,
    flash,
    session,
    jsonify,
)
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from app.services.alerting import create_alerts_for_event
from app.services.dispatcher import dispatch_alert

from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

from app.models import (
    IncidentLog,
    IncidentActivity,
    AlertRule,
    Alert,
    NotificationDelivery,
)
from app.services.sensor_health import (
    record_sensor_health_transition,
)

import time

import psutil
from flask import Blueprint, jsonify

from app.auth.decorators import login_required
from app.core.state import system_state
from app.services.notifications import send_sms_alert
from app.services.intelligence import run_ml_prediction
from app.services.detection import evaluate_detection
from app.services.incidents import (
    ensure_open_incident,
    resolve_open_incidents,
    sync_sensor_health_incident,
)
logger = logging.getLogger(__name__)

monitoring_bp = Blueprint("monitoring", __name__)

# Track resource spikes and the currently active alert.
last_ddos_time = 0

ALERT_EVENT_TYPES = {
    "DANGER: FIRE - DEFENSE ACTIVE": "FIRE DETECTED",
    "MALWARE: CRYPTO-MINER DETECTED": "MALWARE DETECTED",
    (
        "CRITICAL: RESOURCE SPIKE - "
        "INVESTIGATION REQUIRED"
    ): "DDoS SUSPECTED",
    "INTRUSION: MOTION DETECTED": "INTRUSION DETECTED",
}
@monitoring_bp.route("/incidents", methods=["GET"])
@login_required
def incident_console():
    """Display and filter recorded security incidents."""

    status = request.args.get("status", "").upper()
    severity = request.args.get("severity", "").upper()
    search = request.args.get("q", "").strip()

    valid_statuses = {"OPEN", "RESOLVED"}
    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

    query = IncidentLog.query

    if status in valid_statuses:
        query = query.filter(IncidentLog.status == status)

    if severity in valid_severities:
        query = query.filter(IncidentLog.severity == severity)

    if search:
        pattern = f"%{search}%"
        query = query.filter(
            or_(
                IncidentLog.incident_ref.ilike(pattern),
                IncidentLog.event_type.ilike(pattern),
                IncidentLog.description.ilike(pattern),
                IncidentLog.value.ilike(pattern),
            )
        )

    filtered_count = query.count()

    incidents = (
        query
        .order_by(IncidentLog.timestamp.desc())
        .limit(200)
        .all()
    )

    summary = {
        "total": IncidentLog.query.count(),
        "open": IncidentLog.query.filter_by(status="OPEN").count(),
        "resolved": IncidentLog.query.filter_by(
            status="RESOLVED"
        ).count(),
        "critical": IncidentLog.query.filter_by(
            severity="CRITICAL"
        ).count(),
    }

    return render_template(
        "incidents.html",
        incidents=incidents,
        summary=summary,
        status=status,
        severity=severity,
        search=search,
        filtered_count=filtered_count,
    )


@monitoring_bp.route("/api/alerts/rules", methods=["GET"])
@login_required
def list_alert_rules():
    """Return configured alert rules."""
    rules = AlertRule.query.order_by(AlertRule.name.asc()).all()

    return jsonify({
        "rules": [
            {
                "id": rule.id,
                "rule_key": rule.rule_key,
                "name": rule.name,
                "event_type": rule.event_type,
                "min_severity": rule.min_severity,
                "enabled": rule.enabled,
                "cooldown_seconds": rule.cooldown_seconds,
                "created_at": rule.created_at.isoformat(),
                "updated_at": rule.updated_at.isoformat(),
            }
            for rule in rules
        ]
    }), 200

@monitoring_bp.route("/api/alerts/rules", methods=["POST"])
@login_required
def create_alert_rule():
    """Create a configurable alert rule."""
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "A JSON object is required."}), 400

    rule_key = data.get("rule_key")
    name = data.get("name")
    event_type = data.get("event_type")

    if not isinstance(rule_key, str) or not rule_key.strip():
        return jsonify({"error": "rule_key must be a non-empty string."}), 400

    if not isinstance(name, str) or not name.strip():
        return jsonify({"error": "name must be a non-empty string."}), 400

    if not isinstance(event_type, str) or not event_type.strip():
        return jsonify({"error": "event_type must be a non-empty string."}), 400

    rule_key = rule_key.strip()
    name = name.strip()
    event_type = event_type.strip().upper()

    if len(rule_key) > 100:
        return jsonify({"error": "rule_key is too long."}), 400

    if len(name) > 120:
        return jsonify({"error": "name is too long."}), 400

    if len(event_type) > 60:
        return jsonify({"error": "event_type is too long."}), 400

    min_severity = data.get("min_severity")
    valid_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    if min_severity is not None:
        if not isinstance(min_severity, str):
            return jsonify({"error": "Invalid min_severity."}), 400

        min_severity = min_severity.strip().upper()

        if min_severity not in valid_severities:
            return jsonify({"error": "Invalid min_severity."}), 400

    enabled = data.get("enabled", True)

    if not isinstance(enabled, bool):
        return jsonify({"error": "enabled must be true or false."}), 400

    cooldown_seconds = data.get("cooldown_seconds", 0)

    if (
        isinstance(cooldown_seconds, bool)
        or not isinstance(cooldown_seconds, int)
        or cooldown_seconds < 0
    ):
        return jsonify({
            "error": "cooldown_seconds must be a non-negative integer."
        }), 400

    rule = AlertRule(
        rule_key=rule_key,
        name=name,
        event_type=event_type,
        min_severity=min_severity,
        enabled=enabled,
        cooldown_seconds=cooldown_seconds,
    )

    db.session.add(rule)

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "An alert rule with this key already exists."}), 409

    return jsonify({
        "message": "Alert rule created.",
        "rule": {
            "id": rule.id,
            "rule_key": rule.rule_key,
            "name": rule.name,
            "event_type": rule.event_type,
            "min_severity": rule.min_severity,
            "enabled": rule.enabled,
            "cooldown_seconds": rule.cooldown_seconds,
            "created_at": rule.created_at.isoformat(),
            "updated_at": rule.updated_at.isoformat(),
        },
    }), 201
@monitoring_bp.route("/api/alerts/history", methods=["GET"])
@login_required
def notification_history():
    """Return recent notification delivery attempts."""
    status = request.args.get("status", "").strip().upper()
    channel = request.args.get("channel", "").strip().upper()

    valid_statuses = {"PENDING", "SENT", "FAILED"}
    valid_channels = {"SMS", "EMAIL", "DASHBOARD"}

    if status and status not in valid_statuses:
        return jsonify({"error": "Invalid status filter."}), 400

    if channel and channel not in valid_channels:
        return jsonify({"error": "Invalid channel filter."}), 400

    try:
        limit = int(request.args.get("limit", 50))
    except (TypeError, ValueError):
        return jsonify({"error": "limit must be an integer."}), 400

    if limit < 1 or limit > 100:
        return jsonify({"error": "limit must be between 1 and 100."}), 400

    query = (
        NotificationDelivery.query
        .join(Alert, NotificationDelivery.alert_id == Alert.id)
    )

    if status:
        query = query.filter(NotificationDelivery.status == status)

    if channel:
        query = query.filter(NotificationDelivery.channel == channel)

    deliveries = (
        query
        .order_by(NotificationDelivery.attempted_at.desc())
        .limit(limit)
        .all()
    )

    return jsonify({
        "deliveries": [
            {
                "id": delivery.id,
                "alert_id": delivery.alert_id,
                "channel": delivery.channel,
                "status": delivery.status,
                "attempt_number": delivery.attempt_number,
                "provider_message_id": delivery.provider_message_id,
                "error_message": delivery.error_message,
                "attempted_at": delivery.attempted_at.isoformat(),
                "delivered_at": (
                    delivery.delivered_at.isoformat()
                    if delivery.delivered_at
                    else None
                ),
                "alert": {
                    "alert_ref": delivery.alert.alert_ref,
                    "event_type": delivery.alert.event_type,
                    "severity": delivery.alert.severity,
                    "title": delivery.alert.title,
                    "created_at": delivery.alert.created_at.isoformat(),
                },
            }
            for delivery in deliveries
        ],
        "count": len(deliveries),
    }), 200


@monitoring_bp.route(
    "/api/alerts/rules/<int:rule_id>",
    methods=["PATCH"],
)
@login_required
def update_alert_rule(rule_id):
    """Update an alert rule or enable/disable it."""
    rule = db.session.get(AlertRule, rule_id)

    if rule is None:
        return jsonify({"error": "Alert rule not found."}), 404

    data = request.get_json(silent=True)

    if not isinstance(data, dict) or not data:
        return jsonify({
            "error": "A non-empty JSON object is required."
        }), 400

    allowed_fields = {
        "name",
        "event_type",
        "min_severity",
        "enabled",
        "cooldown_seconds",
    }

    unknown_fields = set(data) - allowed_fields

    if unknown_fields:
        return jsonify({
            "error": "Unsupported fields.",
            "fields": sorted(unknown_fields),
        }), 400

    # Validate and normalize all values before changing the model.
    updates = {}

    if "name" in data:
        name = data["name"]

        if not isinstance(name, str) or not name.strip():
            return jsonify({
                "error": "name must be a non-empty string."
            }), 400

        name = name.strip()

        if len(name) > 120:
            return jsonify({
                "error": "name must be 120 characters or fewer."
            }), 400

        updates["name"] = name

    if "event_type" in data:
        event_type = data["event_type"]

        if not isinstance(event_type, str) or not event_type.strip():
            return jsonify({
                "error": "event_type must be a non-empty string."
            }), 400

        event_type = event_type.strip().upper()

        if len(event_type) > 60:
            return jsonify({
                "error": "event_type must be 60 characters or fewer."
            }), 400

        updates["event_type"] = event_type

    if "min_severity" in data:
        min_severity = data["min_severity"]
        valid_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

        if min_severity is None:
            updates["min_severity"] = None
        elif isinstance(min_severity, str):
            min_severity = min_severity.strip().upper()

            if min_severity not in valid_severities:
                return jsonify({
                    "error": "Invalid min_severity."
                }), 400

            updates["min_severity"] = min_severity
        else:
            return jsonify({
                "error": "Invalid min_severity."
            }), 400

    if "enabled" in data:
        enabled = data["enabled"]

        if not isinstance(enabled, bool):
            return jsonify({
                "error": "enabled must be true or false."
            }), 400

        updates["enabled"] = enabled

    if "cooldown_seconds" in data:
        cooldown_seconds = data["cooldown_seconds"]

        if (
            isinstance(cooldown_seconds, bool)
            or not isinstance(cooldown_seconds, int)
            or cooldown_seconds < 0
        ):
            return jsonify({
                "error": "cooldown_seconds must be a non-negative integer."
            }), 400

        updates["cooldown_seconds"] = cooldown_seconds

    # Apply only after every supplied field has passed validation.
    for field, value in updates.items():
        setattr(rule, field, value)

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({
            "error": "Could not update alert rule."
        }), 409

    return jsonify({
        "message": "Alert rule updated.",
        "rule": {
            "id": rule.id,
            "rule_key": rule.rule_key,
            "name": rule.name,
            "event_type": rule.event_type,
            "min_severity": rule.min_severity,
            "enabled": rule.enabled,
            "cooldown_seconds": rule.cooldown_seconds,
            "created_at": rule.created_at.isoformat(),
            "updated_at": rule.updated_at.isoformat(),
        },
    }), 200

@monitoring_bp.route("/incidents/<int:incident_id>", methods=["GET"])
@login_required
def incident_detail(incident_id):
    """Display the details and activity history of an incident."""

    incident = IncidentLog.query.get_or_404(incident_id)

    activities = (
        IncidentActivity.query
        .filter_by(incident_id=incident.id)
        .order_by(IncidentActivity.timestamp.desc())
        .all()
    )

    return render_template(
        "incident_detail.html",
        incident=incident,
        activities=activities,
    )

@monitoring_bp.route(
    "/incidents/<int:incident_id>/acknowledge",
    methods=["POST"],
)
@login_required
def acknowledge_incident(incident_id):
    """Acknowledge an open incident and record the action."""

    incident = IncidentLog.query.get_or_404(incident_id)

    if incident.status != "OPEN":
        flash("Only open incidents can be acknowledged.", "warning")
        return redirect(
            url_for(
                "monitoring.incident_detail",
                incident_id=incident.id,
            )
        )

    actor = session.get("username", "admin")
    now = datetime.now()

    incident.status = "ACKNOWLEDGED"
    incident.acknowledged_at = now
    incident.acknowledged_by = actor

    activity = IncidentActivity(
        incident_id=incident.id,
        action="ACKNOWLEDGED",
        actor=actor,
        note="Incident acknowledged for investigation.",
        timestamp=now,
    )

    db.session.add(activity)
    db.session.commit()

    flash("Incident acknowledged successfully.", "success")

    return redirect(
        url_for(
            "monitoring.incident_detail",
            incident_id=incident.id,
        )
    )


@monitoring_bp.route(
    "/incidents/<int:incident_id>/notes",
    methods=["POST"],
)
@login_required
def add_incident_note(incident_id):
    incident = IncidentLog.query.get_or_404(incident_id)

    # Investigation notes are allowed only while investigating.
    if incident.status != "ACKNOWLEDGED":
        flash(
            "Investigation notes can only be added to acknowledged incidents.",
            "warning",
        )
        return redirect(
            url_for(
                "monitoring.incident_detail",
                incident_id=incident.id,
            )
        )

    note = request.form.get("note", "").strip()

    if not note:
        flash("Please enter an investigation note.", "warning")
        return redirect(
            url_for(
                "monitoring.incident_detail",
                incident_id=incident.id,
            )
        )

    if len(note) > 5000:
        flash("Investigation notes must be 5000 characters or fewer.", "warning")
        return redirect(
            url_for(
                "monitoring.incident_detail",
                incident_id=incident.id,
            )
        )

    actor = session.get("username", "admin")
    now = datetime.now()

    activity = IncidentActivity(
        incident_id=incident.id,
        action="NOTE_ADDED",
        actor=actor,
        note=note,
        timestamp=now,
    )

    db.session.add(activity)
    db.session.commit()

    flash("Investigation note added.", "success")
    return redirect(
        url_for(
            "monitoring.incident_detail",
            incident_id=incident.id,
        )
    )


@monitoring_bp.route(
    "/incidents/<int:incident_id>/resolve",
    methods=["POST"],
)
@login_required
def resolve_incident(incident_id):
    incident = IncidentLog.query.get_or_404(incident_id)

    # Only acknowledged incidents can be resolved.
    if incident.status != "ACKNOWLEDGED":
        flash(
            "Only acknowledged incidents can be resolved.",
            "warning",
        )
        return redirect(
            url_for(
                "monitoring.incident_detail",
                incident_id=incident.id,
            )
        )

    reason = request.form.get("reason", "").strip()

    if not reason:
        flash("A resolution reason is required.", "warning")
        return redirect(
            url_for(
                "monitoring.incident_detail",
                incident_id=incident.id,
            )
        )

    if len(reason) > 5000:
        flash("The resolution reason must be 5000 characters or fewer.", "warning")
        return redirect(
            url_for(
                "monitoring.incident_detail",
                incident_id=incident.id,
            )
        )

    actor = session.get("username", "admin")
    now = datetime.now()

    incident.status = "RESOLVED"
    incident.resolved_at = now
    incident.resolved_by = actor
    incident.resolution_note = reason

    activity = IncidentActivity(
        incident_id=incident.id,
        action="RESOLVED",
        actor=actor,
        note=reason,
        timestamp=now,
    )

    db.session.add(activity)
    db.session.commit()

    flash("Incident resolved successfully.", "success")
    return redirect(
        url_for(
            "monitoring.incident_detail",
            incident_id=incident.id,
        )
    )

@monitoring_bp.route("/api/monitor", methods=["GET"])
@login_required
def get_monitor_data():
    """Collect system metrics and evaluate security conditions."""

    global last_ddos_time

    cpu_usage = psutil.cpu_percent(interval=None)
    ram_usage = psutil.virtual_memory().percent

    iot_metrics = system_state["iot_metrics"]
    current_temperature = iot_metrics["temperature"]
    gas_level = iot_metrics["gas_level"]
    motion_detected = iot_metrics["motion"]

    last_update_epoch = iot_metrics.get("last_update_epoch")
    age_seconds = (
        max(0, time.time() - last_update_epoch)
        if isinstance(last_update_epoch, (int, float))
        else None
    )

    if age_seconds is None or age_seconds > 60:
        sensor_status = "OFFLINE"
    elif age_seconds > 10:
        sensor_status = "STALE"
    else:
        sensor_status = "LIVE"

    sensor_live = sensor_status == "LIVE"

    system_state["sensor_health"] = {
        "status": sensor_status,
        "age_seconds": (
            round(age_seconds, 1)
            if age_seconds is not None
            else None
        ),
        "last_seen": iot_metrics.get(
            "last_update",
            "Waiting..."
        ),
    }

    health_transition = record_sensor_health_transition(
        status=sensor_status,
        age_seconds=age_seconds,
        last_seen_epoch=last_update_epoch,
    )



    sensor_incident, sensor_incident_created = (
        sync_sensor_health_incident(
            status=sensor_status,
            age_seconds=age_seconds,
            last_seen=iot_metrics.get(
                "last_update",
                "Waiting..."
            ),
        )
    )


        # Create and dispatch an alert only when sensor health changes.
    if health_transition and sensor_status in {"STALE", "OFFLINE"}:
        try:
            sensor_event_type = (
                "SENSOR STALE"
                if sensor_status == "STALE"
                else "SENSOR OFFLINE"
            )

            sensor_alerts = create_alerts_for_event(
                event_type=sensor_event_type,
                severity=(
                    "MEDIUM"
                    if sensor_status == "STALE"
                    else "HIGH"
                ),
                title=sensor_event_type,
                message=(
                    f"Sensor status changed to {sensor_status}. "
                    f"Last seen: {iot_metrics.get('last_update', 'Unknown')}."
                ),
                source_type="sensor",
                source_key=getattr(
                    health_transition,
                    "sensor_key",
                    "default",
                ),
                incident_id=(
                    sensor_incident.id
                    if sensor_incident
                    else None
                ),
                event_dedup_key=(
                    f"sensor-health-transition:"
                    f"{health_transition.id}"
                ),
            )

            for sensor_alert in sensor_alerts:
                dispatch_alert(sensor_alert.id)

        except Exception:
            logger.exception(
                "Sensor health alerting failed; monitoring continues."
            )



    prediction_message = (
        run_ml_prediction()
        if sensor_live
        else "Sensor data unavailable"
    )

    now = time.time()

    detection, last_ddos_time = evaluate_detection(
        sensor_live=sensor_live,
        gas_level=gas_level,
        temperature=current_temperature,
        motion_detected=motion_detected,
        cpu_usage=cpu_usage,
        last_ddos_time=last_ddos_time,
        now=now,
    )

    alert_message = (
        detection.alert_message
        if detection
        else "SAFE"
    )

    # Reset prototype response controls before applying detections.
    system_state["system_controls"] = {
        "sprinklers": False,
        "alarm": False,
        "door_lock": True,
        "firewall": "Standard",
    }

    if detection:
        system_state["system_controls"].update(
            detection.control_updates
        )

    event_type = detection.event_type if detection else None
    incident = None
    created = False
    # Resolve previous alert incidents when no alert is active.
    if detection is None:
        resolve_open_incidents(
            event_types=list(ALERT_EVENT_TYPES.values())
        )
    else:
        # Resolve any different alert that is no longer active.
        resolve_open_incidents(
            event_types=list(ALERT_EVENT_TYPES.values()),
            except_event_type=event_type,
        )

        incident, created = ensure_open_incident(
            event_type=detection.event_type,
            value=detection.value,
            severity=detection.severity,
            description=detection.description,
        )

        # Send SMS only when a new incident was created.
        # Alert only when a new incident is created.
    if incident and created:
        try:
            detection_alerts = create_alerts_for_event(
                event_type=detection.event_type,
                severity=detection.severity,
                title=detection.event_type,
                message=detection.alert_message,
                source_type="incident",
                source_key=str(getattr(incident, "id", detection.event_type)),
                incident_id=getattr(incident, "id", None),
                event_dedup_key=f"incident-created:{getattr(incident, 'id', detection.event_type)}",
            )

            if detection_alerts:
                for detection_alert in detection_alerts:
                    dispatch_alert(detection_alert.id)
            else:
                # Preserve legacy SMS if no alert rule matches.
                send_sms_alert(detection.alert_message)

        except Exception:
            logger.exception(
                "Detection alerting failed; using legacy SMS fallback."
            )
            send_sms_alert(detection.alert_message)
            


    # --------------------------------------------------------
    # UPDATE DASHBOARD METRICS
    # --------------------------------------------------------

    system_state["security_metrics"].update({
        "cpu_usage": cpu_usage,
        "ram_usage": ram_usage,
        "alert_status": alert_message,
        "ml_prediction": prediction_message
    })

    return jsonify(system_state)

@monitoring_bp.route("/api/report", methods=["GET"])
@login_required
def download_security_report():
    """Generate a trustworthy, current-state SENTRIX security audit PDF."""
    from io import BytesIO
    from datetime import datetime
    import time

    from flask import current_app, send_file
    from app.models.sensor import SensorData
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether,
        PageBreak,
    )
    from xml.sax.saxutils import escape

    buffer = BytesIO()
    generated_at = datetime.now()

    security_metrics = system_state.get("security_metrics", {})
    sensor_metrics = system_state.get("iot_metrics", {})
    dashboard_alert_state = security_metrics.get("alert_status") or "UNKNOWN"

    # Freshness is derived from the last successful telemetry update, not from
    # default sensor values or the cached sensor_health status.
    last_update_epoch = sensor_metrics.get("last_update_epoch")
    try:
        last_update_epoch = float(last_update_epoch)
    except (TypeError, ValueError):
        last_update_epoch = None

    if last_update_epoch is None:
        telemetry_age = None
        telemetry_status = "OFFLINE"
    else:
        telemetry_age = max(0.0, time.time() - last_update_epoch)
        if telemetry_age > 60:
            telemetry_status = "OFFLINE"
        elif telemetry_age > 10:
            telemetry_status = "STALE"
        else:
            telemetry_status = "LIVE"

    operational_health = "HEALTHY" if telemetry_status == "LIVE" else "DEGRADED"

    # Current values are only reported as current when telemetry is live.
    if telemetry_status == "LIVE":
        temperature = sensor_metrics.get("temperature")
        gas_level = sensor_metrics.get("gas_level")
        motion = sensor_metrics.get("motion")
    else:
        temperature = gas_level = motion = None

    # Include the latest persisted reading separately, with its timestamp.
    latest_sensor_record = (
        SensorData.query.order_by(SensorData.timestamp.desc()).first()
    )

    if latest_sensor_record:
        stored_temperature = latest_sensor_record.temperature
        stored_gas = latest_sensor_record.gas
        stored_motion = latest_sensor_record.motion
        stored_timestamp = latest_sensor_record.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        stored_reading = (
            f"Temperature: {stored_temperature:.1f} °C; "
            f"Gas: {stored_gas}; Motion: {stored_motion}"
        )
    else:
        stored_reading = "No sensor reading stored"
        stored_timestamp = "N/A"

    # The open count covers the entire incident table. The register and
    # severity distribution are explicitly scoped to the latest 100 incidents.
    open_count = IncidentLog.query.filter(
        IncidentLog.status.ilike("OPEN")
    ).count()

    incidents = (
        IncidentLog.query
        .order_by(IncidentLog.timestamp.desc())
        .limit(100)
        .all()
    )

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for incident in incidents:
        severity = (incident.severity or "").upper()
        if severity in severity_counts:
            severity_counts[severity] += 1

    # Keep the landscape layout and existing PDF download endpoint.
    document = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=20 * mm,
        bottomMargin=16 * mm,
        title="SENTRIX Security Audit Report",
        author="SENTRIX Security Operations Center",
    )

    styles = getSampleStyleSheet()
    navy = colors.HexColor("#0F172A")
    blue = colors.HexColor("#2563EB")
    pale_blue = colors.HexColor("#EFF6FF")
    border = colors.HexColor("#CBD5E1")
    slate = colors.HexColor("#475569")
    red = colors.HexColor("#B91C1C")
    orange = colors.HexColor("#C2410C")
    green = colors.HexColor("#15803D")

    title_style = ParagraphStyle(
        "SENTRIXTitle", parent=styles["Title"], alignment=TA_CENTER,
        textColor=blue, fontSize=24, leading=28, spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "SENTRIXSubtitle", parent=styles["Normal"], alignment=TA_CENTER,
        fontSize=9, textColor=slate, spaceAfter=12,
    )
    section_style = ParagraphStyle(
        "SENTRIXSection", parent=styles["Heading2"],
        textColor=blue, fontSize=12, spaceBefore=8, spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "SENTRIXBody", parent=styles["Normal"], fontSize=8.5,
        leading=11, textColor=navy,
    )
    small_style = ParagraphStyle(
        "SENTRIXSmall", parent=body_style, fontSize=7.5,
        leading=9, textColor=slate,
    )
    table_cell_style = ParagraphStyle(
        "SENTRIXTableCell", parent=body_style, fontSize=7.5,
        leading=9, wordWrap="CJK",
    )
    table_header_style = ParagraphStyle(
        "SENTRIXTableHeader", parent=table_cell_style,
        textColor=colors.white, fontName="Helvetica-Bold",
    )

    def para(value, style=table_cell_style):
        # Preserve valid zero values; only None/empty text means unavailable.
        if value is None or value == "":
            value = "N/A"
        return Paragraph(escape(str(value)), style)

    def percent_value(value):
        if value is None or value == "":
            return "N/A"
        try:
            return f"{float(value):.1f}%"
        except (TypeError, ValueError):
            return "N/A"

    if isinstance(temperature, (int, float)) and not isinstance(temperature, bool):
        temperature_display = f"{temperature:.1f} °C"
    else:
        temperature_display = "N/A"

    if isinstance(gas_level, (int, float)) and not isinstance(gas_level, bool):
        gas_display = str(gas_level)
    else:
        gas_display = "N/A"

    if motion == 1:
        motion_display = "DETECTED"
    elif motion == 0:
        motion_display = "NONE"
    else:
        motion_display = "N/A"

    story = [
        Paragraph("SENTRIX", title_style),
        Paragraph("Integrated IT/OT Security Operations Center", subtitle_style),
        Paragraph("Security Audit Report", styles["Heading1"]),
        Paragraph(
            f"Generated: {generated_at.strftime('%Y-%m-%d %H:%M:%S')}",
            styles["Normal"],
        ),
        Spacer(1, 5 * mm),
        Paragraph("Executive Summary", section_style),
        Paragraph(
            "The dashboard alert state and operational telemetry health are "
            "reported separately. A SAFE dashboard alert state does not prove "
            "that the monitored environment is safe when telemetry is stale "
            "or unavailable.",
            body_style,
        ),
        Spacer(1, 3 * mm),
    ]

    # KPI strip: 100-entry scope is explicit; open count is database-wide.
    kpi_data = [
        [para("INCIDENTS IN REGISTER", small_style),
         para("OPEN INCIDENTS (ALL)", small_style),
         para("CRITICAL IN REGISTER", small_style),
         para("HIGH IN REGISTER", small_style)],
        [para(len(incidents), body_style),
         para(open_count, body_style),
         para(severity_counts["CRITICAL"], body_style),
         para(severity_counts["HIGH"], body_style)],
    ]
    kpi_table = Table(kpi_data, colWidths=[66.75 * mm] * 4)
    kpi_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), pale_blue),
        ("BOX", (0, 0), (-1, -1), 0.7, border),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, border),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.extend([kpi_table, Spacer(1, 4 * mm)])

    story.append(Paragraph("Current System Status", section_style))

    # Compact four-column status matrix keeps the complete summary on page 1.
    status_rows = [
        [
            para("Metric", table_header_style), para("Value", table_header_style),
            para("Metric", table_header_style), para("Value", table_header_style),
        ],
        [
            para("Dashboard alert state"), para(dashboard_alert_state),
            para("Operational health"), para(operational_health),
        ],
        [
            para("Telemetry status"), para(telemetry_status),
            para("Telemetry age"),
            para(f"{telemetry_age:.1f} sec" if telemetry_age is not None else "N/A"),
        ],
        [
            para("Temperature"), para(temperature_display),
            para("Gas level"), para(gas_display),
        ],
        [
            para("Motion"), para(motion_display),
            para("CPU usage"), para(percent_value(security_metrics.get("cpu_usage"))),
        ],
        [
            para("RAM usage"), para(percent_value(security_metrics.get("ram_usage"))),
            para("Stored reading time"), para(stored_timestamp),
        ],
        [
            para("Last stored sensor reading"), para(stored_reading), para(""), para(""),
        ],
    ]
    status_table = Table(
        status_rows,
        colWidths=[37 * mm, 46 * mm, 37 * mm, 68 * mm],
        repeatRows=1,
        splitByRow=1,
    )
    status_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), navy),
        ("GRID", (0, 0), (-1, -1), 0.45, border),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F8FAFC")),
        ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#F1F5F9")),
        ("BACKGROUND", (2, 1), (2, -1), colors.HexColor("#F1F5F9")),
        ("SPAN", (1, 6), (3, 6)),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    note = (
        "N/A indicates unavailable current data. Stored readings are historical, "
        "not live telemetry; numeric zero is a valid reading."
    )

    # Place severity beside system status on page 1. This removes the mostly
    # empty severity-only page while preserving the same severity counts.
    severity_rows = [
        [para("Severity", table_header_style), para("Count", table_header_style)],
        [para("CRITICAL"), para(severity_counts["CRITICAL"])],
        [para("HIGH"), para(severity_counts["HIGH"])],
        [para("MEDIUM"), para(severity_counts["MEDIUM"])],
        [para("LOW"), para(severity_counts["LOW"])],
        [para("TOTAL"), para(len(incidents))],
    ]
    severity_table = Table(severity_rows, colWidths=[48 * mm, 25 * mm])
    severity_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), navy),
        ("GRID", (0, 0), (-1, -1), 0.45, border),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (1, 1), (1, -1), "CENTER"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))

    status_severity = Table(
        [[status_table, severity_table]],
        colWidths=[188 * mm, 78 * mm],
        hAlign="LEFT",
    )
    status_severity.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.extend([
        status_severity,
        Spacer(1, 1.5 * mm),
        Paragraph(note, small_style),
        Spacer(1, 2.5 * mm),
    ])

    # Keep the register flowing naturally after the executive overview.
    # The incident table repeats its header when it continues on a new page.
    register_intro = KeepTogether([
        Paragraph("Incident Register", section_style),
        Paragraph(
            "Latest 100 incidents, ordered newest first. Descriptions are shown "
            "as recorded in SENTRIX.",
            small_style,
        ),
        Spacer(1, 1.5 * mm),
    ])
    story.append(register_intro)
    incident_rows = [[
        para("Timestamp", table_header_style),
        para("Reference", table_header_style),
        para("Event", table_header_style),
        para("Severity", table_header_style),
        para("Status", table_header_style),
        para("Description", table_header_style),
    ]]

    for incident in incidents:
        incident_rows.append([
            para(incident.timestamp.strftime("%Y-%m-%d %H:%M:%S")),
            para((incident.incident_ref or "")[:8]),
            para(incident.event_type),
            para((incident.severity or "UNKNOWN").upper()),
            para((incident.status or "UNKNOWN").upper()),
            para(incident.description or "No description provided"),
        ])

    if not incidents:
        incident_rows.append([
            para("No incidents recorded"), para(""), para(""),
            para(""), para(""), para(""),
        ])

    incident_table = Table(
        incident_rows,
        colWidths=[32 * mm, 22 * mm, 52 * mm, 19 * mm, 30 * mm, 112 * mm],
        repeatRows=1,
    )
    incident_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), navy),
        ("GRID", (0, 0), (-1, -1), 0.45, border),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 1.4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.4),
        ("FONTSIZE", (0, 0), (-1, -1), 7.2),
    ]))
    story.append(incident_table)

    def draw_page(canvas, doc):
        canvas.saveState()
        page_width, page_height = landscape(A4)
        canvas.setStrokeColor(border)
        canvas.setLineWidth(0.6)
        canvas.line(15 * mm, page_height - 13 * mm, page_width - 15 * mm, page_height - 13 * mm)
        canvas.setFont("Helvetica-Bold", 8.5)
        canvas.setFillColor(blue)
        canvas.drawString(15 * mm, page_height - 10 * mm, "SENTRIX")
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(slate)
        canvas.drawRightString(page_width - 15 * mm, page_height - 10 * mm, "SECURITY AUDIT REPORT")
        canvas.line(15 * mm, 12 * mm, page_width - 15 * mm, 12 * mm)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(15 * mm, 8 * mm, "Confidential • Internal Security Report")
        canvas.drawRightString(page_width - 15 * mm, 8 * mm, f"Page {doc.page}")
        canvas.restoreState()

    document.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
    buffer.seek(0)

    current_app.logger.info("SENTRIX Security Audit report generated.")
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="SENTRIX_Security_Audit.pdf",
    )
