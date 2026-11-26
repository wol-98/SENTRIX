"""Security monitoring routes for SENTRIX."""

from io import BytesIO
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

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
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
    """Generate and download the SENTRIX Security Audit PDF."""

    buffer = BytesIO()

    generated_at = datetime.now()
    current_status = system_state["security_metrics"].get(
        "alert_status", "UNKNOWN"
    )

    sensor_metrics = system_state["iot_metrics"]

    # Retrieve the latest 100 incidents.
    incidents = (
        IncidentLog.query
        .order_by(IncidentLog.timestamp.desc())
        .limit(100)
        .all()
    )

    # Count incidents by severity.
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for incident in incidents:
        severity = incident.severity.upper()

        if severity in severity_counts:
            severity_counts[severity] += 1

    # Create PDF document.
    document = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title="SENTRIX Security Audit Report",
        author="SENTRIX Security Operations Center",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "SENTRIXTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        textColor=colors.HexColor("#2563EB"),
        fontSize=22,
        spaceAfter=6,
    )

    subtitle_style = ParagraphStyle(
        "SENTRIXSubtitle",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        fontSize=10,
        textColor=colors.HexColor("#64748B"),
        spaceAfter=18,
    )

    section_style = ParagraphStyle(
        "SENTRIXSection",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#1D4ED8"),
        spaceBefore=12,
        spaceAfter=8,
    )

    story = []

    story.append(Paragraph("SENTRIX", title_style))
    story.append(
        Paragraph(
            "Integrated IT/OT Security Operations Center",
            subtitle_style,
        )
    )

    story.append(
        Paragraph("Security Audit Report", styles["Heading1"])
    )

    story.append(
        Paragraph(
            f"Generated: {generated_at.strftime('%Y-%m-%d %H:%M:%S')}",
            styles["Normal"],
        )
    )

    story.append(Spacer(1, 8 * mm))

    # Current system summary.
    story.append(
        Paragraph("Current System Status", section_style)
    )

    status_data = [
        ["Metric", "Current Value"],
        ["Security Status", str(current_status)],
        [
            "Temperature",
            f"{sensor_metrics.get('temperature', 0)} °C",
        ],
        [
            "Gas Level",
            str(sensor_metrics.get("gas_level", 0)),
        ],
        [
            "Motion",
            (
                "DETECTED"
                if sensor_metrics.get("motion", 0) == 1
                else "NONE"
            ),
        ],
        [
            "CPU Usage",
            f"{system_state['security_metrics'].get('cpu_usage', 0)}%",
        ],
        [
            "RAM Usage",
            f"{system_state['security_metrics'].get('ram_usage', 0)}%",
        ],
    ]

    status_table = Table(
        status_data,
        colWidths=[55 * mm, 100 * mm],
    )

    status_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F8FAFC")),
            ("PADDING", (0, 0), (-1, -1), 7),
        ])
    )

    story.append(status_table)
    story.append(Spacer(1, 8 * mm))

    # Incident severity summary.
    story.append(
        Paragraph("Incident Summary", section_style)
    )

    severity_data = [
        ["Severity", "Count"],
        ["Critical", str(severity_counts["CRITICAL"])],
        ["High", str(severity_counts["HIGH"])],
        ["Medium", str(severity_counts["MEDIUM"])],
        ["Low", str(severity_counts["LOW"])],
        ["Total Included", str(len(incidents))],
    ]

    severity_table = Table(
        severity_data,
        colWidths=[55 * mm, 35 * mm],
    )

    severity_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("PADDING", (0, 0), (-1, -1), 7),
        ])
    )

    story.append(severity_table)
    story.append(Spacer(1, 8 * mm))

    # Incident details.
    story.append(
        Paragraph("Recent Security Incidents", section_style)
    )

    incident_data = [[
        "Timestamp",
        "Reference",
        "Event",
        "Severity",
        "Status",
        "Description",
    ]]

    for incident in incidents:
        incident_data.append([
            incident.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            incident.incident_ref[:8],
            incident.event_type,
            incident.severity,
            incident.status,
            incident.description or "",
        ])

    if not incidents:
        incident_data.append([
            "No incidents recorded",
            "",
            "",
            "",
            "",
            "",
        ])

    incident_table = Table(
        incident_data,
        colWidths=[
            32 * mm,
            22 * mm,
            35 * mm,
            22 * mm,
            22 * mm,
            95 * mm,
        ],
        repeatRows=1,
    )

    incident_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ])
    )

    story.append(incident_table)

    # Build PDF.
    document.build(story)

    buffer.seek(0)

    current_app.logger.info(
        "SENTRIX Security Audit report generated."
    )

    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="SENTRIX_Security_Audit.pdf",
    )
