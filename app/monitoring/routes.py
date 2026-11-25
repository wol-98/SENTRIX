
"""Security monitoring routes for SENTRIX."""

from io import BytesIO
from datetime import datetime

from flask import send_file, current_app

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

from app.models import IncidentLog

import time

import psutil
from flask import Blueprint, jsonify

from app.auth.decorators import login_required
from app.core.state import system_state
from app.services.notifications import send_sms_alert
from app.services.intelligence import run_ml_prediction
from app.services.incidents import (
    ensure_open_incident,
    resolve_open_incidents,
    sync_sensor_health_incident,
)

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
    prediction_message = (
        run_ml_prediction()
        if sensor_live
        else "Sensor data unavailable"
    )

    alert_message = "SAFE"

    # Reset prototype response controls before evaluating alerts.
    system_state["system_controls"] = {
        "sprinklers": False,
        "alarm": False,
        "door_lock": True,
        "firewall": "Standard"
    }

    # --------------------------------------------------------
    # FIRE AND GAS DETECTION
    # --------------------------------------------------------

    if sensor_live and gas_level > 1000:

        alert_message = "DANGER: FIRE - DEFENSE ACTIVE"

        system_state["system_controls"].update({
            "sprinklers": True,
            "door_lock": False,
            "alarm": True
        })

    # --------------------------------------------------------
    # RESOURCE ANOMALY / MALWARE HEURISTIC
    # --------------------------------------------------------

    elif (
        sensor_live
        and cpu_usage > 50
        and current_temperature > 30
        and gas_level < 500
    ):

        alert_message = "MALWARE: CRYPTO-MINER DETECTED"

        system_state["system_controls"]["firewall"] = (
            "PROCESS ALERT"
        )

    # --------------------------------------------------------
    # RESOURCE SPIKE HEURISTIC
    # --------------------------------------------------------

    elif (
        cpu_usage > 40
        or (time.time() - last_ddos_time < 5)
    ):

        if cpu_usage > 40:
            last_ddos_time = time.time()

        alert_message = (
            "CRITICAL: RESOURCE SPIKE - "
            "INVESTIGATION REQUIRED"
        )

        system_state["system_controls"]["firewall"] = (
            "TRAFFIC REVIEW"
        )

    # --------------------------------------------------------
    # MOTION / INTRUSION DETECTION
    # -------------------------------------------------------

    elif sensor_live and motion_detected == 1:

        alert_message = "INTRUSION: MOTION DETECTED"

        system_state["system_controls"]["alarm"] = True

    # --------------------------------------------------------
    # ALERT TRANSITION HANDLING
    # --------------------------------------------------------



    # --------------------------------------------------------
    # PERSISTENT ALERT / INCIDENT HANDLING
    # --------------------------------------------------------

    event_type = ALERT_EVENT_TYPES.get(alert_message)

    # When no alert is active, resolve previous open incidents.
    if alert_message == "SAFE":

        resolve_open_incidents(
            event_types=list(ALERT_EVENT_TYPES.values())
        )

    else:
        # Resolve any different alert that is no longer active.
        resolve_open_incidents(
            event_types=list(ALERT_EVENT_TYPES.values()),
            except_event_type=event_type,
        )

        incident_details = {
            "FIRE DETECTED": {
                "value": f"Gas: {gas_level}",
                "severity": "CRITICAL",
                "description": (
                    "Gas concentration exceeded the "
                    "configured safety threshold."
                ),
            },
            "MALWARE DETECTED": {
                "value": (
                    f"CPU: {cpu_usage}% | "
                    f"Temp: {current_temperature} C"
                ),
                "severity": "CRITICAL",
                "description": (
                    "Possible cryptomining activity detected "
                    "through abnormal CPU usage and temperature."
                ),
            },
            "DDoS SUSPECTED": {
                "value": f"CPU: {cpu_usage}%",
                "severity": "HIGH",
                "description": (
                    "Abnormally high CPU usage detected. "
                    "Possible resource exhaustion or "
                    "network traffic anomaly."
                ),
            },
            "INTRUSION DETECTED": {
                "value": "Motion: 1",
                "severity": "HIGH",
                "description": (
                    "Motion sensor detected unexpected movement."
                ),
            },
        }

        details = incident_details.get(event_type)

        if details:
            incident, created = ensure_open_incident(
                event_type=event_type,
                value=details["value"],
                severity=details["severity"],
                description=details["description"],
            )

            # Send SMS only when a new incident was created.
            if incident and created:
                send_sms_alert(alert_message)

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
