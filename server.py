
"""SENTRIX application entry point."""

from datetime import datetime

from fpdf import FPDF
from flask import jsonify, render_template, send_file

from config import Config
from app import create_app
from app.auth.decorators import login_required
from app.extensions import db
from app.core.state import system_state
from app.models import SensorData, IncidentLog


app = create_app()

# ============================================================
# SECURITY REPORT
# ============================================================

@app.route("/api/report", methods=["GET"])
@login_required
def download_report():
    """Generate and download a SENTRIX security report."""

    incidents = (
        IncidentLog.query
        .order_by(IncidentLog.timestamp.desc())
        .all()
    )

    if not incidents:
        return jsonify({"error": "No logs found"}), 404

    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Arial", style="B", size=16)
    pdf.cell(
        0, 10,
        "SENTRIX - Security Monitoring & Incident Report",
        ln=True,
        align="C"
    )

    pdf.set_font("Arial", size=10)
    pdf.cell(
        0, 10,
        f"Generated on: {datetime.now():%Y-%m-%d %H:%M:%S}",
        ln=True,
        align="C"
    )

    pdf.ln(10)

    total_incidents = len(incidents)

    fire_incidents = sum(
        1 for incident in incidents
        if "FIRE" in incident.event_type
    )

    ddos_incidents = sum(
        1 for incident in incidents
        if (
            "DDoS" in incident.event_type
            or "RESOURCE" in incident.event_type
        )
    )

    malware_incidents = sum(
        1 for incident in incidents
        if "MALWARE" in incident.event_type
    )

    pdf.set_font("Arial", style="B", size=12)
    pdf.cell(0, 10, "Executive Summary:", ln=True)

    pdf.set_font("Arial", size=11)

    summary = [
        f"Total Security Incidents: {total_incidents}",
        f"Fire/Hazard Alerts: {fire_incidents}",
        f"DDoS/Resource Alerts: {ddos_incidents}",
        f"Malware Alerts: {malware_incidents}",
    ]

    for item in summary:
        pdf.cell(0, 8, f"- {item}", ln=True)

    pdf.ln(10)

    pdf.set_font("Arial", style="B", size=10)
    pdf.set_fill_color(200, 220, 255)

    headers = [
        ("Timestamp", 50),
        ("Event Type", 50),
        ("Value", 50),
        ("Status", 40),
    ]

    for label, width in headers:
        pdf.cell(width, 10, label, border=1, align="C", fill=True)

    pdf.ln()

    pdf.set_font("Arial", size=9)

    for incident in incidents[:20]:
        values = [
            (str(incident.timestamp), 50),
            (incident.event_type, 50),
            (incident.value, 50),
            (incident.status, 40),
        ]

        for value, width in values:
            pdf.cell(width, 10, str(value)[:35], border=1)

        pdf.ln()

    report_filename = "SENTRIX_Security_Report.pdf"
    pdf.output(report_filename)

    return send_file(report_filename, as_attachment=True)


# ============================================================
# APPLICATION ENTRY POINT
# ============================================================

if __name__ == "__main__":

    Config.validate()

    with app.app_context():
        db.create_all()

        latest_reading = (
            SensorData.query
            .order_by(SensorData.timestamp.desc(), SensorData.id.desc())
            .first()
        )

        if latest_reading:
            system_state["iot_metrics"].update({
                "temperature": latest_reading.temperature,
                "gas_level": latest_reading.gas,
                "motion": latest_reading.motion,
                "last_update": latest_reading.timestamp.strftime("%H:%M:%S"),
                "last_update_epoch": latest_reading.timestamp.timestamp(),
            })

        print("SENTRIX database initialized.")

    print("SENTRIX Security Platform starting on port 5001.")

    app.run(
        host="0.0.0.0",
        port=5001,
        debug=app.config["DEBUG"]
    )
