"""Security analytics API routes for SENTRIX."""

from datetime import datetime, time

from flask import Blueprint, jsonify, request

from app.auth.decorators import login_required
from app.services.analytics import get_incident_analytics
from app.services.sensor_health_analytics import (
    get_sensor_health_analytics,
)

analytics_bp = Blueprint("analytics", __name__)


@analytics_bp.route("/api/analytics/incidents", methods=["GET"])
@login_required
def incident_analytics():
    """Return filtered incident analytics as JSON."""

    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    severity = request.args.get("severity", "").strip().upper()
    event_type = request.args.get("event_type", "").strip()
    status = request.args.get("status", "").strip().upper()

    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    valid_statuses = {"OPEN", "ACKNOWLEDGED", "RESOLVED"}

    if severity and severity not in valid_severities:
        return jsonify({
            "error": "Invalid severity filter."
        }), 400

    if status and status not in valid_statuses:
        return jsonify({
            "error": "Invalid status filter."
        }), 400

    try:
        parsed_start = (
            datetime.combine(
                datetime.strptime(start_date, "%Y-%m-%d").date(),
                time.min,
            )
            if start_date
            else None
        )

        parsed_end = (
            datetime.combine(
                datetime.strptime(end_date, "%Y-%m-%d").date(),
                time.max,
            )
            if end_date
            else None
        )

    except ValueError:
        return jsonify({
            "error": "Dates must use YYYY-MM-DD format."
        }), 400

    if parsed_start and parsed_end and parsed_start > parsed_end:
        return jsonify({
            "error": "start_date must not be after end_date."
        }), 400

    analytics = get_incident_analytics(
        start_date=parsed_start,
        end_date=parsed_end,
        severity=severity or None,
        event_type=event_type or None,
        status=status or None,
    )

    return jsonify(analytics)

@analytics_bp.route("/api/analytics/sensors", methods=["GET"])
@login_required
def sensor_health_analytics():
    """Return sensor health history and uptime/offline analytics."""

    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")

    try:
        parsed_start = (
            datetime.combine(
                datetime.strptime(start_date, "%Y-%m-%d").date(),
                time.min,
            )
            if start_date
            else None
        )

        parsed_end = (
            datetime.combine(
                datetime.strptime(end_date, "%Y-%m-%d").date(),
                time.max,
            )
            if end_date
            else None
        )

    except ValueError:
        return jsonify({
            "error": "Dates must use YYYY-MM-DD format."
        }), 400

    if parsed_start and parsed_end and parsed_start > parsed_end:
        return jsonify({
            "error": "start_date must not be after end_date."
        }), 400

    analytics = get_sensor_health_analytics(
        start_date=parsed_start,
        end_date=parsed_end,
    )

    return jsonify(analytics)
