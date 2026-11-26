"""Security analytics calculations for SENTRIX."""

from collections import Counter

from app.models import IncidentLog


def get_incident_analytics(
    start_date=None,
    end_date=None,
    severity=None,
    event_type=None,
    status=None,
):
    """Return filtered incident analytics and response-time metrics.

    Date filters are inclusive.
    MTTA and MTTR are calculated only when their corresponding
    timestamps exist and produce a non-negative duration.
    """

    query = IncidentLog.query

    if start_date is not None:
        query = query.filter(IncidentLog.timestamp >= start_date)

    if end_date is not None:
        query = query.filter(IncidentLog.timestamp <= end_date)

    if severity:
        query = query.filter(
            IncidentLog.severity == severity.upper()
        )

    if event_type:
        query = query.filter(
            IncidentLog.event_type == event_type
        )

    if status:
        query = query.filter(
            IncidentLog.status == status.upper()
        )

    incidents = query.order_by(IncidentLog.timestamp.asc()).all()

    status_counts = Counter(
        incident.status.upper() for incident in incidents
    )
    severity_counts = Counter(
        incident.severity.upper() for incident in incidents
    )
    event_type_counts = Counter(
        incident.event_type for incident in incidents
    )

    mtta_seconds = []
    mttr_seconds = []

    for incident in incidents:
        if incident.acknowledged_at:
            duration = (
                incident.acknowledged_at - incident.timestamp
            ).total_seconds()

            if duration >= 0:
                mtta_seconds.append(duration)

        if incident.resolved_at:
            duration = (
                incident.resolved_at - incident.timestamp
            ).total_seconds()

            if duration >= 0:
                mttr_seconds.append(duration)

    daily_counts = Counter(
        incident.timestamp.date().isoformat()
        for incident in incidents
    )

    def average_minutes(durations):
        if not durations:
            return None

        return round(
            sum(durations) / len(durations) / 60,
            2,
        )

    return {
        "total_incidents": len(incidents),
        "status_counts": dict(status_counts),
        "severity_counts": dict(severity_counts),
        "event_type_counts": dict(event_type_counts),
        "daily_trends": [
            {"date": day, "count": count}
            for day, count in sorted(daily_counts.items())
        ],
        "response_performance": {
            "mtta_minutes": average_minutes(mtta_seconds),
            "mttr_minutes": average_minutes(mttr_seconds),
            "mtta_sample_size": len(mtta_seconds),
            "mttr_sample_size": len(mttr_seconds),
        },
    }
