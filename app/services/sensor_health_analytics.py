"""Analytics for SENTRIX sensor health history."""

from datetime import datetime

from app.models import SensorHealthHistory


def get_sensor_health_analytics(
    start_date=None,
    end_date=None,
    sensor_key="default",
    now=None,
):
    """Summarize sensor status history and known uptime/offline periods."""

    now = now or datetime.now()

    records = (
        SensorHealthHistory.query
        .filter_by(sensor_key=sensor_key)
        .order_by(
            SensorHealthHistory.changed_at.asc(),
            SensorHealthHistory.id.asc(),
        )
        .all()
    )

    if not records:
        return {
            "sensor_key": sensor_key,
            "current_status": None,
            "history": [],
            "outages": {
                "count": 0,
                "completed_count": 0,
                "ongoing": False,
                "total_offline_seconds": 0,
                "ongoing_seconds": None,
            },
            "uptime": {
                "percentage": None,
                "known_seconds": 0,
                "online_seconds": 0,
                "offline_seconds": 0,
            },
        }

    current_record = max(
        records,
        key=lambda item: (item.recorded_at, item.id),
    )

    period_start = start_date or records[0].changed_at
    period_end = min(end_date, now) if end_date else now

    if period_end < period_start:
        period_end = period_start

    history = [
        {
            "status": item.status,
            "changed_at": item.changed_at.isoformat(),
            "recorded_at": item.recorded_at.isoformat(),
            "last_seen_at": (
                item.last_seen_at.isoformat()
                if item.last_seen_at
                else None
            ),
            "age_seconds": item.age_seconds,
        }
        for item in records
        if (
            (start_date is None or item.changed_at >= start_date)
            and (end_date is None or item.changed_at <= end_date)
        )
    ]

    online_seconds = 0.0
    offline_seconds = 0.0
    total_offline_seconds = 0.0
    completed_outages = 0
    ongoing_seconds = None
    ongoing_outage = False

    for index, item in enumerate(records):
        interval_start = item.changed_at

        next_record = (
            records[index + 1]
            if index + 1 < len(records)
            else None
        )

        if next_record:
            interval_end = next_record.changed_at
            is_current_interval = False
        else:
            interval_end = now
            is_current_interval = item.status == "OFFLINE"

        # Clip each interval to the requested period.
        clipped_start = max(interval_start, period_start)
        clipped_end = min(interval_end, period_end)

        if clipped_end <= clipped_start:
            continue

        duration = (clipped_end - clipped_start).total_seconds()

        if item.status == "OFFLINE":
            # Without last_seen_at, the initial outage start is unknown.
            if item.last_seen_at is None:
                continue

            offline_seconds += duration
            total_offline_seconds += duration

            recovered_within_period = (
                next_record is not None
                and next_record.status != "OFFLINE"
                and next_record.changed_at <= period_end
            )

            if recovered_within_period:
                completed_outages += 1
            elif is_current_interval:
                ongoing_outage = True
                ongoing_seconds = duration

        else:
            online_seconds += duration

    known_seconds = online_seconds + offline_seconds

    uptime_percentage = (
        round(online_seconds / known_seconds * 100, 2)
        if known_seconds > 0
        else None
    )

    return {
        "sensor_key": sensor_key,
        "current_status": current_record.status,
        "history": history,
        "outages": {
            "count": completed_outages + int(ongoing_outage),
            "completed_count": completed_outages,
            "ongoing": ongoing_outage,
            "total_offline_seconds": round(
                total_offline_seconds,
                1,
            ),
            "ongoing_seconds": (
                round(ongoing_seconds, 1)
                if ongoing_seconds is not None
                else None
            ),
        },
        "uptime": {
            "percentage": uptime_percentage,
            "known_seconds": round(known_seconds, 1),
            "online_seconds": round(online_seconds, 1),
            "offline_seconds": round(offline_seconds, 1),
        },
    }
