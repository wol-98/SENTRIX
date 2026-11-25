"""Rule-based detection engine for SENTRIX."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Detection:
    rule_id: str
    alert_message: str
    event_type: str
    severity: str
    value: str
    description: str
    control_updates: dict


def evaluate_detection(
    *,
    sensor_live,
    gas_level,
    temperature,
    motion_detected,
    cpu_usage,
    last_ddos_time,
    now,
):
    """
    Evaluate SENTRIX detection rules in priority order.

    Returns:
        tuple[Detection | None, float]:
            The matched detection, if any, and updated DDoS timestamp.
    """

    # Rule 1: Fire / gas detection
    if sensor_live and gas_level > 1000:
        return Detection(
            rule_id="DET-FIRE-001",
            alert_message="DANGER: FIRE - DEFENSE ACTIVE",
            event_type="FIRE DETECTED",
            severity="CRITICAL",
            value=f"Gas: {gas_level}",
            description=(
                "Gas concentration exceeded the "
                "configured safety threshold."
            ),
            control_updates={
                "sprinklers": True,
                "door_lock": False,
                "alarm": True,
            },
        ), last_ddos_time

    # Rule 2: Cryptomining heuristic
    if (
        sensor_live
        and cpu_usage > 50
        and temperature > 30
        and gas_level < 500
    ):
        return Detection(
            rule_id="DET-MALWARE-001",
            alert_message="MALWARE: CRYPTO-MINER DETECTED",
            event_type="MALWARE DETECTED",
            severity="CRITICAL",
            value=f"CPU: {cpu_usage}% | Temp: {temperature} C",
            description=(
                "Possible cryptomining activity detected "
                "through abnormal CPU usage and temperature."
            ),
            control_updates={
                "firewall": "PROCESS ALERT",
            },
        ), last_ddos_time

    # Rule 3: Resource spike heuristic
    if cpu_usage > 40:
        last_ddos_time = now

    if cpu_usage > 40 or (now - last_ddos_time < 5):
        return Detection(
            rule_id="DET-RESOURCE-001",
            alert_message=(
                "CRITICAL: RESOURCE SPIKE - "
                "INVESTIGATION REQUIRED"
            ),
            event_type="DDoS SUSPECTED",
            severity="HIGH",
            value=f"CPU: {cpu_usage}%",
            description=(
                "Abnormally high CPU usage detected. "
                "Possible resource exhaustion or "
                "network traffic anomaly."
            ),
            control_updates={
                "firewall": "TRAFFIC REVIEW",
            },
        ), last_ddos_time

    # Rule 4: Motion / intrusion detection
    if sensor_live and motion_detected == 1:
        return Detection(
            rule_id="DET-INTRUSION-001",
            alert_message="INTRUSION: MOTION DETECTED",
            event_type="INTRUSION DETECTED",
            severity="HIGH",
            value="Motion: 1",
            description=(
                "Motion sensor detected unexpected movement."
            ),
            control_updates={
                "alarm": True,
            },
        ), last_ddos_time

    return None, last_ddos_time
