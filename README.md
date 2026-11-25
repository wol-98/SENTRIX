# SENTRIX

### Intelligent Security Monitoring & Threat Response Platform

SENTRIX is an evolving security monitoring platform designed to bring IoT telemetry, endpoint monitoring, threat detection, analytics, and incident response into a unified security operations environment.

## Vision

To provide a modular and extensible platform for monitoring connected systems, identifying suspicious activity, analysing security events, and supporting informed incident response.

## Core Capabilities

- IoT sensor telemetry collection
- Device and system monitoring
- Security event logging
- API authentication
- Anomaly detection and analytics
- Incident monitoring and reporting
- Alert and notification integration

## Technology Stack

- **Backend:** Python, Flask
- **Database:** SQLite (initial implementation)
- **ORM:** Flask-SQLAlchemy
- **Analytics:** NumPy, scikit-learn
- **Frontend:** HTML, CSS, JavaScript, Chart.js
- **Testing:** Python unittest

## Project Structure

```text
SENTRIX/
├── config.py
├── server.py
├── smart_sensor.py
├── test_suite.py
├── ddos_attack.py
├── requirements.txt
├── templates/
├── instance/
└── docs/
```

## Development Status

SENTRIX is under active modernization. Development is currently focused on security foundations, backend architecture, telemetry validation, and automated testing.

Physical IoT hardware integration will follow the software development phase.

## Getting Started

Clone the repository:

```bash
git clone https://github.com/wol-98/sentrix.git
cd sentrix
```

Create and activate a virtual environment, install dependencies, configure environment variables using `.env.example`, and run the application using the documented development configuration.

## Project Direction

SENTRIX is being developed incrementally toward a modular security operations platform.

---

**SENTRIX — Monitor. Detect. Understand. Respond.**
