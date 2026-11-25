import hmac
from functools import wraps

from flask import current_app, jsonify, request


def require_api_key(view_function):
    """Protect API endpoints using API-key authentication."""

    @wraps(view_function)
    def decorated_function(*args, **kwargs):
        expected_key = current_app.config.get("API_SECRET_KEY")
        provided_key = request.headers.get("X-API-Key", "")

        if (
            not expected_key
            or not hmac.compare_digest(provided_key, expected_key)
        ):
            return jsonify({
                "error": "Unauthorized Access"
            }), 403

        return view_function(*args, **kwargs)

    return decorated_function
