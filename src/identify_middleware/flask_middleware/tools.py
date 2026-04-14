#    Copyright 2025 FAO
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
#    Author: Carlo Cancellieri (ccancellieri@gmail.com)
#    Company: FAO, Viale delle Terme di Caracalla, 00100 Rome, Italy
#    Contact: copyright@fao.org - http://fao.org/contact-us/terms/en/
# File: middleware/tools.py

"""
Developer Tools and Helpers for the Identify Middleware.

This module provides framework-specific tools to make it easier to
access the authenticated user's identity within your application endpoints.
"""

import logging
from functools import wraps

from flask import g, abort

logger = logging.getLogger(__name__)

# --- Flask Tools (Decorators) ---

def flask_require_auth(f):
    """
    Flask decorator to require an authenticated user.
    
    If no user is found on `g.user`, it aborts with a 401.
    
    Usage:
        @app.route("/secure-data")
        @flask_require_auth
        def get_secure_data():
            # g.user is guaranteed to be a valid UserIdentity
            return jsonify(message=f"Secure data for {g.user.email}")
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not hasattr(g, "user") or not g.user:
            logger.warning("flask_require_auth: No user found, aborting 401.")
            abort(401, description="Not authenticated")
        return f(*args, **kwargs)
    return decorated_function


def require_auth(func):
    """Decorator to protect a Flask route, requiring an authenticated user."""
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not g.get("user"):
            abort(401, description="Authentication required")
        return func(*args, **kwargs)
    return decorated_function
