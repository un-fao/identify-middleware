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

"""
Flask Identity Middleware

This module provides a Flask-compatible identity middleware that integrates
with the IdentityValidator classes.
"""

import logging
from identify_middleware.shared.models import UserIdentity
from identify_middleware.shared.validators import IdentityValidator
from typing import Optional, List

from flask import Flask, request, g, session, abort
from werkzeug.local import LocalProxy

try:
    from asgiref.sync import async_to_sync
except ImportError:
    async_to_sync = None

def get_current_user() -> Optional[UserIdentity]:
    """Helper function to get the current user identity from Flask's global context."""
    return g.get("user")

current_user: "UserIdentity" = LocalProxy(get_current_user) # type: ignore

__all__ = ["FlaskIdentifyMiddleware", "current_user"]

logger = logging.getLogger(__name__)

class FlaskIdentifyMiddleware:
    """
    Flask-compatible middleware to validate user identity.
    """

    def __init__(self, app: Optional[Flask] = None, validators: List[IdentityValidator] = None):
        self.validators = validators if validators is not None else []
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask):
        if not Flask:
            raise ImportError(
                "The 'flask' library is required. Install with `pip install identify-middleware[flask]`."
            )
        
        # FIX: Use asgiref for robust async execution
        if not async_to_sync:
            logger.warning("The 'asgiref' library is recommended for Flask middleware stability. "
                           "Install with `pip install asgiref`.")

        if not hasattr(app, 'session_interface') or app.session_interface is None:
            logger.error("Flask app requires a session_interface. Ensure secret_key is set.")
            raise RuntimeError("FlaskIdentifyMiddleware requires a session interface.")

        app.before_request(self._before_request_handler)

    def _before_request_handler(self):
        """
        Handler executed before each request to validate user identity.
        """
        # FIX: Use async_to_sync to handle the async validators in Flask's sync context safely
        if async_to_sync:
            async_to_sync(self._validate_request)()
        else:
            import asyncio
            # Fallback: simple run, but dangerous if nested in another loop
            try:
                loop = asyncio.get_running_loop()
                # If we are already in a loop (e.g. uvicorn), this will fail with RuntimeError
                # This is why asgiref is preferred.
                if loop.is_running():
                     loop.create_task(self._validate_request())
                     return 
            except RuntimeError:
                pass
            asyncio.run(self._validate_request())

    async def _validate_request(self):
        for validator in self.validators:
            validator_name = validator.__class__.__name__
            logger.debug(f"Attempting Flask validation with {validator_name}.")
            try:
                user_identity = await validator.validate(request)
                if user_identity:
                    logger.info(f"Flask validation succeeded with {validator_name} for {user_identity.email}.")
                    g.user = user_identity
                    
                    # FIX: Session Size Optimization
                    # Only store minimal data in the cookie to prevent overflow (4KB limit)
                    session_data = user_identity.model_dump(include={'id', 'email', 'exp', 'provider'})
                    session["user"] = session_data
                    
                    return
                logger.debug(f"Flask validation failed for {validator_name}.")
            except Exception as e:
                # IdentifyException or other errors
                detail = getattr(e, "detail", "Authentication error")
                status = getattr(e, "status_code", 500)
                logger.warning(f"Validation error from {validator_name}: {detail}")
                session.pop("user", None)
                abort(status, description=detail)
        
        logger.info("Unauthenticated Flask request. Treating as public access.")
        g.user = None
        session.pop("user", None)