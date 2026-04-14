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
from typing import Optional
from functools import wraps

from identify_middleware.shared.models import UserIdentity

logger = logging.getLogger(__name__)

# --- FastAPI Tools (Dependencies) ---

from fastapi import Request, HTTPException, Depends

def get_current_user(request: Request) -> Optional[UserIdentity]:
    """
    FastAPI dependency to get the current user.
    
    Returns Optional[UserIdentity], so it's suitable for endpoints
    that are public but have optional authenticated features.
    
    Usage:
        @app.get("/public-data")
        async def get_public_data(
            user: Optional[UserIdentity] = Depends(get_current_user)
        ):
            if user:
                return {"message": f"Hello, {user.email}"}
            return {"message": "Hello, guest"}
    """
    return getattr(request.state, "user", None)

def require_auth(
    request: Request,
    user: Optional[UserIdentity] = Depends(get_current_user)
) -> UserIdentity:
    """
    FastAPI dependency to require an authenticated user.
    
    If no user is found, it raises a 401 HTTPException.
    This is for protecting endpoints that must have an authenticated user.
    
    Usage:
        @app.get("/secure-data")
        async def get_secure_data(
            user: UserIdentity = Depends(require_auth)
        ):
            # user is guaranteed to be a valid UserIdentity
            return {"message": f"Secure data for {user.email}"}
    """
    if not user:
        logger.warning("require_auth: No user found, raising 401.")
        # Note: We don't raise IAPTokenExpiredError here because if validation
        # failed, the middleware would have already raised it. This is the
        # catch-all for "no validators succeeded at all".
        raise HTTPException(
            status_code=401,
            detail="Not authenticated"
        )
    return user