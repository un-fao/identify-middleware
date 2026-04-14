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
# File: examples/fastapi_cookie_session.py

"""
Example: FastAPI with CookieBackend (Stateless)

This example demonstrates how to configure the IdentifyMiddleware
in a stateless environment like Google Cloud Run.

It uses:
- `starlette_session.backends.CookieBackend` to store the session in a
  signed cookie on the client side.
- The IAP renewal flow, configured with a placeholder URL.
- The FastAPI dependency tools (`get_current_user`, `require_auth`).
"""

import secrets
import uvicorn
import logging
from typing import Optional

try:
    from fastapi import FastAPI, Depends
    from starlette_session import SessionMiddleware
    from starlette_session.backends import CookieBackend  # <-- Pluggable Backend!
except ImportError:
    print("Failed to import FastAPI or Starlette-Session.")
    print("Please install with: pip install 'identify-middleware[fastapi]'")
    exit(1)

try:
    from identify_middleware.shared.models import UserIdentity
    from middleware.identify import IdentifyMiddleware
    from middleware.validators import (
        SessionPersistenceValidator,
        IAPTokenValidator,
        Oauth2Validator,
        IAPCookieValidator
    )
    from middleware.tools import get_current_user, require_auth
except ImportError:
    print("Error: Could not import middleware components.")
    print("Please ensure you are running from the root of the project or the package is installed.")
    exit(1)


# --- Configuration ---
# This key is CRITICAL. It must be a strong, unique secret.
# It's used to sign the session cookie.
# In production, load this from a secret manager or environment variable.
APP_SECRET_KEY = secrets.token_urlsafe(32)

# GCP IAP Audience (Find in IAP settings)
# Format: /projects/<PROJECT_NUMBER>/apps/<PROJECT_ID>
GCP_IAP_AUDIENCE = "/projects/123456789/apps/my-gcp-project-id"

# Your Nginx proxy endpoint that handles the IAP redirect dance
IAP_RENEWAL_URL = "https://my-proxy.com/renew-iap-example"


# Define your validator chain
validators = [
    # 1. Check for an existing valid session *from the cookie* first.
    SessionPersistenceValidator(expiration_threshold=300),

    # 2. If no session, check for the IAP cookie (fast, local validation)
    IAPCookieValidator(
        audience=GCP_IAP_AUDIENCE,
        iap_renewal_url=IAP_RENEWAL_URL # Pass renewal URL here
    ),

    # 3. If no cookie, check for the IAP header (for apps behind IAP)
    IAPTokenValidator(
        audience=GCP_IAP_AUDIENCE,
        iap_renewal_url=IAP_RENEWAL_URL # Pass renewal URL here
    ),

    # 4. If no IAP, check for a Bearer token
    Oauth2Validator(),
]

app = FastAPI()

# --- Middleware Configuration ---

# 1. Add SessionMiddleware (e.g., Cookie-based for stateless)
app.add_middleware(
    SessionMiddleware,
    backend=CookieBackend(secret_key=APP_SECRET_KEY), # Stateless, perfect for Cloud Run
    secret_key=APP_SECRET_KEY, # For legacy signing
    https_only=True, # Recommended for production
    max_age=None # Let the identity's 'exp' control validity
)

# 2. Add the Identify Middleware *SECOND*
# It will read/write to the `request.session` provided by CookieBackend.
app.add_middleware(IdentifyMiddleware, validators=validators)


@app.get("/secure-endpoint")
async def get_secure_data(
    # This endpoint now requires a valid user
    user: UserIdentity = Depends(require_auth)
):
    """
    A secure endpoint that is protected by the `require_auth` dependency.
    """
    # 'user' is guaranteed to be a valid UserIdentity object
    return {
        "message": f"This is secure data for {user.email}",
        "provider": user.provider,
        "session_expires": user.exp
    }

@app.get("/optional-endpoint")
async def get_optional_data(
    # This endpoint works for both logged-in and public users
    user: Optional[UserIdentity] = Depends(get_current_user)
):
    """
    An endpoint that provides different data based on authentication.
    """
    if user:
        return {"message": f"Hello, {user.email}! Here is your personalized data."}
    
    return {"message": "Hello, guest! Here is the public data."}


@app.get("/")
async def public_endpoint():
    """A public endpoint that requires no authentication."""
    return {"message": "This is a public endpoint"}


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    logger.info("Starting FastAPI server with CookieBackend session and Auth Tools...")
    logger.info(f"IAP Audience configured for: {GCP_IAP_AUDIENCE}")
    if IAP_RENEWAL_URL:
        logger.info(f"IAP Renewal URL configured: {IAP_RENEWAL_URL}")
    if GCP_IAP_AUDIENCE == "/projects/123456789/apps/my-gcp-project-id":
        logger.warning("Using placeholder IAP Audience. Update GCP_IAP_AUDIENCE to test IAP.")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)