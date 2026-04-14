import secrets
import uvicorn
from fastapi import FastAPI, Request
from starlette_session import SessionMiddleware
from starlette_session.backends import CookieBackend  # <-- Pluggable Backend!
from typing import Optional

# Import your identity model and validators
# Assuming 'models' and 'middleware' are in the python path
try:
    from models.identity import UserIdentity
    from middleware.identify import IdentifyMiddleware
    from middleware.validators import (
        SessionPersistenceValidator,
        IAPTokenValidator,
        Oauth2Validator,
    )
except ImportError:
    print("Error: Could not import middleware components.")
    print("Please ensure the 'models' and 'middleware' directories are in your PYTHONPATH.")
    import sys
    sys.exit(1)


# --- Configuration ---
# This key is CRITICAL. It must be a strong, unique secret.
# It's used to sign the session cookie.
# In production, load this from a secret manager or environment variable.
APP_SECRET_KEY = "your-very-strong-32-byte-secret-key"
if APP_SECRET_KEY == "your-very-strong-32-byte-secret-key":
    print("WARNING: Using default secret key. SET a strong key in production.")
    # For generation:
    # import secrets
    # print(f"Generated key: {secrets.token_urlsafe(32)}")


# GCP IAP Audience (Find in IAP settings)
# Format: /projects/<PROJECT_NUMBER>/apps/<PROJECT_ID>
GCP_IAP_AUDIENCE = "/projects/123456789/apps/my-gcp-project-id"

# Define your validator chain
validators = [
    # 1. Check for an existing valid session *from the cookie* first.
    SessionPersistenceValidator(expiration_threshold=300),

    # 2. If no session, check for Google IAP token
    IAPTokenValidator(audience=GCP_IAP_AUDIENCE),

    # 3. If no IAP, check for a Bearer token
    Oauth2Validator(),
]

app = FastAPI()

# --- Middleware Configuration ---

# 1. Add the Session Middleware *FIRST*
# We use CookieBackend to store the entire session in a signed cookie.
# This is stateless and perfect for Cloud Run.
app.add_middleware(
    SessionMiddleware,
    backend=CookieBackend(secret_key=APP_SECRET_KEY),
    secret_key=APP_SECRET_KEY,  # secret_key is also used for legacy signing
    https_only=False,  # Set to True in production (requires HTTPS)
    max_age=None,  # Let the identity's 'exp' control validity
)

# 2. Add the Identify Middleware *SECOND*
# It will read/write to the `request.session` provided by CookieBackend.
app.add_middleware(IdentifyMiddleware, validators=validators)


@app.get("/secure-endpoint")
async def secure_endpoint(request: Request):
    """
    A secure endpoint that relies on the middleware to populate user identity.
    """
    # We can type-hint the user for better editor support
    user: Optional[UserIdentity] = getattr(request.state, "user", None)

    if user:
        return {
            "message": f"Access granted to {user.email}",
            "provider": user.provider,
            "session_expires": user.exp,
        }

    # If no validator succeeded, it's treated as public access
    return {"message": "Public access (no identity found)"}


@app.get("/")
async def public_endpoint():
    """A public endpoint that requires no authentication."""
    return {"message": "This is a public endpoint"}


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger()
    logger.info("Starting FastAPI server with CookieBackend session...")
    logger.info(f"IAP Audience configured for: {GCP_IAP_AUDIENCE}")
    if GCP_IAP_AUDIENCE == "/projects/123456789/apps/my-gcp-project-id":
        logger.warning("Using placeholder IAP Audience. Update GCP_IAP_AUDIENCE to test IAP.")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)