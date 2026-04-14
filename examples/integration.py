from fastapi import FastAPI
from identify_middleware.fastapi_identify import IdentifyMiddleware
from identify_middleware.shared.validators import (
    SessionPersistenceValidator,
    IAPTokenValidator
)

# 1. Get your IAP Audience (from GCP Console)
# It looks like: "/projects/123456789/global/backendServices/987654321"
# Or for Cloud Run direct invocation: "https://my-service-url.run.app"
IAP_AUDIENCE = "/projects/YOUR_PROJECT_NUMBER/global/backendServices/YOUR_SERVICE_ID"

app = FastAPI()

# 2. Configure the Middleware
app.add_middleware(
    IdentifyMiddleware,
    validators=[
        # First, check if we already have a valid session cookie (Fastest)
        SessionPersistenceValidator(expiration_threshold=300),
        
        # Second, check the GCP Header (The Source of Truth)
        IAPTokenValidator(
            audience=IAP_AUDIENCE,
            authorization_header_key="X-Goog-Iap-Jwt-Assertion" 
        )
    ]
)

# 3. Protected Route
@app.get("/")
def read_root(request: Request):
    user = request.state.user
    if user:
        return {
            "Hello": user.email, 
            "Provider": user.provider, # Will be 'google-iap-token'
            "Keycloak_Original_Sub": user.claims.get("sub") # The long workforce ID
        }
    return {"Hello": "Guest"}