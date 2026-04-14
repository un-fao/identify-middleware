# Handling the "Redirect to Authority" (The missing piece)
# Validators do not perform redirects; they only return None (not valid) or UserIdentity (valid). 
# If you want the application to "Identify OR Redirect", you must handle the Unauthenticated state at the application level.

# Strategy for Browser Applications (Session-Based)
# Configure Middleware: Use SessionPersistenceValidator (first) and OIDCTokenValidator (second).

# Protect Routes: Use the require_auth dependency.

# Handle Failure: Add an exception handler that catches 401 Unauthorized and redirects the user to Keycloak.

from fastapi import FastAPI, Depends, Request
from fastapi.responses import RedirectResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

# ... import your middleware and validators ...

app = FastAPI()

# 1. Add Middleware
app.add_middleware(IdentifyMiddleware, validators=[
    SessionPersistenceValidator(), # Checks cookie session
    OIDCTokenValidator(
        discovery_url="https://auth.example.com/realms/myrealm/.well-known/openid-configuration",
        audience="my-client-id"
    )
])

# 2. Redirect Logic (The "IAP Replacement")
# If 'require_auth' fails, it raises 401. We catch it and redirect to login.
@app.exception_handler(401)
async def unauth_handler(request: Request, exc: StarletteHTTPException):
    if "text/html" in request.headers.get("accept", ""):
        # It's a browser, send them to Keycloak
        return RedirectResponse(url="/login")
    # It's an API, return 401 JSON
    return JSONResponse({"detail": "Not authenticated"}, status_code=401)

# 3. Login Handshake Endpoints (Required for "Redirect" flow)
from authlib.integrations.starlette_client import OAuth

oauth = OAuth()
oauth.register(
    name='keycloak',
    server_metadata_url='https://auth.example.com/realms/myrealm/.well-known/openid-configuration',
    client_id='my-client-id',
    client_secret='my-secret',
    client_kwargs={'scope': 'openid email profile'}
)

@app.get("/login")
async def login(request: Request):
    redirect_uri = request.url_for('auth_callback')
    return await oauth.keycloak.authorize_redirect(request, redirect_uri)

@app.get("/callback")
async def auth_callback(request: Request):
    token = await oauth.keycloak.authorize_access_token(request)
    user_info = token['userinfo']
    
    # THIS is where you set the session that SessionPersistenceValidator reads
    request.session['user'] = {
        "id": user_info['sub'],
        "email": user_info['email'],
        "exp": user_info['exp'],
        "provider": "keycloak",
        "claims": user_info
    }
    return RedirectResponse(url="/")