# Identify Middleware

This library provides a robust and modular middleware solution for managing user authentication in Python web applications, with built-in support for FastAPI and Flask. It allows for flexible integration of multiple identity validation methods, standardizing the output to a single UserIdentity object.

This middleware is designed to be configurable for various environments, from serverless platforms like Google Cloud Run (where state may be ephemeral) to stateful applications on GKE or Compute Engine.

## Features

Standardized Identity: All successful validations produce a single UserIdentity Pydantic model, available in request.state.user (FastAPI) or g.user (Flask).

Pluggable Session Persistence: Automatically persists and re-validates the UserIdentity using a pluggable session backend. You can use client-side cookies, Redis, PostgreSQL, or any other backend by configuring the upstream session middleware.

Extensible Validator Chain: Pass a list of validators to check identity in order.

## Built-in Validators:

SessionPersistenceValidator: Re-uses a valid identity from the session (fastest check).

IAPTokenValidator: Validates GCP IAP X-Goog-Iap-Jwt-Assertion header.

IAPCookieValidator: Validates GCP IAP GCP_IAP_UID cookie.

Oauth2Validator: Validates Google-issued ID tokens from an Authorization: Bearer header.

StaticAPIKeyValidator: Validates against a single key or a dictionary of keys.

CustomTokenValidator: Validates using your own async function (e.g., to query a database or external auth service).

Framework Support: Includes middleware wrappers for both FastAPI (IdentifyMiddleware) and Flask (FlaskIdentifyMiddleware).

Modular Installation: Install only the dependencies you need.

Modular Installation

This library is designed to be modular. The core library has minimal requirements.

Core Installation:

pip install identify-middleware


## Installing Extras:

Install support for frameworks, auth methods, and session backends as needed.

Google Auth (google): Required for Google IAP and OAuth2 validators.

pip install "identify-middleware[google]"


FastAPI Support (fastapi): Installs fastapi and starlette-session. starlette-session provides CookieBackend, RedisBackend, and InMemoryBackend.

pip install "identify-middleware[fastapi]"


Flask Support (flask): Installs flask and Flask-Session. Flask-Session provides backends for Redis, Filesystem, SQLAlchemy, etc.

pip install "identify-middleware[flask]"


Redis Session Backend (redis): Installs the redis client, which is used by starlette-session and Flask-Session.

pip install "identify-middleware[redis]"


All Extras: To install everything for a comprehensive setup:

pip install "identify-middleware[all]"


🏛️ Architecture: Pluggable Session Backends

This middleware does not implement session storage itself. It is designed to work with a separate session middleware, such as StarletteSessionMiddleware (for FastAPI) or Flask-Session (for Flask).

This design makes the backend completely pluggable. You configure your session middleware first, and the IdentifyMiddleware will automatically read from and write to the request.session or session object provided by that middleware.

### Choosing Your Session Backend

### Client-Side CookieBackend (Recommended for Cloud Run / Stateless)

How it works: The entire UserIdentity is serialized, signed with your SECRET_KEY, and stored in the client's cookie.

Pros: Perfect for stateless applications (like Cloud Run). No external dependencies. Any server instance can validate the session.

Cons: Cookies are limited to 4KB. If your UserIdentity (with all claims) is larger, this will fail.

Expiration: SessionPersistenceValidator checks the exp field in the cookie data. It will reject expired sessions even if the cookie still exists.

### Server-Side RedisBackend (Recommended for Scaled / Stateful)

How it works: A tiny, unique session ID is stored in the client's cookie. The UserIdentity is stored in your Redis server, referenced by that ID.

Pros: No size limit. Session can be invalidated server-side.

Cons: Requires a running Redis server.

Expiration: SessionPersistenceValidator checks the exp field. You should also set a TTL in Redis that matches the expiration.

### Server-Side InMemoryBackend / Filesystem (For Dev / Single Instances)

How it works: The session is stored in the server's local memory or on its disk.

Pros: Simple, no dependencies.

Cons: NOT suitable for Cloud Run, GKE, or any autoscaled environment. The session is lost if the user hits a new server instance.

The SessionPersistenceValidator is key. It should always be the first validator in your list to get the performance benefit of re-using a session.

## 🚀 Usage with FastAPI

Example 1: Client-Side Cookie Session (Recommended for Cloud Run)

This example stores the session in a signed cookie.

### Installation:

pip install "identify-middleware[fastapi,google]"


### Example (main.py):

import secrets
from fastapi import FastAPI, Request
from starlette_session import SessionMiddleware
from starlette_session.backends import CookieBackend # Pluggable Backend!

from models.identity import UserIdentity
from middleware.identify import IdentifyMiddleware
from middleware.validators import (
    SessionPersistenceValidator,
    IAPTokenValidator,
    Oauth2Validator
)

# --- Configuration ---
# CRITICAL: This must be a strong, persistent secret.
# In Cloud Run, set this from Secret Manager or a build-time env var.
APP_SECRET_KEY = "your-very-strong-32-byte-secret-key"

GCP_IAP_AUDIENCE = "/projects/123456789/apps/my-gcp-project-id"

validators = [
    SessionPersistenceValidator(expiration_threshold=300), # 1. Check cookie
    IAPTokenValidator(audience=GCP_IAP_AUDIENCE),       # 2. Check IAP header
    Oauth2Validator(),                                  # 3. Check Bearer token
]

app = FastAPI()

# 1. Add the Session Middleware *FIRST*
app.add_middleware(
    SessionMiddleware,
    backend=CookieBackend(secret_key=APP_SECRET_KEY),
    secret_key=APP_SECRET_KEY, # Also used for legacy signing
    https_only=True, # Production recommendation
)

# 2. Add the Identify Middleware *SECOND*
app.add_middleware(IdentifyMiddleware, validators=validators)

@app.get("/secure")
async def secure_endpoint(request: Request):
    user: UserIdentity | None = getattr(request.state, "user", None)
    if user:
        return {"message": f"Access granted to {user.email} from session"}
    return {"message": "Public access"}


## Example 2: Server-Side Redis Session (Recommended for GKE / Stateful)

This example uses Redis to store sessions.

### Installation:

pip install "identify-middleware[fastapi,google,redis]"


### Example (main.py):

# ... (imports are similar, but include RedisBackend)
from starlette_session.backends import RedisBackend
# ... (validators and app setup are identical)

# 1. Add the Session Middleware *FIRST*
app.add_middleware(
    SessionMiddleware,
    backend=RedisBackend(redis_url="redis://localhost:6379/0"),
    secret_key=APP_SECRET_KEY,
    https_only=True,
)

# 2. Add the Identify Middleware *SECOND* (this line is identical)
app.add_middleware(IdentifyMiddleware, validators=validators)

# ... (endpoints are identical)


## 💡 Usage with Tools (Recommended)

To simplify endpoint protection, the library provides helper dependencies (FastAPI) and decorators (Flask).

### FastAPI: `require_auth` Dependency

Instead of manually checking `request.state.user`, you can use the `require_auth` dependency to protect an endpoint. It will automatically return a `401 Unauthorized` error if no valid user identity is found.

```python
# main.py
from fastapi import FastAPI, Depends
from models.identity import UserIdentity
from middleware.tools import require_auth # <-- Import the tool

# ... (app and middleware setup is the same)

@app.get("/my-profile")
async def get_profile(user: UserIdentity = Depends(require_auth)):
    # This code only runs if authentication succeeds.
    # The 'user' object is guaranteed to be a valid UserIdentity.
    return {"email": user.email, "provider": user.provider}
```

### Flask: `@require_auth` Decorator

For Flask, use the `@require_auth` decorator.

```python
# app.py
from flask import g
from middleware.flask_identify import require_auth # <-- Import the tool

@app.route("/my-profile")
@require_auth
def my_profile():
    # This code only runs if g.user is valid.
    return {"email": g.user.email}
```

##  Usage with Flask

Flask's default session is a client-side cookie session, just like CookieBackend. Flask-Session is only needed if you want server-side sessions (like Redis or Filesystem).

Example 1: Client-Side Cookie Session (Default Flask)

### Installation:

pip install "identify-middleware[flask,google]"


### Example (app.py):

from flask import Flask, g
from models.identity import UserIdentity
from middleware.flask_identify import FlaskIdentifyMiddleware
from middleware.validators import (
    SessionPersistenceValidator, IAPTokenValidator, Oauth2Validator
)

# --- Configuration ---
app = Flask(__name__)
# CRITICAL: This key is used to sign the client-side session cookie.
app.config["SECRET_KEY"] = "your-very-strong-flask-secret-key"

GCP_IAP_AUDIENCE = "/projects/123456789/apps/my-gcp-project-id"

validators = [
    SessionPersistenceValidator(),
    IAPTokenValidator(audience=GCP_IAP_AUDIENCE),
    Oauth2Validator(),
]

# 1. Flask's built-in session is already active.
# No extra session middleware is needed.

# 2. Initialize the Identify Middleware
# It will use Flask's default `session` object.
FlaskIdentifyMiddleware(app, validators=validators)

@app.route("/secure")
def secure_endpoint():
    user: UserIdentity | None = getattr(g, "user", None)
    if user:
        return {"message": f"Authenticated as {user.email} from session"}
    return {"message": "Public Access"}


Example 2: Server-Side Redis Session (with Flask-Session)

Installation:

pip install "identify-middleware[flask,google,redis]"


Example (app.py):

from flask import Flask, g, session
from flask_session import Session # Pluggable Backend!
from redis import Redis
# ... (other imports are the same)

# --- Configuration ---
app = Flask(__name__)
app.config["SECRET_KEY"] = "a-very-secret-key-for-sessions"

# 1. Configure Flask-Session *FIRST*
app.config["SESSION_TYPE"] = "redis"
app.config["SESSION_REDIS"] = Redis(host="localhost", port=6379, db=0)
Session(app)

# ... (validators list is the same)

# 2. Initialize the Identify Middleware *SECOND*
# It will use the `session` object from Flask-Session.
FlaskIdentifyMiddleware(app, validators=validators)

# ... (endpoints are identical)

## Example 3: Server-Side Database Session (FastAPI + SQLAlchemy)

While `starlette-session` does not have a built-in SQLAlchemy backend, this library provides one in the `contrib` module. This is useful for storing sessions in a PostgreSQL or other relational database.

> **Note for Flask Users:** `Flask-Session` already has excellent support for SQLAlchemy. You can configure it directly without needing the `contrib` backend.

### Installation:

`pip install "identify-middleware[fastapi,google]" sqlalchemy asyncpg`

### Example (main.py):

```python
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime
from sqlalchemy import Column, String, Text, DateTime
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from starlette_session import SessionMiddleware

# 1. Import the DatabaseBackend
from contrib.database_backend import DatabaseBackend

# 2. Define your SQLAlchemy Session model
Base = declarative_base()
class SessionData(Base):
    __tablename__ = "sessions"
    session_id = Column(String(255), primary_key=True)
    data = Column(Text, nullable=False)
    last_modified = Column(DateTime, nullable=False, default=datetime.utcnow)

# 3. Set up your database connection and session callable
DATABASE_URL = "postgresql+asyncpg://user:password@host/dbname"
engine = create_async_engine(DATABASE_URL)
async_session_maker = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

@asynccontextmanager
async def get_db_session():
    async with async_session_maker() as session:
        yield session

# 4. Configure the SessionMiddleware with the DatabaseBackend
app.add_middleware(
    SessionMiddleware,
    backend=DatabaseBackend(session_table=SessionData, db_callable=get_db_session),
    secret_key=APP_SECRET_KEY,
)

# ... (the rest of your app, IdentifyMiddleware, and endpoints are the same)
```

## Validators Reference

All validators are imported from middleware.validators.

### SessionPersistenceValidator

Checks for a valid, non-expired UserIdentity object in the session. This should always be the first validator in your list.

expiration_threshold (int): Seconds before actual expiration to consider the session invalid, forcing re-validation. Default: 300 (5 minutes).

SessionPersistenceValidator(expiration_threshold=300)


### IAPTokenValidator

Validates the `X-Goog-Iap-Jwt-Assertion` header sent by Google Cloud Identity-Aware Proxy.

**Note:** This validator uses the `google-auth` library, which may perform network calls to validate the token with Google's servers, though it employs caching.

audience (str): Required. The expected audience string for the IAP JWT.

authorization_header_key (str): The header name. Default: "X-Goog-Iap-Jwt-Assertion".

IAPTokenValidator(audience=f"/projects/{PROJECT_NUMBER}/apps/{PROJECT_ID}")


### IAPCookieValidator

Validates the `GCP_IAP_UID` cookie sent by Google Cloud Identity-Aware Proxy.

**Note:** This validator performs **local** cryptographic validation using Google's cached public keys. It does **not** make a network call for every request, making it highly performant.

audience (str): Required. The expected audience string for the IAP cookie JWT.

IAPCookieValidator(audience=f"/projects/{PROJECT_NUMBER}/apps/{PROJECT_ID}")


### Oauth2Validator

Validates a Google-issued ID Token sent as a Bearer token in the Authorization header.

This validator has no constructor arguments.

Oauth2Validator()


### StaticAPIKeyValidator

Validates a static API key from a header. Useful for service-to-service communication.

key_or_map (Union[str, Mapping[str, str]]): Required.

As a str: A single, valid API key.

As a dict: A mapping of { "api_key_1": "user1@example.com", "api_key_2": "user2@example.com" }.

user_email (str): The email to assign if key_or_map is a single string. Default: "service-account@example.com".

header_key (str): The header name to check. Default: "X-API-Key".

# Single key mode
StaticAPIKeyValidator(
    key_or_map="my-secret-key-123",
    user_email="service-a@example.com"
)


### CustomTokenValidator

Validates a token using a custom async function. This is the most flexible validator, allowing you to connect to any database or external authentication authority.

auth_callable (Callable[[str], Awaitable[Optional[UserIdentity]]]): Required. An async function that takes the token string and returns either a valid UserIdentity object or None.

header_key (str): The header name. Default: "X-API-Key".

scheme (Optional[str]): If provided, checks for an auth scheme (e.g., "Bearer") and only passes the token part to your callable.

### Example:

from models.identity import UserIdentity
import time

# 1. Define your custom async validation logic
async def validate_token_from_my_db(token: str) -> Optional[UserIdentity]:
    # user_data = await my_db.find_user_by_api_key(token)
    # if not user_data:
    #     return None
    
    if token == "token-from-my-custom-db":
        user_data = {"id": "user-db-123", "email": "user@my-db.com"}
    else:
        return None
    
    return UserIdentity(
        id=user_data["id"],
        email=user_data["email"],
        exp=int(time.time() + 3600), # Give it a 1-hour session
        provider="my-custom-db",
        claims=user_data,
        token=token
    )

# 2. Pass the callable to the validator
CustomTokenValidator(
    auth_callable=validate_token_from_my_db,
    header_key="Authorization",
    scheme="Bearer" # Handles "Bearer <token>"
)


## Testing

Run the test suite using pytest:

pytest tests/
