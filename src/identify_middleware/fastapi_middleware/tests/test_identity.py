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

# tests/test_identity.py
import time

import pytest
from fastapi import FastAPI, Request, HTTPException
from starlette.testclient import TestClient
from starlette_session import SessionMiddleware as StarletteSessionMiddleware
from starlette_session.backends import InMemoryBackend
from unittest.mock import patch, MagicMock

from middleware.identify import (
    IdentifyMiddleware,
)
from middleware.validators import (
    SessionPersistenceValidator,
    Oauth2Validator,
    StaticAPIKeyValidator,
    IAPTokenValidator,
    IAPCookieValidator,
)
from models.identity import UserIdentity
from utils.jwt_utils import IdentityException


@pytest.fixture
def future_time():
    return int(time.time() + 3600)


@pytest.fixture
def mock_user_identity(future_time):
    return UserIdentity(
        id="12345",
        email="test@example.com",
        exp=future_time,
        provider="test-provider",
        claims={"sub": "12345", "email": "test@example.com", "exp": future_time},
        token="test-token",
    )


@pytest.fixture
def mock_iap_cookie_identity(future_time):
    return UserIdentity(
        id="iap-cookie-123",
        email="iap_cookie@example.com",
        exp=future_time,
        provider="google-iap-cookie",
        claims={"sub": "iap-cookie-123", "email": "iap_cookie@example.com", "exp": future_time},
        token="iap-cookie-token",
    )


@pytest.fixture
def mock_iap_token_identity(future_time):
    return UserIdentity(
        id="iap-token-456",
        email="iap_token@example.com",
        exp=future_time,
        provider="google-iap-token",
        claims={"sub": "iap-token-456", "email": "iap_token@example.com", "exp": future_time},
        token="iap-token",
    )


@pytest.fixture
def mock_oauth2_identity(future_time):
    return UserIdentity(
        id="oauth2-789",
        email="oauth2@example.com",
        exp=future_time,
        provider="oauth2-google",
        claims={"sub": "oauth2-789", "email": "oauth2@example.com", "exp": future_time},
        token="oauth2-token",
    )


@pytest.fixture
def app_with_middleware(
    mock_iap_cookie_identity, mock_iap_token_identity, mock_oauth2_identity
):
    app = FastAPI()

    # Mock all validators
    mock_session_validator = MagicMock(spec=SessionPersistenceValidator)
    mock_session_validator.validate = MagicMock(return_value=None)

    mock_static_validator = MagicMock(spec=StaticAPIKeyValidator)
    mock_static_validator.validate = MagicMock(return_value=None)

    mock_oauth2_validator = MagicMock(spec=Oauth2Validator)
    mock_oauth2_validator.validate = MagicMock(return_value=None)

    mock_iap_cookie_validator = MagicMock(spec=IAPCookieValidator)
    mock_iap_cookie_validator.validate = MagicMock(return_value=None)

    mock_iap_token_validator = MagicMock(spec=IAPTokenValidator)
    mock_iap_token_validator.validate = MagicMock(return_value=None)

    validators = [
        mock_session_validator,
        mock_static_validator,
        mock_oauth2_validator,
        mock_iap_cookie_validator,
        mock_iap_token_validator,
    ]

    # Add SessionMiddleware for session handling
    app.add_middleware(
        StarletteSessionMiddleware, backend=InMemoryBackend(), secret_key="test-secret"
    )

    app.add_middleware(IdentifyMiddleware, validators=validators)

    @app.get("/secure-endpoint")
    async def secure_endpoint(request: Request):
        if hasattr(request.state, "user") and request.state.user:
            return {"message": "Access granted", "user": request.state.user.model_dump()}
        return {"message": "Public access", "user": None}

    @app.get("/unprotected-endpoint")
    async def unprotected_endpoint():
        return {"message": "This is unprotected"}

    client = TestClient(app)
    return {
        "client": client,
        "validators": {
            "session": mock_session_validator,
            "static": mock_static_validator,
            "oauth2": mock_oauth2_validator,
            "iap_cookie": mock_iap_cookie_validator,
            "iap_token": mock_iap_token_validator,
        },
        "identities": {
            "iap_cookie": mock_iap_cookie_identity,
            "iap_token": mock_iap_token_identity,
            "oauth2": mock_oauth2_identity,
        },
    }


def test_unprotected_endpoint(app_with_middleware):
    client = app_with_middleware["client"]
    response = client.get("/unprotected-endpoint")
    assert response.status_code == 200
    assert response.json() == {"message": "This is unprotected"}


def test_no_auth_provided(app_with_middleware):
    client = app_with_middleware["client"]
    response = client.get("/secure-endpoint")
    assert response.status_code == 200
    assert response.json() == {"message": "Public access", "user": None}


def test_static_api_key_success(app_with_middleware, mock_user_identity):
    client = app_with_middleware["client"]
    app_with_middleware["validators"]["static"].validate = MagicMock(
        return_value=mock_user_identity
    )

    response = client.get("/secure-endpoint", headers={"X-API-Key": "static-key"})
    assert response.status_code == 200
    assert response.json()["message"] == "Access granted"
    assert response.json()["user"]["email"] == "test@example.com"
    assert "session" in client.cookies
    assert client.cookies["session"] is not None


def test_oauth2_validator_success(app_with_middleware):
    client = app_with_middleware["client"]
    identity = app_with_middleware["identities"]["oauth2"]
    app_with_middleware["validators"]["oauth2"].validate = MagicMock(
        return_value=identity
    )

    response = client.get(
        "/secure-endpoint", headers={"Authorization": "Bearer some-oauth2-token"}
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Access granted"
    assert response.json()["user"]["email"] == "oauth2@example.com"


def test_iap_cookie_validator_success(app_with_middleware):
    client = app_with_middleware["client"]
    identity = app_with_middleware["identities"]["iap_cookie"]
    app_with_middleware["validators"]["iap_cookie"].validate = MagicMock(
        return_value=identity
    )

    client.cookies.set("GCP_IAP_UID", "some-iap-cookie-jwt")
    response = client.get("/secure-endpoint")
    assert response.status_code == 200
    assert response.json()["message"] == "Access granted"
    assert response.json()["user"]["email"] == "iap_cookie@example.com"


def test_iap_token_validator_success(app_with_middleware):
    client = app_with_middleware["client"]
    identity = app_with_middleware["identities"]["iap_token"]
    app_with_middleware["validators"]["iap_token"].validate = MagicMock(
        return_value=identity
    )

    response = client.get(
        "/secure-endpoint", headers={"X-Goog-Iap-Jwt-Assertion": "some-iap-jwt"}
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Access granted"
    assert response.json()["user"]["email"] == "iap_token@example.com"


def test_session_persistence_validator_success(app_with_middleware, mock_user_identity):
    client = app_with_middleware["client"]
    
    # Mock static validator for first request
    app_with_middleware["validators"]["static"].validate = MagicMock(
        return_value=mock_user_identity
    )
    # First request to establish session
    response = client.get("/secure-endpoint", headers={"X-API-Key": "static-key"})
    assert response.status_code == 200
    assert response.json()["user"]["email"] == "test@example.com"
    assert "session" in client.cookies

    # Reset mocks for second request
    app_with_middleware["validators"]["static"].validate = MagicMock(return_value=None)
    app_with_middleware["validators"]["session"].validate = MagicMock(
        return_value=mock_user_identity
    )

    # Second request, should be validated by session persistence
    response = client.get("/secure-endpoint")
    assert response.status_code == 200
    assert response.json()["user"]["email"] == "test@example.com"
    # Ensure the session validator was called
    app_with_middleware["validators"]["session"].validate.assert_called_once()
    # Ensure the static validator was NOT called
    app_with_middleware["validators"]["static"].validate.assert_not_called()


def test_session_persistence_validator_expired(
    app_with_middleware, mock_user_identity
):
    client = app_with_middleware["client"]
    
    # Set up session validator to throw expired exception
    app_with_middleware["validators"]["session"].validate = MagicMock(
        side_effect=IdentityException(status_code=401, detail="Expired")
    )
    
    # Mock static validator to provide a new identity
    app_with_middleware["validators"]["static"].validate = MagicMock(
        return_value=mock_user_identity
    )

    # Make request. Session validator will fail, but static validator will succeed.
    response = client.get("/secure-endpoint", headers={"X-API-Key": "static-key"})
    assert response.status_code == 200 # The static validator "catches" the request
    assert response.json()["user"]["email"] == "test@example.com"
    app_with_middleware["validators"]["session"].validate.assert_called_once()
    app_with_middleware["validators"]["static"].validate.assert_called_once()


def test_middleware_http_exception_flow(app_with_middleware):
    """
    Test the middleware flow with an invalid key that raises IdentityException.
    """
    client = app_with_middleware["client"]
    # Patch the validator to raise an exception
    app_with_middleware["validators"]["iap_token"].validate = MagicMock(
        side_effect=IdentityException(status_code=403, detail="Invalid Token")
    )
    response = client.get(
        "/secure-endpoint", headers={"X-Goog-Iap-Jwt-Assertion": "invalid-api-key"}
    )
    assert response.status_code == 403
    assert "Invalid Token" in response.json()["detail"]


def test_middleware_general_exception_flow(app_with_middleware):
    """
    Test the middleware flow with a validator that raises a general Exception.
    """
    client = app_with_middleware["client"]
    # Patch the validator to raise an exception
    app_with_middleware["validators"]["iap_token"].validate = MagicMock(
        side_effect=Exception("Something went very wrong")
    )
    response = client.get(
        "/secure-endpoint", headers={"X-Goog-Iap-Jwt-Assertion": "invalid-api-key"}
    )
    assert response.status_code == 500
    assert "Internal server error" in response.json()["detail"]