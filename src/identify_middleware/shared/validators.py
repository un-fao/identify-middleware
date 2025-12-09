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
import logging
import time
from abc import ABC, abstractmethod
from typing import Optional, Callable, Awaitable, Union, Mapping, Any

from identify_middleware.shared.models import UserIdentity
from identify_middleware.shared.jwt_utils import (
    get_iap_public_keys,
    verify_iap_cookie_jwt,
    check_token_expiration,
    verify_iap_jwt,
    receive_authorized_get_request,
    IdentityException,
)

# Import google auth components if available for the robust cookie validator fix
try:
    from google.oauth2.id_token import verify_oauth2_token
    from google.auth.transport import requests as google_requests
    HAS_GOOGLE_AUTH = True
except ImportError:
    HAS_GOOGLE_AUTH = False
    verify_oauth2_token = None
    google_requests = None

logger = logging.getLogger(__name__)

AuthCallable = Callable[[str], Awaitable[Optional[UserIdentity]]]

class IdentityValidator(ABC):
    """
    Abstract base class for identity validators.
    """

    @abstractmethod
    # FIX: Type Hinting
    # Use 'Any' for request to support both FastAPI and Flask Requests without hard dependencies
    async def validate(self, request: Any) -> Optional[UserIdentity]:
        """
        Validate the request for user authentication.
        Args:
            request: The incoming web framework request object (FastAPI or Flask).
        """
        pass


class SessionPersistenceValidator(IdentityValidator):
    def __init__(self, expiration_threshold: int = 300):
        self.expiration_threshold = expiration_threshold

    async def validate(self, request: Any) -> Optional[UserIdentity]:
        # Works for both Flask and Starlette/FastAPI sessions
        session = getattr(request, "session", {})
        user_identity_data = session.get("user")
        
        if user_identity_data and isinstance(user_identity_data, dict):
            try:
                # If we optimized storage, we might be missing 'claims' in the session.
                # We inject empty claims if missing to satisfy Pydantic if necessary,
                # or we assume the model makes them optional (checked in models.py).
                if "claims" not in user_identity_data:
                    user_identity_data["claims"] = {} 

                user_identity = UserIdentity(**user_identity_data)
                check_token_expiration(
                    user_identity.model_dump(), self.expiration_threshold
                )
                return user_identity
            except IdentityException:
                if isinstance(session, dict): session.pop("user", None)
                else: del session["user"]
            except Exception as e:
                logger.warning(f"Could not parse UserIdentity from session: {e}")
                if isinstance(session, dict): session.pop("user", None)
                else: del session["user"]
        return None


class Oauth2Validator(IdentityValidator):
    def __init__(self):
        # FIX: Dependency Check
        if not HAS_GOOGLE_AUTH:
            raise ImportError("google-auth library required for Oauth2Validator. pip install google-auth")

    async def validate(self, request: Any) -> Optional[UserIdentity]:
        try:
            claims = receive_authorized_get_request(request)
            if claims and "email" in claims and "exp" in claims:
                # Extract raw token for record keeping
                auth_header = request.headers.get("Authorization", "")
                token = None
                if " " in auth_header:
                    token = auth_header.split(" ", 1)[1]
                
                user_identity = UserIdentity(
                    id=claims.get("sub", claims["email"]),
                    email=claims["email"],
                    exp=claims["exp"],
                    provider="oauth2-google",
                    claims=claims,
                    token=token,
                )
                return user_identity
        except Exception as e:
            if not isinstance(e, IdentityException):
                logger.error(f"OAuth2 token validation failed: {e}")
            else:
                logger.info(f"OAuth2 token validation failed: {e.detail}")
        return None


class StaticAPIKeyValidator(IdentityValidator):
    def __init__(
        self,
        key_or_map: Union[str, Mapping[str, str]],
        user_email: str = "service-account@example.com",
        header_key: str = "X-API-Key",
        ttl: int = 315360000 # FIX: Added TTL parameter (default ~10 years)
    ):
        if not key_or_map:
            raise ValueError("key_or_map cannot be empty.")

        self.key_map = {}
        if isinstance(key_or_map, str):
            self.key_map = {key_or_map: user_email}
        else:
            self.key_map = key_or_map

        self.header_key = header_key
        self.ttl = ttl

    async def validate(self, request: Any) -> Optional[UserIdentity]:
        key_from_header = request.headers.get(self.header_key)
        
        if not key_from_header:
            return None

        user_email = self.key_map.get(key_from_header)

        if user_email:
            # Calculate expiration based on configured TTL
            exp_time = int(time.time() + self.ttl)
            user_identity = UserIdentity(
                id=user_email,
                email=user_email,
                exp=exp_time,
                provider="static-api-key",
                claims={
                    "sub": user_email,
                    "email": user_email,
                    "exp": exp_time,
                    "iat": int(time.time()),
                },
                token=key_from_header,
            )
            return user_identity
        return None


class CustomTokenValidator(IdentityValidator):
    def __init__(
        self,
        auth_callable: AuthCallable,
        header_key: str = "X-API-Key",
        scheme: Optional[str] = None,
    ):
        self.auth_callable = auth_callable
        self.header_key = header_key
        self.scheme = scheme.lower().strip() + " " if scheme else None
        self.scheme_len = len(self.scheme) if self.scheme else 0

    async def validate(self, request: Any) -> Optional[UserIdentity]:
        token_from_header = request.headers.get(self.header_key)

        if not token_from_header:
            return None

        token: str
        if self.scheme:
            if not token_from_header.lower().startswith(self.scheme):
                return None
            token = token_from_header[self.scheme_len :]
        else:
            token = token_from_header

        if not token:
            return None

        try:
            user_identity = await self.auth_callable(token)
            if user_identity:
                if not user_identity.token:
                    user_identity.token = token
                return user_identity
        except Exception as e:
            logger.error(f"Error in CustomTokenValidator auth_callable: {e}")
        return None


class IAPTokenValidator(IdentityValidator):
    def __init__(self, audience: str, authorization_header_key: str = "X-Goog-Iap-Jwt-Assertion"):
        if not HAS_GOOGLE_AUTH:
            raise ImportError("google-auth library required for IAPTokenValidator.")
        self.audience = audience
        self.authorization_header_key = authorization_header_key
        get_iap_public_keys()

    async def validate(self, request: Any) -> Optional[UserIdentity]:
        apikey = request.headers.get(self.authorization_header_key)
        if apikey:
            try:
                decoded_jwt = verify_iap_jwt(apikey, self.audience)
                user_identity = UserIdentity(
                    id=decoded_jwt.get("sub", "unknown"),
                    email=decoded_jwt.get("email", decoded_jwt.get("sub", "unknown")),
                    exp=decoded_jwt["exp"],
                    claims=decoded_jwt,
                    provider="google-iap-token",
                    token=apikey,
                )
                return user_identity
            except Exception as e:
                if isinstance(e, IdentityException):
                    logger.info(f"IAP token validation failed: {e.detail}")
                else:
                    logger.error(f"IAP token error: {e}")
        return None


class IAPCookieValidator(IdentityValidator):
    def __init__(self, audience: str, cookie_name: str = "__Host-GCP_IAP_AUTH_TOKEN"):
        self.audience = audience
        self.cookie_name = cookie_name
        # Pre-fetch keys only if google-auth is not available, as it's the fallback
        if not HAS_GOOGLE_AUTH:
            get_iap_public_keys()
        elif not google_requests:
            logger.warning("google-auth is installed, but google.auth.transport.requests is not available.")

    async def validate(self, request: Any) -> Optional[UserIdentity]:
        iap_cookie = request.cookies.get(self.cookie_name)
        if not iap_cookie:
            return None
            
        try:
            decoded_jwt = None
            # FIX: Prefer google-auth library for consistent validation if available
            if HAS_GOOGLE_AUTH and google_requests:
                request_adapter = google_requests.Request()
                # verify_oauth2_token handles the heavy lifting (signature, aud, exp)
                decoded_jwt = verify_oauth2_token(iap_cookie, request_adapter, audience=self.audience)
            else:
                # Fallback to local 'jose' validation
                decoded_jwt = verify_iap_cookie_jwt(iap_cookie, self.audience)

            user_identity = UserIdentity(
                id=decoded_jwt.get("sub", "unknown"),
                email=decoded_jwt.get("email", decoded_jwt.get("sub", "unknown")),
                exp=decoded_jwt["exp"],
                claims=decoded_jwt,
                provider="google-iap-cookie",
                token=iap_cookie,
            )
            return user_identity
        except Exception as e:
            # Generic catch for both google-auth errors and jose errors
            logger.info(f"IAP cookie validation failed: {e}")
        return None

import base64
import json
import binascii
class GoogleGatewayValidator(IdentityValidator):
    """
    Validates identity passed by Google Cloud API Gateway or Cloud Endpoints.
    
    When the Gateway is configured with a security definition (firebase, auth0, 
    google_id_token, etc.), it validates the JWT at the edge.
    It then forwards the request to the backend with the 'X-Apigateway-Api-Userinfo' 
    header containing the base64 encoded claims (sub, email, etc.).
    """

    def __init__(self, header_key: str = "X-Apigateway-Api-Userinfo"):
        self.header_key = header_key

    async def validate(self, request: Any) -> Optional[UserIdentity]:
        # 1. Get the header injected by the Gateway
        user_info_b64 = request.headers.get(self.header_key)
        
        if not user_info_b64:
            return None

        try:
            # 2. Fix Base64 Padding
            # Google sometimes sends unpadded base64url strings
            user_info_b64 += "=" * ((4 - len(user_info_b64) % 4) % 4)
            
            # 3. Decode
            user_info_bytes = base64.urlsafe_b64decode(user_info_b64)
            user_info_str = user_info_bytes.decode("utf-8")
            user_info = json.loads(user_info_str)

            # 4. Map to UserIdentity
            # API Gateway has already validated expiration (exp), so we trust it.
            # We set a short internal expiration (300s) just for the object life.
            user_identity = UserIdentity(
                id=user_info.get("sub", "unknown"),
                # API Gateway mapping varies. Try 'email' then fallback to 'sub'
                email=user_info.get("email", user_info.get("sub")),
                exp=int(time.time() + 300), 
                provider="google-api-gateway",
                claims=user_info,
                token=None # The gateway usually strips the original Authorization header
            )
            
            logger.info(f"Gateway API validation succeeded for {user_identity.email}")
            return user_identity

        except (binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.warning(f"Failed to decode Gateway header: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in GoogleGatewayValidator: {e}")
            return None