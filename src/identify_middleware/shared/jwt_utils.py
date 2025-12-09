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

import time
import logging
import base64
import json
from functools import lru_cache
from typing import Mapping, Any, Optional
import httpx
from jose import jwt, exceptions

try:
    from google.oauth2.id_token import verify_oauth2_token
    from google.auth.transport.requests import Request as GoogleAuthRequest
    from google.auth.transport import requests
    from google.oauth2 import id_token
except ImportError:
    verify_oauth2_token = None
    GoogleAuthRequest = None
    id_token = None
    requests = None

logger = logging.getLogger(__name__)

class IdentityException(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"[{status_code}] {detail}")

IAP_PUBLIC_KEYS_URL = "https://www.gstatic.com/iap/verify/public_key-jwk"

def repair_jwt_padding(token: str) -> str:
    """
    Ensures that a JWT string has the correct padding for its base64 segments.
    IAP tokens are often stripped of padding, which causes python's base64 lib to crash.
    """
    if not token:
        return token
        
    try:
        parts = token.split('.')
        # A standard JWT has 3 parts: header.payload.signature
        if len(parts) != 3:
            return token # Return as-is, let the validator fail naturally if malformed
            
        repaired_parts = []
        for part in parts:
            missing_padding = len(part) % 4
            if missing_padding:
                part += '=' * (4 - missing_padding)
            repaired_parts.append(part)
            
        return ".".join(repaired_parts)
    except Exception:
        return token

def check_token_expiration(decoded_jwt: Mapping[str, Any], threshold: int = 300):
    current_time = time.time()
    expire_time = int(decoded_jwt.get("exp", -1))
    if expire_time == -1:
        raise IdentityException(status_code=401, detail="Token does not have an expiration claim")
    if current_time > expire_time - threshold:
        raise IdentityException(
            status_code=401, detail="Token expired or nearing expiration."
        )

def verify_iap_jwt(iap_jwt: str, audience: str) -> dict:
    # This function explicitly requires google-auth
    if not verify_oauth2_token or not GoogleAuthRequest:
        raise ImportError("google-auth library required for verify_iap_jwt.")
    try:
        # Fix padding before passing to google-auth
        # (Though google-auth is usually robust, explicit fixing prevents edge cases)
        clean_jwt = repair_jwt_padding(iap_jwt)
        
        google_request = GoogleAuthRequest()
        decoded_jwt = verify_oauth2_token(
            id_token=clean_jwt, request=google_request, audience=audience
        )
        return decoded_jwt
    except ValueError as e:
        # Catch padding errors explicitly
        if "padding" in str(e).lower():
             logger.error("Padding error detected in verify_iap_jwt even after repair attempt.")
        raise IdentityException(
            status_code=403, detail=f"Unauthorized: Invalid IAP token ({str(e)})"
        ) from e
    except Exception as e:
        logger.error(f"Unexpected error during IAP JWT validation: {e}")
        raise IdentityException(status_code=500, detail="An unexpected error occurred.") from e

@lru_cache(maxsize=1)
def get_iap_public_keys() -> dict:
    try:
        # Sync call is acceptable here as it is cached lru(1) and meant for startup/fallback
        with httpx.Client(timeout=10) as client:
            response = client.get(IAP_PUBLIC_KEYS_URL)
            response.raise_for_status()
        return response.json().get("keys", [])
    except Exception as e:
        logger.error(f"Error fetching IAP public keys: {e}")
        raise IdentityException(status_code=500, detail="Could not fetch IAP public keys.") from e

def decode_iap_jwt(token):
    """
    Manually decodes a JWT payload without verifying signature. 
    Useful for debugging or extracting claims when signature is validated elsewhere.
    """
    parts = token.split('.')
    if len(parts) < 2:
        raise ValueError("Invalid Token Format")
        
    payload = parts[1]
    
    # Calculate missing padding
    missing_padding = len(payload) % 4
    if missing_padding:
        payload += '=' * (4 - missing_padding)
    
    # Now decode
    decoded_bytes = base64.urlsafe_b64decode(payload)
    return json.loads(decoded_bytes)

def verify_iap_cookie_jwt(iap_jwt_cookie: str, audience: str) -> dict:
    """
    Verifies the IAP JWT using local `jose` library. 
    This is the fallback method if google-auth is not used.
    """
    try:
        public_keys = get_iap_public_keys()
        
        # Fix padding for jose
        clean_jwt = repair_jwt_padding(iap_jwt_cookie)
        
        decoded_jwt = jwt.decode(
            clean_jwt,
            public_keys,
            algorithms=["ES256"],
            audience=audience,
            options={"verify_exp": True, "verify_aud": True}
        )
        return decoded_jwt
    except exceptions.JWTError as e:
        logger.warning(f"IAP cookie JWT validation failed (jose): {e}")
        raise IdentityException(status_code=403, detail=f"Unauthorized: Invalid IAP cookie token") from e
    except Exception as e:
        logger.error(f"Unexpected error during IAP cookie JWT validation: {e}")
        raise IdentityException(status_code=500, detail="An unexpected error occurred.") from e

def receive_authorized_get_request(request: Any) -> Optional[dict]:
    if not id_token or not requests:
         return None
         
    auth_header = request.headers.get("Authorization")
    if auth_header:
        try:
            auth_type, creds = auth_header.split(" ", 1)
        except ValueError:
            return None

        if auth_type.lower() == "bearer":
            try:
                # Ensure we handle padding for standard OIDC headers too
                creds = repair_jwt_padding(creds)
                
                claims = id_token.verify_oauth2_token(creds, requests.Request())
                if "email" not in claims and "sub" in claims:
                    claims["email"] = claims["sub"]
                return claims
            except ValueError as e:
                logger.info(f"OAuth2 Bearer token validation failed: {e}")
                raise IdentityException(status_code=401, detail=f"Invalid Bearer token: {e}") from e
    return None