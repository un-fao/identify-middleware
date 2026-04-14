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

# from identify_middleware.shared.keycloak_validator import KeycloakRestValidator

# keycloak_validator = KeycloakRestValidator(
#     server_url="https://auth.your-domain.com",
#     realm="your-realm",
#     client_id="middleware-service-account",
#     client_secret="************"
# )

# # Add to your middleware list
# middleware = IdentifyMiddleware(app, validators=[
#     # SessionPersistenceValidator(), # Always first
#     keycloak_validator,            # Then check Keycloak
#     # Oauth2Validator()            # Fallback
# ])


import logging
import time
from typing import Optional, Any, Dict
import httpx
from identify_middleware.shared.models import UserIdentity
from identify_middleware.shared.validators import IdentityValidator
from identify_middleware.shared.jwt_utils import IdentityException

logger = logging.getLogger(__name__)

class KeycloakRestValidator(IdentityValidator):
    """
    Validates/Enriches an identity by querying the Keycloak Admin REST API.
    
    This is useful when you have an email/ID from a trusted upstream source 
    (like GCP Workforce Identity or IAP) and you need to fetch the full 
    Keycloak user profile (groups, attributes, roles) to populate the UserIdentity.
    """

    def __init__(
        self,
        server_url: str,
        realm: str,
        client_id: str,
        client_secret: str,
        header_key: str = "X-Goog-Authenticated-User-Email",
        strip_header_prefix: str = "accounts.google.com:",
        use_service_account: bool = True
    ):
        """
        Args:
            server_url: Base URL of Keycloak (e.g., 'https://idp.example.com')
            realm: The Keycloak realm name.
            client_id: Client ID with 'view-users' permission in 'realm-management'.
            client_secret: Client secret for the service account.
            header_key: The header containing the user's email/id (default: IAP email header).
            strip_header_prefix: Prefix to strip from the header value (common in GCP IAP).
            use_service_account: If True, uses client_credentials flow to auth against Admin API.
        """
        self.server_url = server_url.rstrip('/')
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.header_key = header_key
        self.strip_header_prefix = strip_header_prefix
        
        # Internal cache for the Admin API Access Token
        self._admin_token: Optional[str] = None
        self._admin_token_exp: float = 0

    async def _get_admin_token(self) -> str:
        """Fetches and caches a technical token to query Keycloak Admin API."""
        if self._admin_token and time.time() < self._admin_token_exp:
            return self._admin_token

        token_url = f"{self.server_url}/realms/{self.realm}/protocol/openid-connect/token"
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(token_url, data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                })
                response.raise_for_status()
                data = response.json()
                
                self._admin_token = data["access_token"]
                # Set expiration (buffer of 30 seconds)
                self._admin_token_exp = time.time() + data.get("expires_in", 300) - 30
                return self._admin_token
            except httpx.HTTPError as e:
                logger.error(f"Failed to get Keycloak Admin Token: {e}")
                raise IdentityException(500, "Authentication service failure")

    async def _lookup_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Queries Keycloak Admin API for a user by email."""
        token = await self._get_admin_token()
        search_url = f"{self.server_url}/admin/realms/{self.realm}/users"
        
        async with httpx.AsyncClient() as client:
            try:
                # exact=True requires Keycloak 19+, otherwise standard search
                response = await client.get(
                    search_url, 
                    params={"email": email, "exact": "true"},
                    headers={"Authorization": f"Bearer {token}"}
                )
                response.raise_for_status()
                users = response.json()
                
                if not users:
                    return None
                
                # Return the first match (Keycloak emails are usually unique)
                return users[0]
            except httpx.HTTPError as e:
                logger.error(f"Keycloak User Lookup failed: {e}")
                return None

    async def validate(self, request: Any) -> Optional[UserIdentity]:
        # 1. Extract the Identifier (Email) from the request
        # This example defaults to reading the trusted IAP header, but you could
        # extract it from a Bearer token or other source.
        user_identifier = request.headers.get(self.header_key)
        
        if not user_identifier:
            return None

        # Clean the identifier (GCP IAP sends 'accounts.google.com:user@example.com')
        if self.strip_header_prefix and user_identifier.startswith(self.strip_header_prefix):
            user_identifier = user_identifier[len(self.strip_header_prefix):]

        # 2. Query Keycloak
        try:
            kc_user = await self._lookup_user_by_email(user_identifier)
            
            if not kc_user:
                logger.warning(f"User {user_identifier} found in headers but NOT in Keycloak.")
                return None

            # 3. Construct UserIdentity from Keycloak Data
            # We use the Keycloak ID as the primary ID, but keep the email
            user_identity = UserIdentity(
                id=kc_user.get("id"),
                email=kc_user.get("email"),
                exp=int(time.time() + 3600), # Artificial expiration for this lookup
                provider="keycloak-rest-api",
                claims={
                    "sub": kc_user.get("id"),
                    "username": kc_user.get("username"),
                    "email_verified": kc_user.get("emailVerified"),
                    "attributes": kc_user.get("attributes", {}),
                    "groups": kc_user.get("groups", []) # NOTE: Groups usually require a separate API call or mapper
                },
                token=None # We don't have a user token, just the identity
            )
            logger.info(f"Keycloak REST validation succeeded for {user_identity.email}")
            return user_identity

        except IdentityException as ie:
            # Re-raise known identity exceptions (like auth failure)
            raise ie
        except Exception as e:
            logger.error(f"Unexpected error in KeycloakRestValidator: {e}")
            return None