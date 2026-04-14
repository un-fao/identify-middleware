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

# tests/test_jwt_utils.py
import pytest
import time
from unittest.mock import patch, Mock
import httpx
import jwt

from identify_middleware.shared.jwt_utils import (
    check_token_expiration, 
    verify_iap_jwt, 
    verify_iap_cookie_jwt, 
    get_iap_public_keys, 
    receive_authorized_get_request,
    IdentityException
)


# Tests for `check_token_expiration`
def test_valid_token():
    decoded_jwt = {"exp": time.time() + 3600}
    try:
        check_token_expiration(decoded_jwt) # type: ignore
    except IdentityException:
        pytest.fail("IdentityException was raised for a valid token.")


def test_nearing_expiration_token():
    decoded_jwt = {"exp": time.time() + 200}
    with pytest.raises(IdentityException, match="Token expired or nearing expiration."):
        check_token_expiration(decoded_jwt, threshold=300) # type: ignore


def test_expired_token():
    decoded_jwt = {"exp": time.time() - 10}
    with pytest.raises(IdentityException, match="Token expired or nearing expiration."):
        check_token_expiration(decoded_jwt) # type: ignore


def test_missing_exp_claim():
    decoded_jwt = {}
    with pytest.raises(IdentityException, match="Token does not have an expiration claim"):
        check_token_expiration(decoded_jwt) # type: ignore


# Tests for `verify_iap_jwt`
@patch("identify_middleware.shared.jwt_utils.verify_oauth2_token")
@patch("identify_middleware.shared.jwt_utils.GoogleAuthRequest")
def test_verify_iap_jwt_success(mock_google_request, mock_verify_oauth2_token):
    mock_verify_oauth2_token.return_value = {"exp": time.time() + 3600}
    decoded_jwt = verify_iap_jwt("valid-token", "test-audience")
    assert decoded_jwt["exp"] > time.time()


@patch("identify_middleware.shared.jwt_utils.verify_oauth2_token")
@patch("identify_middleware.shared.jwt_utils.GoogleAuthRequest")
def test_verify_iap_jwt_expired(mock_google_request, mock_verify_oauth2_token):
    mock_verify_oauth2_token.side_effect = ValueError("Token has expired")
    with pytest.raises(IdentityException, match="Unauthorized: Invalid IAP token"):
        verify_iap_jwt("expired-token", "test-audience")


@patch("identify_middleware.shared.jwt_utils.verify_oauth2_token")
@patch("identify_middleware.shared.jwt_utils.GoogleAuthRequest")
def test_verify_iap_jwt_invalid_token(mock_google_request, mock_verify_oauth2_token):
    mock_verify_oauth2_token.side_effect = ValueError("Signature verification failed")
    with pytest.raises(IdentityException, match="Unauthorized: Invalid IAP token"):
        verify_iap_jwt("invalid-token", "test-audience")


# Tests for `get_iap_public_keys`
@patch("identify_middleware.shared.jwt_utils.httpx.Client")
def test_get_iap_public_keys_success(mock_client):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"key1": "value1"}
    mock_response.raise_for_status.return_value = None
    
    mock_client.return_value.__enter__.return_value.get.return_value = mock_response

    # Clear cache before test
    get_iap_public_keys.cache_clear()
    
    keys = get_iap_public_keys()
    assert keys == {"key1": "value1"}
    mock_client.return_value.__enter__.return_value.get.assert_called_once_with("https://www.gstatic.com/iap/verify/public_keys")

    # Test caching
    keys_cached = get_iap_public_keys()
    assert keys_cached == {"key1": "value1"}
    # Assert get was still only called once
    mock_client.return_value.__enter__.return_value.get.assert_called_once()


@patch("identify_middleware.shared.jwt_utils.httpx.Client")
def test_get_iap_public_keys_failure(mock_client):
    mock_client.return_value.__enter__.return_value.get.side_effect = httpx.RequestError("Network error", request=Mock())
    
    # Clear cache before test
    get_iap_public_keys.cache_clear()

    with pytest.raises(IdentityException, match="Could not fetch IAP public keys."):
        get_iap_public_keys()
    
    get_iap_public_keys.cache_clear()


# Tests for `verify_iap_cookie_jwt`
@patch("identify_middleware.shared.jwt_utils.ECAlgorithm.from_jwk")
@patch("identify_middleware.shared.jwt_utils.get_iap_public_keys")
@patch("identify_middleware.shared.jwt_utils.jwt.get_unverified_header")
@patch("identify_middleware.shared.jwt_utils.jwt.decode")
def test_verify_iap_cookie_jwt_success(mock_jwt_decode, mock_get_header, mock_get_iap_public_keys, mock_from_jwk):
    mock_get_header.return_value = {"kid": "k1"}
    mock_get_iap_public_keys.return_value = [{"kid": "k1", "kty": "EC"}]
    mock_from_jwk.return_value = Mock()
    mock_jwt_decode.return_value = {"email": "test@example.com", "exp": time.time() + 3600}

    decoded_jwt = verify_iap_cookie_jwt("valid-cookie-jwt", "test-audience")
    assert decoded_jwt["email"] == "test@example.com"
    mock_jwt_decode.assert_called_once()


@patch("identify_middleware.shared.jwt_utils.ECAlgorithm.from_jwk")
@patch("identify_middleware.shared.jwt_utils.get_iap_public_keys")
@patch("identify_middleware.shared.jwt_utils.jwt.get_unverified_header")
@patch("identify_middleware.shared.jwt_utils.jwt.decode")
def test_verify_iap_cookie_jwt_invalid(mock_jwt_decode, mock_get_header, mock_get_iap_public_keys, mock_from_jwk):
    mock_get_header.return_value = {"kid": "k1"}
    mock_get_iap_public_keys.return_value = [{"kid": "k1", "kty": "EC"}]
    mock_from_jwk.return_value = Mock()
    mock_jwt_decode.side_effect = jwt.InvalidTokenError("Invalid signature")

    with pytest.raises(IdentityException, match="Unauthorized: Invalid IAP cookie token"):
        verify_iap_cookie_jwt("invalid-cookie-jwt", "test-audience")


# Tests for `receive_authorized_get_request`
@patch("identify_middleware.shared.jwt_utils.id_token.verify_oauth2_token")
@patch("identify_middleware.shared.jwt_utils.requests.Request")
def test_receive_auth_get_request_success(mock_google_request, mock_verify_oauth2_token):
    mock_request = Mock()
    mock_request.headers = {"Authorization": "Bearer valid-token"}
    mock_verify_oauth2_token.return_value = {"email": "user@example.com", "exp": time.time() + 3600}

    claims = receive_authorized_get_request(mock_request)
    assert claims["email"] == "user@example.com"


@patch("identify_middleware.shared.jwt_utils.id_token.verify_oauth2_token")
@patch("identify_middleware.shared.jwt_utils.requests.Request")
def test_receive_auth_get_request_expired(mock_google_request, mock_verify_oauth2_token):
    mock_request = Mock()
    mock_request.headers = {"Authorization": "Bearer expired-token"}
    mock_verify_oauth2_token.side_effect = ValueError("Token has expired")

    with pytest.raises(IdentityException, match="Invalid Bearer token: Token has expired"):
        receive_authorized_get_request(mock_request)


def test_receive_auth_get_request_no_header():
    mock_request = Mock()
    mock_request.headers = {}
    assert receive_authorized_get_request(mock_request) is None


def test_receive_auth_get_request_wrong_scheme():
    mock_request = Mock()
    mock_request.headers = {"Authorization": "Basic some-creds"}
    assert receive_authorized_get_request(mock_request) is None


def test_receive_auth_get_request_malformed_header():
    mock_request = Mock()
    mock_request.headers = {"Authorization": "Bearer"} # Missing token
    assert receive_authorized_get_request(mock_request) is None