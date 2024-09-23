import json
import logging
import os
import pytest
import requests
import requests_mock

from faker import Faker
from dotenv import dotenv_values
from unittest.mock import MagicMock, patch, call

from ..client import (
    parse_json,
    DSpaceClient,
    DSpaceObject,
    SimpleDSpaceObject,
    Bitstream,
    Bundle,
    Item,
    Community,
    Collection,
    User,
    Group,
)

faker = Faker()

# Test for the parse_json function


def test_parse_json_valid():
    """Test for valid JSON response"""
    valid_json = {"key": "value"}  # Example of a valid JSON
    with requests_mock.Mocker() as m:
        m.get("https://example.com", text=json.dumps(valid_json))
        response = requests.get("https://example.com")
        assert parse_json(response) == valid_json


def test_parse_json_invalid():
    """Test for invalid JSON response"""
    with requests_mock.Mocker() as m:
        m.get("https://example.com", text="not a valid json")
        response = requests.get("https://example.com")
        assert parse_json(response) is None


def test_parse_json_none_response():
    """Test for None response"""
    assert parse_json(None) == {}


def test_parse_json_logs_error(caplog):
    """Test for logging error when JSON parsing fails"""
    invalid_json = faker.text()  # Generate some random text that isn't valid JSON
    with requests_mock.Mocker() as m:
        m.get("https://example.com", text=invalid_json)
        response = requests.get("https://example.com")
        parse_json(response)
        assert "Error parsing response JSON" in caplog.text


# Test for the DSpaceClient class


@pytest.fixture
def mock_group():
    return Group({"name": "New Group"})


@pytest.fixture
def dspace_client():
    # Setup DSpaceClient with mocked session
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )
    client.session = MagicMock()
    return client


@pytest.fixture
def dspace_client_dso(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )
    mocker.patch.object(
        client,
        "fetch_resource",
        return_value={
            "_embedded": {
                "searchResult": {
                    "_embedded": {
                        "objects": [
                            {
                                "_embedded": {
                                    "indexableObject": {
                                        "id": "123",
                                        "name": "Test DSO 1",
                                    }
                                }
                            },
                            {
                                "_embedded": {
                                    "indexableObject": {
                                        "id": "456",
                                        "name": "Test DSO 2",
                                    }
                                }
                            },
                        ]
                    }
                }
            }
        },
    )
    return client


@pytest.fixture
def mock_dso():
    dso = SimpleDSpaceObject()
    dso.links = {"self": {"href": "http://example.com/server/api/core/items/123"}}
    dso.uuid = "123"
    dso.type = "item"
    dso.as_dict = MagicMock(return_value={"name": "Updated DSO"})
    return dso


@pytest.fixture
def mock_item():
    item = Item()
    item.uuid = "item-uuid"
    return item


@pytest.fixture
def mock_bundle():
    bundle = Bundle({"uuid": "bundle-uuid", "name": "ORIGINAL"})
    return bundle


@pytest.fixture
def mock_user_data():
    return User({"email": "test@example.com", "firstName": "Test", "lastName": "User"})


def test_dspace_client_session_property():
    """Test that the session property is a requests.Session object"""
    d = DSpaceClient("https://example.com", "username", "password")
    assert isinstance(d.session, requests.Session)


def test_dspace_client_initialization_defaults(monkeypatch, mocker):
    # Load .env values if .env file exists
    env_path = ".env"
    env_values = {}
    if os.path.exists(env_path):
        env_values = dotenv_values(env_path)

    # Mock environment variables (or use values from .env if present)
    api_endpoint = env_values.get(
        "DSPACE_API_ENDPOINT", "http://example.com/server/api"
    )
    username = env_values.get("DSPACE_API_USERNAME", "admin")
    password = env_values.get("DSPACE_API_PASSWORD", "admin")
    solr_endpoint = env_values.get("SOLR_ENDPOINT", "http://example.com:8983/solr")
    solr_auth = env_values.get("SOLR_AUTH", None)

    # Apply mocked environment variables
    monkeypatch.setenv("DSPACE_API_ENDPOINT", api_endpoint)
    monkeypatch.setenv("DSPACE_API_USERNAME", username)
    monkeypatch.setenv("DSPACE_API_PASSWORD", password)
    monkeypatch.setenv("SOLR_ENDPOINT", solr_endpoint)
    monkeypatch.setenv("SOLR_AUTH", solr_auth)

    # Mock external dependencies
    mocker.patch("requests.Session")
    mocker.patch("pysolr.Solr")

    # Initialization
    client = DSpaceClient()

    # Assertions using either the .env values or the default test values
    assert client.API_ENDPOINT == api_endpoint
    assert client.USERNAME == username
    assert client.PASSWORD == password
    assert client.SOLR_ENDPOINT == solr_endpoint
    assert client.SOLR_AUTH == solr_auth


def test_dspace_client_initialization_custom_args(monkeypatch, mocker):
    # TODO: Add test for custom arguments
    # Mock environment variables as a fallback
    monkeypatch.setenv("DSPACE_API_ENDPOINT", "http://fallback:8080/server/api")
    monkeypatch.setenv("DSPACE_API_USERNAME", "fallbackUser")
    monkeypatch.setenv("DSPACE_API_PASSWORD", "fallbackPass")
    monkeypatch.setenv("SOLR_ENDPOINT", "http://fallback:8983/solr")
    monkeypatch.setenv("SOLR_AUTH", "env-solr-auth-token")

    # Mock external dependencies
    mocker.patch("requests.Session")
    mocker.patch("pysolr.Solr")

    client_from_env = DSpaceClient()

    # Assertions for the environment variable fallback
    assert (
        client_from_env.SOLR_AUTH == "env-solr-auth-token"
    )  # Derived from the env var


def test_authenticate_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the session.post to simulate a successful login
    mocker.patch.object(
        client.session,
        "post",
        return_value=MagicMock(
            status_code=200, headers={"Authorization": "Bearer token123"}
        ),
    )

    # Mock the session.get to return authenticated status
    mocker.patch.object(
        client.session,
        "get",
        return_value=MagicMock(status_code=200, json=lambda: {"authenticated": True}),
    )

    # Call the authenticate method
    result = client.authenticate()

    # Assert that authentication was successful
    assert result is True
    assert client.session.headers["Authorization"] == "Bearer token123"


def test_authenticate_invalid_credentials(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="wrong", password="wrong"
    )

    # Mock the session.post to return a 401 Unauthorized
    mocker.patch.object(client.session, "post", return_value=MagicMock(status_code=401))

    # Call the authenticate method
    result = client.authenticate()

    # Assert that authentication fails with invalid credentials
    assert result is False


def test_authenticate_csrf_failure_then_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the session.post to first return a 403 Forbidden, then a success
    mocker.patch.object(
        client.session,
        "post",
        side_effect=[
            MagicMock(status_code=403),  # First attempt fails
            MagicMock(
                status_code=200, headers={"Authorization": "Bearer token123"}
            ),  # Second attempt succeeds
        ],
    )

    # Mock the session.get to return authenticated status
    mocker.patch.object(
        client.session,
        "get",
        return_value=MagicMock(status_code=200, json=lambda: {"authenticated": True}),
    )

    # Call the authenticate method
    result = client.authenticate()

    # Assert that authentication succeeds after retry
    assert result is True
    assert client.session.headers["Authorization"] == "Bearer token123"


def test_authenticate_too_many_retries(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the session.post to always return a 403 Forbidden
    mocker.patch.object(
        client.session,
        "post",
        side_effect=[
            MagicMock(status_code=403, text="CSRF token invalid"),
            MagicMock(status_code=403, text="CSRF token invalid"),
        ],
    )

    # Mock logging.error to verify error logging
    mocked_error_log = mocker.patch("logging.error")

    # Call the authenticate method
    result = client.authenticate()

    # Assert that the method returns False after too many retries
    assert result is False
    assert mocked_error_log.called
    mocked_error_log.assert_called_with(
        "Too many retries updating token: 403: CSRF token invalid"
    )


def test_authenticate_status_not_authenticated(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the session.post to simulate a successful login
    mocker.patch.object(
        client.session,
        "post",
        return_value=MagicMock(
            status_code=200, headers={"Authorization": "Bearer token123"}
        ),
    )

    # Mock the session.get to return a non-authenticated response
    mocker.patch.object(
        client.session,
        "get",
        return_value=MagicMock(status_code=200, json=lambda: {"authenticated": False}),
    )

    # Call the authenticate method
    result = client.authenticate()

    # Assert that the method returns False due to non-authenticated status
    assert result is False


def test_refresh_token(mocker):
    # Mock the api_post method to simulate a successful POST request with a CSRF token
    mock_response = MagicMock()
    mock_response.headers = {"DSPACE-XSRF-TOKEN": "new-csrf-token"}
    mocker.patch.object(DSpaceClient, "api_post", return_value=mock_response)

    # Mock the update_token method to verify it's called with the correct response
    mock_update_token = mocker.patch.object(DSpaceClient, "update_token")

    # Initialize the DSpaceClient and call refresh_token
    client = DSpaceClient()
    client.refresh_token()

    # Assert the update_token was called with the response from api_post
    mock_update_token.assert_called_once_with(mock_response)


def test_get_authn_status_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the session.get to simulate a successful response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"authenticated": True}

    # Patch the session.get method
    mocker.patch.object(client.session, "get", return_value=mock_response)

    # Call the get_authn_status method
    response = client.get_authn_status()

    # Assert that session.get was called with the correct URL and headers
    client.session.get.assert_called_once_with(
        "http://example.com/authn/status", headers=client.request_headers
    )

    # Assert that the response object returned is correct
    assert response.status_code == 200
    assert response.json() == {"authenticated": True}


def test_get_authn_status_failure(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the session.get to simulate a failed response
    mock_response = MagicMock()
    mock_response.status_code = 403
    mock_response.json.return_value = {"authenticated": False}

    # Patch the session.get method
    mocker.patch.object(client.session, "get", return_value=mock_response)

    # Call the get_authn_status method
    response = client.get_authn_status()

    # Assert that session.get was called with the correct URL and headers
    client.session.get.assert_called_once_with(
        "http://example.com/authn/status", headers=client.request_headers
    )

    # Assert that the response object returned is correct for a failure
    assert response.status_code == 403
    assert response.json() == {"authenticated": False}


def test_logout_success(mocker):
    # Setup API endpoint and username for the test
    api_endpoint = "http://example.com/server/api"
    username = "testuser"

    # Initialize the DSpaceClient
    client = DSpaceClient(
        api_endpoint=api_endpoint, username=username, password="password"
    )

    # Mock the POST request to the logout endpoint to return 204 No Content
    logout_url = f"{api_endpoint}/authn/logout"
    with requests_mock.Mocker() as m:
        m.post(logout_url, status_code=204)

        # Mock logging to verify the logout message
        mock_logger = mocker.patch.object(logging, "info")

        # Call the logout method
        result = client.logout()

        # Verify the logout was successful
        assert result is True, "Logout should return True on success"

        # Verify logging was called with the correct message
        mock_logger.assert_called_once_with(f"User {username} logged out successfully")


def test_api_get_success(mocker):
    url = "http://example.com/server/api/test"

    # Mock the `session.get` method
    mock_response = MagicMock(status_code=200, json=lambda: {"key": "value"})
    mocker.patch.object(requests.Session, "get", return_value=mock_response)

    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Call the `api_get` method
    response = client.api_get(url)

    # Assertions
    assert response.status_code == 200
    assert response.json() == {"key": "value"}


def test_api_post_uri_success(mocker):
    api_endpoint = "http://example.com/server/api"
    url = f"{api_endpoint}/test"
    uri_list = "http://example.com/server/api/other/object\nhttp://example.com/server/api/another/object"

    client = DSpaceClient(api_endpoint=api_endpoint, username="admin", password="admin")

    # Mock the `session.post` method
    mock_response = MagicMock(status_code=200, text="success")
    mocker.patch.object(requests.Session, "post", return_value=mock_response)

    # Call the `api_post_uri` method
    response = client.api_post_uri(url, None, uri_list)

    # Assertions
    assert response.status_code == 200
    assert response.text == "success"


def test_api_post_uri_unauthorized(mocker):
    url = "http://example.com/server/api/test"
    uri_list = "http://example.com/server/api/other/object"

    # Mock the `session.post` method to simulate unauthorized access (401)
    mock_response = MagicMock(status_code=401)
    mocker.patch.object(requests.Session, "post", return_value=mock_response)

    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Call the `api_post_uri` method
    response = client.api_post_uri(url, None, uri_list)

    # Assertions
    assert response.status_code == 401


def test_api_post_uri_csrf_retry(mocker):
    url = "http://example.com/server/api/test"
    uri_list = "http://example.com/server/api/other/object"

    # Mock the session.post method to simulate the CSRF failure followed by success
    mock_response_403 = MagicMock(
        status_code=403, json=lambda: {"message": "CSRF token invalid"}
    )
    mock_response_200 = MagicMock(status_code=200, text="success")

    # Mock the session.post to return 403 on first call and 200 on retry
    mocker.patch.object(
        requests.Session, "post", side_effect=[mock_response_403, mock_response_200]
    )

    # Mock logging.debug to observe the retry
    mocked_log_debug = mocker.patch("logging.debug")

    # Instantiate the client
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Call the api_post_uri method (initial call with retry=False, so it retries on 403)
    response = client.api_post_uri(url, None, uri_list, retry=False)

    # Assertions
    assert response.status_code == 200
    mocked_log_debug.assert_called_with("Retrying request with updated CSRF token")


def test_api_post_retry_on_csrf_failure(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )
    url = "http://example.com/api/test"
    params = {"test": "param"}
    json_data = {"key": "value"}
    csrf_failure_response = MagicMock(status_code=403, text="CSRF token invalid")
    success_response = MagicMock(status_code=200, json=lambda: {"success": True})
    # Mock session.post to simulate CSRF token failure followed by a successful retry
    mocked_post = mocker.patch.object(
        client.session, "post", side_effect=[csrf_failure_response, success_response]
    )
    # Mock parse_json to return a simulated response indicating CSRF token failure
    mocker.patch(
        "dspace_rest_client.client.parse_json",
        side_effect=[{"message": "CSRF token invalid"}, {"success": True}],
    )
    # Mock logging.debug to assert it gets called with the expected message
    mocked_log_debug = mocker.patch("logging.debug")
    # Call the api_post method
    response = client.api_post(url, params=params, json=json_data)
    # Verify that the method returns the success response after retrying
    assert response.json() == {"success": True}
    # Verify that session.post was called twice
    assert mocked_post.call_count == 2
    # Verify the first call to session.post was with the initial parameters
    mocked_post.assert_has_calls(
        [
            call(url, json=json_data, params=params, headers=client.request_headers),
            call(url, json=json_data, params=params, headers=client.request_headers),
        ]
    )
    # Ensure that logging.debug was called during the test
    mocked_log_debug.assert_called()


def test_api_post_success(mocker):
    url = "http://example.com/server/api/test"
    json_data = {"key": "value"}

    # Mock the `session.post` method
    mock_response = MagicMock(status_code=200, json=lambda: json_data)
    mocker.patch.object(requests.Session, "post", return_value=mock_response)

    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Call the `api_post` method
    response = client.api_post(url, None, json_data)

    # Assertions
    assert response.status_code == 200
    assert response.json() == json_data


def test_api_post_unauthorized(mocker):
    url = "http://example.com/server/api/test"
    json_data = {"key": "value"}

    # Mock the `session.post` method to simulate unauthorized access (401)
    mock_response = MagicMock(status_code=401)
    mocker.patch.object(requests.Session, "post", return_value=mock_response)

    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Call the `api_post` method
    response = client.api_post(url, None, json_data)

    # Assertions
    assert response.status_code == 401


def test_api_post_csrf_retry(mocker):
    url = "http://example.com/server/api/test"
    json_data = {"key": "value"}

    # Mock the `session.post` method to simulate the CSRF failure followed by success
    mock_response_403 = MagicMock(
        status_code=403, json=lambda: {"message": "CSRF token invalid"}
    )
    mock_response_200 = MagicMock(status_code=200, json=lambda: json_data)

    # Mock the `session.post` to return the 403 response first, then 200 on retry
    mocker.patch.object(
        requests.Session, "post", side_effect=[mock_response_403, mock_response_200]
    )

    # Mock the token update logic to ensure the token gets refreshed
    mocker.patch.object(DSpaceClient, "update_token")

    # Create DSpaceClient instance
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Call the `api_post` method to trigger CSRF retry logic (start with retry=False)
    response = client.api_post(url, None, json_data, retry=False)

    # Assertions to ensure the retry was successful after the CSRF token failure
    assert response.status_code == 200
    assert response.json() == json_data


def test_api_post_uri_retry_on_csrf_failure(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )
    url = "http://example.com/api/test"
    params = {"test": "param"}
    uri_list = "http://example.com/api/item/1"
    csrf_failure_response = MagicMock(
        status_code=403, json=lambda: {"message": "CSRF token invalid"}
    )
    success_response = MagicMock(status_code=200, json=lambda: {"success": True})
    # Mock session.post to simulate CSRF token failure followed by a successful retry
    mocked_post = mocker.patch.object(
        client.session, "post", side_effect=[csrf_failure_response, success_response]
    )
    # Mock logging.debug to assert it gets called with the expected message
    mocked_log_debug = mocker.patch("logging.debug")
    # Call the api_post_uri method
    response = client.api_post_uri(url, params=params, uri_list=uri_list)
    # Verify that the method returns the success response after retrying
    assert response.json() == {"success": True}
    # Verify that session.post was called twice (initial call + retry)
    assert mocked_post.call_count == 2
    # Verify the first call to session.post was with the initial parameters
    mocked_post.assert_has_calls(
        [
            call(
                url,
                data=uri_list,
                params=params,
                headers=client.list_request_headers,
            ),
            call(
                url,
                data=uri_list,
                params=params,
                headers=client.list_request_headers,
            ),
        ]
    )
    # Verify that logging.debug was called during the test
    mocked_log_debug.assert_called()


def test_api_put_success(mocker):
    url = "http://example.com/server/api/test"
    json_data = {"key": "updated value"}

    # Mock the `session.put` method to simulate a successful PUT request
    mock_response = MagicMock(status_code=200, json=lambda: json_data)
    mocker.patch.object(requests.Session, "put", return_value=mock_response)

    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Call the `api_put` method
    response = client.api_put(url, params=None, json=json_data)

    # Assertions
    assert response.status_code == 200
    assert response.json() == json_data


def test_api_put_csrf_retry(mocker):
    url = "http://example.com/server/api/test"
    json_data = {"key": "value for retry"}

    # Simulate CSRF failure on first attempt and success on retry
    mock_response_403 = MagicMock(
        status_code=403, json=lambda: {"message": "CSRF token invalid"}
    )
    mock_response_200 = MagicMock(status_code=200, json=lambda: json_data)

    # Patch `requests.Session.put` to return 403 first, then 200 after retry
    mocker.patch.object(
        requests.Session, "put", side_effect=[mock_response_403, mock_response_200]
    )

    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Call the `api_put` method with retry=False (should retry internally after CSRF failure)
    response = client.api_put(url, params=None, json=json_data, retry=False)

    # Assertions
    assert response.status_code == 200
    assert response.json() == json_data


def test_api_put_retry_limit(mocker):
    url = "http://example.com/server/api/test"
    json_data = {"key": "retry limit test"}

    # Simulate CSRF failure for both attempts
    mock_response_403 = MagicMock(
        status_code=403, json=lambda: {"message": "CSRF token invalid"}
    )

    # Patch `requests.Session.put` to always return 403
    mocker.patch.object(requests.Session, "put", return_value=mock_response_403)

    # Patch the logger to catch warnings
    mock_warning = mocker.patch("logging.warning")

    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Call the `api_put` method with retry=True (but it will fail due to CSRF)
    response = client.api_put(url, params=None, json=json_data, retry=True)

    # Assertions
    assert response.status_code == 403
    mock_warning.assert_called_once()


def test_api_delete_success(mocker):
    url = "http://example.com/server/api/test"

    # Mock the `session.delete` method to simulate a successful DELETE request (204 No Content)
    mock_response = MagicMock(status_code=204)
    mocker.patch.object(requests.Session, "delete", return_value=mock_response)

    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Call the `api_delete` method
    response = client.api_delete(url, params={})

    # Assertions
    assert response.status_code == 204


def test_api_delete_csrf_retry(mocker):
    url = "http://example.com/server/api/test"

    # Simulate CSRF failure on first request, then success on retry
    mock_response_403 = MagicMock(
        status_code=403, json=lambda: {"message": "CSRF token invalid"}
    )
    mock_response_204 = MagicMock(status_code=204)

    # Patch `requests.Session.delete` to return 403 first, then 204 after retry
    mocker.patch.object(
        requests.Session, "delete", side_effect=[mock_response_403, mock_response_204]
    )

    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Call the `api_delete` method to trigger CSRF retry
    response = client.api_delete(url, params={}, retry=False)

    # Assertions
    assert response.status_code == 204


def test_api_delete_retry_limit(mocker):
    url = "http://example.com/server/api/test"

    # Simulate CSRF failure for both attempts
    mock_response_403 = MagicMock(
        status_code=403, json=lambda: {"message": "CSRF token invalid"}
    )

    # Patch `requests.Session.delete` to always return 403
    mocker.patch.object(requests.Session, "delete", return_value=mock_response_403)

    # Patch the logger to catch warnings
    mock_warning = mocker.patch("logging.warning")

    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Call the `api_delete` method with retry=True (but it will fail due to CSRF)
    response = client.api_delete(url, params={}, retry=True)

    # Assertions
    assert response.status_code == 403
    mock_warning.assert_called_once()


def test_api_patch_success(mocker):
    url = "http://example.com/server/api/items/1234"
    operation = "replace"
    path = "/metadata/dc.title/0/value"
    value = "Updated Title"

    # Mock the `session.patch` method to simulate a successful PATCH request
    mock_response = MagicMock(
        status_code=200, json=lambda: {"type": "item", "id": "1234"}
    )
    mocker.patch.object(requests.Session, "patch", return_value=mock_response)

    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Call the `api_patch` method
    response = client.api_patch(url, operation, path, value)

    # Assertions
    assert response.status_code == 200
    assert response.json() == {"type": "item", "id": "1234"}


def test_api_patch_csrf_retry(mocker):
    url = "http://example.com/server/api/items/1234"
    operation = "add"
    path = "/metadata/dc.contributor.author/-"
    value = "New Author"

    # Simulate CSRF failure on first attempt and success on retry
    mock_response_403 = MagicMock(
        status_code=403, json=lambda: {"message": "CSRF token invalid"}
    )
    mock_response_200 = MagicMock(
        status_code=200, json=lambda: {"type": "item", "id": "1234"}
    )

    # Patch `requests.Session.patch` to return 403 first, then 200 after retry
    mocker.patch.object(
        requests.Session, "patch", side_effect=[mock_response_403, mock_response_200]
    )

    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Call the `api_patch` method with retry=False (should retry internally after CSRF failure)
    response = client.api_patch(url, operation, path, value, retry=False)

    # Assertions
    assert response.status_code == 200
    assert response.json() == {"type": "item", "id": "1234"}


def test_api_patch_missing_arguments(mocker):
    # Mock the logging.error method to ensure it is called on missing arguments
    mock_log_error = mocker.patch("logging.error")

    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Call the `api_patch` method with missing arguments
    response = client.api_patch(url=None, operation=None, path=None, value=None)

    # Ensure that no request is made and logging.error is called
    assert response is None
    mock_log_error.assert_called_once()


def test_api_patch_invalid_path(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock logging.error without using 'with' context manager
    mocked_log_error = mocker.patch("logging.error")

    # Call the api_patch method with an invalid path (None)
    result = client.api_patch(
        url="http://example.com/api/test", operation="add", path=None, value="test"
    )

    # Verify the method returns None
    assert result is None

    # Optionally verify logging.error was called
    mocked_log_error.assert_called()


def test_api_patch_missing_value(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock logging.error without using 'with' context manager
    mocked_log_error = mocker.patch("logging.error")

    # Call the api_patch method with a missing value (None)
    result = client.api_patch(
        url="http://example.com/api/test",
        operation="add",
        path="/metadata/dc.title",
        value=None,
    )

    # Verify the method returns None
    assert result is None

    # Optionally verify logging.error was called
    mocked_log_error.assert_called()


def test_api_patch_move_operation(mocker):
    # Initialize DSpaceClient
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Define the original and new paths for the move operation
    original_path = "/original/path"
    new_path = "/new/path"

    # Mock session.patch to simulate the API response
    mocked_patch = mocker.patch.object(
        client.session, "patch", return_value=MagicMock(status_code=200)
    )

    # Call the api_patch method with the 'move' operation
    client.api_patch(
        url="http://example.com/api/test",
        operation="move",
        path=new_path,
        value=original_path,
    )

    # Verify that session.patch was called once
    mocked_patch.assert_called_once()

    # Get the request body (JSON data) sent with the patch request
    request_data = mocked_patch.call_args.kwargs["json"][0]

    # Assert that the correct 'from' and 'path' values are included in the request
    assert request_data["from"] == original_path
    assert request_data["path"] == new_path

    # Assertion to verify the patch request is sent to the correct URL
    assert mocked_patch.call_args[0][0] == "http://example.com/api/test"


def test_api_patch_csrf_retry(mocker):
    # Create an instance of DSpaceClient
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the session.patch method to return a 403 response, indicating CSRF token failure
    mock_response_403 = MagicMock(status_code=403, text="CSRF token expired")
    mocker.patch.object(client.session, "patch", return_value=mock_response_403)

    # Mock the parse_json method to simulate a CSRF token error
    mocker.patch(
        "dspace_rest_client.client.parse_json",
        return_value={"message": "CSRF token expired"},
    )

    # Mock logging.debug to capture the retry message
    mock_debug_log = mocker.patch("dspace_rest_client.client.logging.debug")

    # Call the api_patch method with retry set to False (initial attempt)
    client.api_patch(
        url="http://example.com/api/test",
        operation="add",
        path="/metadata/dc.title",
        value="test",
        retry=False,
    )

    # Ensure logging.debug was called with the retry message
    mock_debug_log.assert_called_with("Retrying request with updated CSRF token")


def test_api_patch_retry_limit(mocker):
    # Create an instance of DSpaceClient
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the session.patch method to return a 403 response twice, indicating retry limit reached
    mock_response_403 = MagicMock(status_code=403, text="Forbidden")
    mocker.patch.object(client.session, "patch", return_value=mock_response_403)

    # Mock the parse_json method to simulate a CSRF token error
    mocker.patch(
        "dspace_rest_client.client.parse_json",
        return_value={"message": "CSRF token expired"},
    )

    # Mock logging.warning to capture the retry limit message
    mock_warning_log = mocker.patch("dspace_rest_client.client.logging.warning")

    # Call the api_patch method with retry set to True (already retried)
    client.api_patch(
        url="http://example.com/api/test",
        operation="add",
        path="/metadata/dc.title",
        value="test",
        retry=True,
    )

    # Ensure logging.warning was called with the appropriate message for retry limit reached
    mock_warning_log.assert_called_once_with(
        "Too many retries updating token: 403: Forbidden"
    )


def test_search_objects_success(dspace_client_dso):
    dsos = dspace_client_dso.search_objects(
        query="test",
        dso_type="collection",
        scope="123456789/1",
        size=10,
        page=0,
        sort="name,asc",
    )

    assert len(dsos) == 2
    assert all(isinstance(dso, DSpaceObject) for dso in dsos)
    assert dsos[0].id == "123" and dsos[1].id == "456"


def test_search_objects_failure(dspace_client_dso):
    dspace_client_dso.fetch_resource.return_value = None
    dsos = dspace_client_dso.search_objects(query="test")

    assert dsos == []


def test_fetch_resource_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"key": "value"}
    mocker.patch.object(client, "api_get", return_value=mock_response)

    result = client.fetch_resource("http://example.com/server/api/resource", {})
    assert result == {"key": "value"}


def test_fetch_resource_failure(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Mock the response to simulate a 404 error
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_response.text = "Resource not found"

    # Patch the api_get method to return the mock response
    mocker.patch.object(client, "api_get", return_value=mock_response)

    # Mock logging.error without using 'with' context manager
    mocked_log_error = mocker.patch("logging.error")

    # Call the fetch_resource method
    result = client.fetch_resource("http://example.com/server/api/nonexistent", {})

    # Assert the method returns None on failure
    assert result is None

    # Optionally verify logging.error was called
    mocked_log_error.assert_called()


def test_fetch_resource_json_parse_error(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Mock the response to simulate a successful API call
    mock_response = MagicMock()
    mock_response.status_code = 200

    # Patch the client.api_get method to return the mock response
    mocker.patch.object(client, "api_get", return_value=mock_response)

    # Patch parse_json to raise a ValueError simulating a JSON parsing error
    mocker.patch(
        "dspace_rest_client.client.parse_json",
        side_effect=ValueError("Mock JSON parse error"),
    )

    # Patch logging.error to monitor the error handling
    mock_log_error = mocker.patch("logging.error")

    # Call fetch_resource with the test URL
    result = client.fetch_resource("http://example.com/server/api/badjson", {})

    # Ensure fetch_resource returns None when a JSON parse error occurs
    assert result is None

    # Ensure logging.error was called to log the JSON parse error
    mock_log_error.assert_called_once()


def test_get_dso_valid_uuid(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the UUID method to return a valid UUID version
    mocker.patch("dspace_rest_client.client.UUID", return_value=MagicMock(version=4))

    # Mock the api_get method to return the expected data
    mock_api_get = mocker.patch.object(
        client,
        "api_get",
        return_value={"uuid": "12345678-1234-5678-1234-567812345678"},
    )

    # Call the get_dso method with a valid UUID
    result = client.get_dso(
        url="http://example.com/api/test",
        uuid="12345678-1234-5678-1234-567812345678",
    )

    # Assertions
    mock_api_get.assert_called_once_with(
        "http://example.com/api/test/12345678-1234-5678-1234-567812345678",
        None,
        None,
    )
    assert result == {"uuid": "12345678-1234-5678-1234-567812345678"}


def test_get_dso_invalid_uuid(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the UUID method to raise a ValueError (simulate invalid UUID)
    mocker.patch(
        "dspace_rest_client.client.UUID", side_effect=ValueError("Invalid UUID")
    )

    # Call the get_dso method with an invalid UUID
    result = client.get_dso(url="http://example.com/api/test", uuid="invalid_uuid")

    # Assertions
    assert result is None


def test_create_dso_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )
    success_response = MagicMock(
        status_code=201, json=lambda: {"type": "item", "uuid": "1234-5678"}
    )
    mocker.patch.object(client, "api_post", return_value=success_response)
    # Mock logging.info without using 'with' context manager
    mocked_info_log = mocker.patch.object(logging, "info")
    # Call the create_dso method
    response = client.create_dso(
        "http://example.com/server/api/items", None, {"name": "New DSO"}
    )
    # Assert the response status code
    assert response.status_code == 201
    # Verify that logging.info was called with the correct message
    mocked_info_log.assert_called_with("item 1234-5678 created successfully!")


def test_create_dso_failure(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )
    failure_response = MagicMock(status_code=400, text="Bad request error")
    mocker.patch.object(client, "api_post", return_value=failure_response)

    with patch.object(logging, "error") as mock_error_log:
        response = client.create_dso(
            "http://example.com/server/api/items", None, {"invalid": "data"}
        )

        assert response.status_code == 400
        mock_error_log.assert_called_with(
            "create operation failed: 400: Bad request error (http://example.com/server/api/items)"
        )


def test_update_dso_success(mocker, mock_dso):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Mock the success response
    success_response = MagicMock(
        status_code=200, json=lambda: {"uuid": mock_dso.uuid, "type": mock_dso.type}
    )

    # Patch the api_put method of the client to return the success response
    mocker.patch.object(client, "api_put", return_value=success_response)

    # Mock logging.info without using 'with' context manager
    mocked_info_log = mocker.patch("logging.info")

    # Call the update_dso method
    updated_dso = client.update_dso(mock_dso)

    # Assertions
    assert updated_dso is not None
    assert updated_dso.uuid == "123"

    # Verify that logging.info was called (if needed)
    mocked_info_log.assert_called()


def test_update_dso_invalid_type(mocker, mock_dso):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Simulate a non-SimpleDSpaceObject
    non_simple_dso = MagicMock()
    non_simple_dso.links = mock_dso.links

    # Mock logging.error without using 'with' context manager
    mocked_error_log = mocker.patch("logging.error")

    # Call the update_dso method
    result = client.update_dso(non_simple_dso)

    # Assertions
    assert result == non_simple_dso

    # Verify that logging.error was called (if needed)
    mocked_error_log.assert_called()


def test_update_dso_failure(mocker, mock_dso):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Simulate a failed response from the API
    failed_response = MagicMock(status_code=400, text="Bad request")

    # Patch the api_put method to return the failed response
    mocker.patch.object(client, "api_put", return_value=failed_response)

    # Mock logging.error without using 'with' context manager
    mocked_error_log = mocker.patch("logging.error")

    # Call the update_dso method
    result = client.update_dso(mock_dso)

    # Assertions
    assert result is None

    # Verify that logging.error was called (if needed)
    mocked_error_log.assert_called()


def test_update_dso_with_none_dso(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    result = client.update_dso(dso=None)

    assert result is None


def test_update_dso_value_error(mocker, mock_dso):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Patch the api_put method to simulate a successful API call but return invalid JSON
    mocker.patch.object(client, "api_put", return_value=MagicMock(status_code=200))

    # Patch the parse_json method to raise a ValueError (simulating a parsing error)
    mocker.patch(
        "dspace_rest_client.client.parse_json", side_effect=ValueError("Invalid JSON")
    )

    # Mock logging.error without using 'with' context manager
    mocked_error_log = mocker.patch("logging.error")

    # Call the update_dso method
    result = client.update_dso(mock_dso)

    # Assertions
    assert result is None

    # Verify that logging.error was called with the appropriate message
    mocked_error_log.assert_called_once_with(
        "Error parsing DSO response", exc_info=True
    )


def test_delete_dso_success(mocker, mock_dso):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Mock api_delete to return a successful response
    mocker.patch.object(client, "api_delete", return_value=MagicMock(status_code=204))

    # Mock logging.info without using 'with' context manager
    mocked_info_log = mocker.patch("logging.info")

    # Call the delete_dso method
    response = client.delete_dso(dso=mock_dso)

    # Assertions
    assert response.status_code == 204

    # Optionally verify that logging.info was called
    mocked_info_log.assert_called()


def test_delete_dso_no_dso_or_url(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Mock logging.error without using 'with' context manager
    mocked_error_log = mocker.patch("logging.error")

    # Call the delete_dso method without passing a dso or URL
    response = client.delete_dso()

    # Assertions
    assert response is None

    # Verify that logging.error was called
    mocked_error_log.assert_called()


def test_delete_dso_api_error(mocker, mock_dso):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Mock api_delete to return a failure response (status 400)
    mocker.patch.object(
        client,
        "api_delete",
        return_value=MagicMock(status_code=400, text="Bad request"),
    )

    # Mock logging.error without using 'with' context manager
    mocked_error_log = mocker.patch("logging.error")

    # Call the delete_dso method
    response = client.delete_dso(dso=mock_dso)

    # Assertions
    assert response is None

    # Verify that logging.error was called
    mocked_error_log.assert_called()


def test_delete_dso_invalid_type(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Simulate a non-SimpleDSpaceObject
    invalid_dso = MagicMock()

    # Mock logging.error without using 'with' context manager
    mocked_error_log = mocker.patch("logging.error")

    # Call the delete_dso method with an invalid DSO
    result = client.delete_dso(dso=invalid_dso)

    # Assertions: result should return the invalid_dso object
    assert result == invalid_dso

    # Verify that logging.error was called with the correct message
    mocked_error_log.assert_called_once_with(
        "Only SimpleDSpaceObject types (eg Item, Collection, Community, EPerson) "
        "are supported by generic update_dso PUT."
    )


def test_delete_dso_value_error(mocker, mock_dso):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Mock api_delete to raise a ValueError
    mocker.patch.object(client, "api_delete", side_effect=ValueError("Delete failed"))

    # Mock logging.error without using 'with' context manager
    mocked_error_log = mocker.patch("logging.error")

    # Call the delete_dso method
    result = client.delete_dso(dso=mock_dso)

    # Assertions
    assert result is None

    # Verify that logging.error was called with the correct error message
    mocked_error_log.assert_called_once_with(
        f"Error deleting DSO {mock_dso.uuid}: Delete failed"
    )


def test_get_bundles_for_item(mocker, mock_item):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Mock bundle data for an item
    mock_bundles_data = {
        "_embedded": {
            "bundles": [
                {"uuid": "bundle-uuid-1", "name": "ORIGINAL"},
                {"uuid": "bundle-uuid-2", "name": "LICENSE"},
            ]
        }
    }

    # Patch fetch_resource to return the mock bundles
    mocker.patch.object(client, "fetch_resource", return_value=mock_bundles_data)

    # Call get_bundles method with a parent item
    bundles = client.get_bundles(parent=mock_item)

    # Assertions
    assert len(bundles) == 2
    assert all(isinstance(bundle, Bundle) for bundle in bundles)
    assert bundles[0].uuid == "bundle-uuid-1"
    assert bundles[1].uuid == "bundle-uuid-2"


def test_get_bundles_single_bundle(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Mock bundle data for a single bundle
    mock_bundle_data = {"uuid": "bundle-uuid-1", "name": "ORIGINAL"}

    # Patch fetch_resource to return the mock bundle data
    mocker.patch.object(client, "fetch_resource", return_value=mock_bundle_data)

    # Call get_bundles method with a bundle UUID
    bundles = client.get_bundles(uuid="bundle-uuid-1")

    # Assertions
    assert len(bundles) == 1
    assert isinstance(bundles[0], Bundle)
    assert bundles[0].uuid == "bundle-uuid-1"


def test_get_bundles_no_parent_or_uuid(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Patch fetch_resource to prevent API call
    mocker.patch.object(client, "fetch_resource")

    # Call get_bundles method without parent or UUID
    bundles = client.get_bundles()

    # Assertions
    assert bundles == []
    client.fetch_resource.assert_not_called()


def test_get_bundles_with_sort(mocker, mock_item):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Mock bundle data
    mock_bundles_data = {
        "_embedded": {
            "bundles": [
                {"uuid": "bundle-uuid-1", "name": "ORIGINAL"},
                {"uuid": "bundle-uuid-2", "name": "LICENSE"},
            ]
        }
    }

    # Patch fetch_resource to return the mock bundles
    mocker.patch.object(client, "fetch_resource", return_value=mock_bundles_data)

    # Call get_bundles with the sort parameter
    bundles = client.get_bundles(parent=mock_item, sort="name,asc")

    # Assertions
    assert len(bundles) == 2
    assert bundles[0].uuid == "bundle-uuid-1"
    assert bundles[1].uuid == "bundle-uuid-2"

    # Assert that fetch_resource was called with the correct params, including the sort parameter
    client.fetch_resource.assert_called_once_with(
        f"http://example.com/server/api/core/items/{mock_item.uuid}/bundles",
        params={"size": 20, "page": 0, "sort": "name,asc"},
    )


def test_get_bundles_value_error(mocker, mock_item):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Mock API response with invalid data
    mock_bundles_data = {
        "_embedded": {
            "bundles": [
                {"uuid": "bundle-uuid-1", "name": "ORIGINAL"},
                {"uuid": "bundle-uuid-2", "name": "LICENSE"},
            ]
        }
    }

    # Patch fetch_resource to return the invalid data
    mocker.patch.object(client, "fetch_resource", return_value=mock_bundles_data)

    # Patch the Bundle constructor to raise a ValueError when trying to create a Bundle
    mocker.patch(
        "dspace_rest_client.client.Bundle", side_effect=ValueError("Invalid Bundle")
    )

    # Mock logging.error without using 'with' context manager
    mocked_error_log = mocker.patch("logging.error")

    # Call get_bundles with a parent item
    bundles = client.get_bundles(parent=mock_item)

    # Assertions
    assert bundles == []  # Expect an empty list due to ValueError

    # Verify that logging.error was called with the appropriate error message
    mocked_error_log.assert_called_once_with(
        "error parsing bundle results: Invalid Bundle"
    )


def test_create_bundle_success(mocker, mock_item):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Mock the API response for creating a bundle
    mock_bundle_data = {"uuid": "bundle-uuid-1", "name": "ORIGINAL"}

    # Patch the api_post method to return the mock response
    mocker.patch.object(
        client, "api_post", return_value=MagicMock(json=lambda: mock_bundle_data)
    )

    # Patch parse_json to return the parsed response
    mocker.patch("dspace_rest_client.client.parse_json", return_value=mock_bundle_data)

    # Call create_bundle with a parent item
    bundle = client.create_bundle(parent=mock_item, name="ORIGINAL")

    # Assertions
    assert isinstance(bundle, Bundle)
    assert bundle.uuid == "bundle-uuid-1"
    assert bundle.name == "ORIGINAL"

    # Verify that api_post was called with the correct URL and payload
    client.api_post.assert_called_once_with(
        f"http://example.com/server/api/core/items/{mock_item.uuid}/bundles",
        params=None,
        json={"name": "ORIGINAL", "metadata": {}},
    )


def test_create_bundle_no_parent(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Call create_bundle with no parent item
    bundle = client.create_bundle(parent=None)

    # Assertions: Expect None when parent is not provided
    assert bundle is None


def test_create_bundle_error(mocker, mock_item):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Mock the api_post method to raise a ValueError (simulating an API error)
    mocker.patch.object(
        client, "api_post", side_effect=ValueError("API request failed")
    )

    # Mock logging.error without using 'with' context manager
    mocked_error_log = mocker.patch("logging.error")

    # Call create_bundle and expect the error handling
    bundle = client.create_bundle(parent=mock_item, name="ORIGINAL")

    # Assertions
    assert bundle is None

    # Verify that logging.error was called with the correct error message
    mocked_error_log.assert_called_once_with(
        "error creating bundle: API request failed"
    )


def test_get_bitstreams_for_bundle(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )
    mock_bundle = Bundle({"uuid": "bundle-uuid"})
    mock_bundle.links = {
        "bitstreams": {
            "href": "http://example.com/server/api/core/bundles/bundle-uuid/bitstreams"
        }
    }
    mock_bitstreams_data = {
        "_embedded": {
            "bitstreams": [
                {"uuid": "bitstream-uuid-1", "name": "Bitstream 1"},
                {"uuid": "bitstream-uuid-2", "name": "Bitstream 2"},
            ]
        }
    }
    mocker.patch.object(client, "fetch_resource", return_value=mock_bitstreams_data)

    bitstreams = client.get_bitstreams(bundle=mock_bundle)

    assert len(bitstreams) == 2
    assert all(isinstance(bitstream, Bitstream) for bitstream in bitstreams)
    assert bitstreams[0].uuid == "bitstream-uuid-1"
    assert bitstreams[1].uuid == "bitstream-uuid-2"


def test_get_bitstreams_no_uuid_or_bundle(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Call get_bitstreams without uuid or bundle
    bitstreams = client.get_bitstreams()

    # Assertions: Expect an empty list when both uuid and bundle are None
    assert bitstreams == []


def test_get_bitstreams_manual_url_construction(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Create a bundle without bitstream links
    mock_bundle = Bundle({"uuid": "bundle-uuid"})
    mock_bundle.links = {}  # No bitstream links

    mock_bitstreams_data = {
        "_embedded": {
            "bitstreams": [
                {"uuid": "bitstream-uuid-1", "name": "Bitstream 1"},
                {"uuid": "bitstream-uuid-2", "name": "Bitstream 2"},
            ]
        }
    }

    # Patch fetch_resource to return the mock bitstreams
    mocker.patch.object(client, "fetch_resource", return_value=mock_bitstreams_data)

    # Patch logging.warning
    mocked_warning_log = mocker.patch("logging.warning")

    # Call get_bitstreams with a bundle that doesn't have bitstream links
    bitstreams = client.get_bitstreams(bundle=mock_bundle)

    # Assertions
    assert len(bitstreams) == 2
    assert bitstreams[0].uuid == "bitstream-uuid-1"
    assert bitstreams[1].uuid == "bitstream-uuid-2"

    # Verify that the warning log was called once with the correct message
    mocked_warning_log.assert_called_once_with(
        "Cannot find bundle bitstream links, will try to construct manually: "
        "http://example.com/server/api/core/bundles/bundle-uuid/bitstreams"
    )

    # Verify that fetch_resource was called with the correct manually constructed URL
    client.fetch_resource.assert_called_once_with(
        "http://example.com/server/api/core/bundles/bundle-uuid/bitstreams",
        params={"size": 20, "page": 0},
    )


def test_get_bitstreams_with_sort(mocker, mock_bundle):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    mock_bitstreams_data = {
        "_embedded": {
            "bitstreams": [
                {"uuid": "bitstream-uuid-1", "name": "Bitstream 1"},
                {"uuid": "bitstream-uuid-2", "name": "Bitstream 2"},
            ]
        }
    }

    # Patch fetch_resource to return the mock bitstreams
    mocker.patch.object(client, "fetch_resource", return_value=mock_bitstreams_data)

    # Call get_bitstreams with the sort parameter
    bitstreams = client.get_bitstreams(bundle=mock_bundle, sort="name,asc")

    # Assertions
    assert len(bitstreams) == 2
    assert bitstreams[0].uuid == "bitstream-uuid-1"
    assert bitstreams[1].uuid == "bitstream-uuid-2"

    # Verify that fetch_resource was called with the correct parameters, including the sort
    client.fetch_resource.assert_called_once_with(
        "http://example.com/server/api/core/bundles/bundle-uuid/bitstreams",
        params={"size": 20, "page": 0, "sort": "name,asc"},
    )


def test_create_bitstream_success(mocker, mock_bundle, tmp_path):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )
    # Create a temporary file to simulate an actual file upload
    tmp_file = tmp_path / "testfile.txt"
    tmp_file.write_text("Test file content")

    mocker.patch.object(
        client.session,
        "send",
        return_value=MagicMock(
            status_code=201, json=lambda: {"uuid": "bitstream-uuid"}
        ),
    )

    bitstream = client.create_bitstream(
        bundle=mock_bundle, name="testfile.txt", path=str(tmp_file), mime="text/plain"
    )

    assert bitstream.uuid == "bitstream-uuid"


def test_create_bitstream_missing_parameters(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Mock logging.error
    mocked_error_log = mocker.patch("logging.error")

    # Call create_bitstream with missing parameters (e.g., no bundle)
    bitstream = client.create_bitstream(
        name="testfile.txt", path="/path/to/file", mime="text/plain"
    )

    # Assertions: Expect None when a required parameter is missing
    assert bitstream is None

    # Verify that logging.error was called with the correct message
    mocked_error_log.assert_called_once_with(
        "Missing required parameters for create_bitstream"
    )


def test_create_bitstream_csrf_token_retry(mocker, mock_bundle, tmp_path):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Create a temporary file to simulate an actual file upload
    tmp_file = tmp_path / "testfile.txt"
    tmp_file.write_text("Test file content")

    # Mock the first response to simulate a CSRF token error
    mock_response_csrf = MagicMock(
        status_code=403, json=lambda: {"message": "CSRF token invalid"}
    )

    # Mock the second response to simulate a successful retry
    mock_response_success = MagicMock(
        status_code=201, json=lambda: {"uuid": "bitstream-uuid"}
    )

    # Patch session.send to return the CSRF error first, then a successful response
    mocker.patch.object(
        client.session, "send", side_effect=[mock_response_csrf, mock_response_success]
    )

    # Patch logging.debug to check if retry logging works
    mocked_debug_log = mocker.patch("logging.debug")

    # Call create_bitstream
    bitstream = client.create_bitstream(
        bundle=mock_bundle, name="testfile.txt", path=str(tmp_file), mime="text/plain"
    )

    # Assertions: The retry should succeed
    assert bitstream.uuid == "bitstream-uuid"

    # Verify that logging.debug was called for the retry
    mocked_debug_log.assert_called_with("Retrying request with updated CSRF token")


def test_create_bitstream_csrf_token_retry_failure(mocker, mock_bundle, tmp_path):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Create a temporary file to simulate an actual file upload
    tmp_file = tmp_path / "testfile.txt"
    tmp_file.write_text("Test file content")

    # Mock the response to simulate a CSRF token error both times
    mock_response_csrf = MagicMock(
        status_code=403,
        json=lambda: {"message": "CSRF token invalid"},
        text="CSRF token invalid",
    )

    # Patch session.send to always return the CSRF error
    mocker.patch.object(client.session, "send", return_value=mock_response_csrf)

    # Patch logging.error to check if the retry limit is reached
    mocked_error_log = mocker.patch("logging.error")

    # Call create_bitstream with retry=True to simulate a retry failure
    bitstream = client.create_bitstream(
        bundle=mock_bundle,
        name="testfile.txt",
        path=str(tmp_file),
        mime="text/plain",
        retry=True,
    )

    # Assertions: Expect None after retry failure
    assert bitstream is None

    # Verify that logging.error was called twice with the correct messages
    mocked_error_log.assert_has_calls(
        [
            mocker.call("Already retried... something must be wrong"),
            mocker.call("Error creating bitstream: 403: CSRF token invalid"),
        ]
    )


def test_create_bitstream_general_failure(mocker, mock_bundle, tmp_path):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Create a temporary file to simulate an actual file upload
    tmp_file = tmp_path / "testfile.txt"
    tmp_file.write_text("Test file content")

    # Mock the response to simulate a general failure (e.g., 400 Bad Request)
    mock_response_failure = MagicMock(status_code=400, text="Bad request")

    # Patch session.send to return the failure response
    mocker.patch.object(client.session, "send", return_value=mock_response_failure)

    # Mock logging.error to verify error logging
    mocked_error_log = mocker.patch("logging.error")

    # Call create_bitstream
    bitstream = client.create_bitstream(
        bundle=mock_bundle, name="testfile.txt", path=str(tmp_file), mime="text/plain"
    )

    # Assertions: Expect None on failure
    assert bitstream is None

    # Verify that logging.error was called with the correct error message
    mocked_error_log.assert_called_once_with(
        "Error creating bitstream: 400: Bad request"
    )


def test_create_bitstream_update_token(mocker, mock_bundle, tmp_path):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Create a temporary file to simulate an actual file upload
    tmp_file = tmp_path / "testfile.txt"
    tmp_file.write_text("Test file content")

    # Mock the response with a DSPACE-XSRF-TOKEN header
    mock_response = MagicMock(
        status_code=201,
        headers={"DSPACE-XSRF-TOKEN": "new-xsrf-token"},
        json=lambda: {"uuid": "bitstream-uuid"},
    )

    # Patch session.send to return the mock response
    mocker.patch.object(client.session, "send", return_value=mock_response)

    # Mock logging.debug to verify the token update log
    mocked_debug_log = mocker.patch("logging.debug")

    # Call create_bitstream to trigger the token update
    bitstream = client.create_bitstream(
        bundle=mock_bundle, name="testfile.txt", path=str(tmp_file), mime="text/plain"
    )

    # Assertions: Ensure the bitstream is created successfully
    assert bitstream.uuid == "bitstream-uuid"

    # Verify that logging.debug was called with the correct message
    mocked_debug_log.assert_called_once_with("Updating token to new-xsrf-token")

    # Verify that the session headers and cookies were updated with the new token
    assert client.session.headers["X-XSRF-Token"] == "new-xsrf-token"
    assert client.session.cookies.get("X-XSRF-Token") == "new-xsrf-token"


def test_get_communities_top(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )
    mock_communities_data = {
        "_embedded": {
            "communities": [
                {"uuid": "community-uuid-1", "name": "Community 1"},
                {"uuid": "community-uuid-2", "name": "Community 2"},
            ]
        }
    }
    mocker.patch.object(client, "fetch_resource", return_value=mock_communities_data)

    communities = client.get_communities(top=True)

    assert len(communities) == 2
    assert all(isinstance(community, Community) for community in communities)
    assert communities[0].uuid == "community-uuid-1"
    assert communities[1].uuid == "community-uuid-2"


def test_get_communities_with_sort(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Mock the API response with multiple communities
    mock_communities_data = {
        "_embedded": {
            "communities": [
                {"uuid": "community-uuid-1", "name": "Community 1"},
                {"uuid": "community-uuid-2", "name": "Community 2"},
            ]
        }
    }

    # Patch fetch_resource to return the mock response
    mocker.patch.object(client, "fetch_resource", return_value=mock_communities_data)

    # Call get_communities with a sort parameter
    communities = client.get_communities(sort="name,asc")

    # Assertions
    assert len(communities) == 2
    assert communities[0].uuid == "community-uuid-1"
    assert communities[1].uuid == "community-uuid-2"

    # Verify that fetch_resource was called with the correct parameters, including the sort
    client.fetch_resource.assert_called_once_with(
        "http://example.com/server/api/core/communities",
        {"size": 20, "page": 0, "sort": "name,asc"},
    )


def test_get_communities_with_valid_uuid(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Mock the API response for a single community
    mock_single_community_data = {"uuid": "community-uuid-1", "name": "Community 1"}

    # Patch fetch_resource to return the mock response
    mocker.patch.object(
        client, "fetch_resource", return_value=mock_single_community_data
    )

    # Call get_communities with a valid UUID to trigger URL modification
    communities = client.get_communities(uuid="123e4567-e89b-12d3-a456-426614174000")

    # Assertions: Ensure the community is returned as a list
    assert communities is not None  # Ensure we didn't get None
    assert len(communities) == 1
    assert communities[0].uuid == "community-uuid-1"

    # Verify that fetch_resource was called with the correct URL and positional None argument for params
    client.fetch_resource.assert_called_once_with(
        "http://example.com/server/api/core/communities/123e4567-e89b-12d3-a456-426614174000",
        None,
    )


def test_get_communities_invalid_uuid(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Patch logging.error to verify the error log
    mocked_error_log = mocker.patch("logging.error")

    # Call get_communities with an invalid UUID
    communities = client.get_communities(uuid="invalid-uuid")

    # Assertions: Expect None when UUID is invalid
    assert communities is None

    # Verify that logging.error was called with the correct message
    mocked_error_log.assert_called_once_with("Invalid community UUID: invalid-uuid")


def test_get_single_community(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )

    # Mock the API response for a single community
    mock_single_community_data = {"uuid": "community-uuid-1", "name": "Community 1"}

    # Patch fetch_resource to return the mock response
    mocker.patch.object(
        client, "fetch_resource", return_value=mock_single_community_data
    )

    # Call get_communities with a valid UUID to retrieve a single community
    communities = client.get_communities(uuid="community-uuid-1")

    # Assertions: Ensure the community is returned as a list
    assert communities is not None
    assert len(communities) == 1
    assert communities[0].uuid == "community-uuid-1"

    # Verify that fetch_resource was called with the correct URL for the single community
    client.fetch_resource.assert_called_once_with(
        "http://example.com/server/api/core/communities/community-uuid-1", params=None
    )


def test_create_community_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )
    mocker.patch(
        "dspace_rest_client.client.parse_json",
        return_value={"uuid": "community-uuid", "name": "New Community"},
    )
    mocker.patch.object(
        client,
        "create_dso",
        return_value=MagicMock(
            status_code=201,
            json=lambda: {"uuid": "community-uuid", "name": "New Community"},
        ),
    )

    community = client.create_community(
        parent="parent-uuid", data={"name": "New Community"}
    )

    assert isinstance(community, Community)
    assert community.uuid == "community-uuid"
    assert community.name == "New Community"


def test_get_collections_with_valid_uuid(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the fetch_resource method to return a single collection response
    mock_response = {"uuid": "12345678-1234-5678-1234-567812345678"}
    mocker.patch.object(client, "fetch_resource", return_value=mock_response)

    # Call the method with a valid UUID
    collections = client.get_collections(uuid="12345678-1234-5678-1234-567812345678")

    # Assert that fetch_resource was called with the correct URL
    client.fetch_resource.assert_called_once_with(
        "http://example.com/core/collections/12345678-1234-5678-1234-567812345678",
        params=None,
    )

    # Assert that the method returns a list with a single collection
    assert len(collections) == 1
    assert collections[0].uuid == "12345678-1234-5678-1234-567812345678"


def test_get_collections_with_invalid_uuid(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock logging error
    mock_logging_error = mocker.patch("logging.error")

    # Call the method with an invalid UUID
    collections = client.get_collections(uuid="invalid-uuid")

    # Assert that logging.error was called with the appropriate message
    mock_logging_error.assert_called_once_with("Invalid collection UUID: invalid-uuid")

    # Assert that the method returns None
    assert collections is None


def test_get_collections_with_community(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock a community object with valid collection links
    mock_community = MagicMock()
    mock_community.links = {
        "collections": {"href": "http://example.com/server/api/core/collections"}
    }

    # Mock the fetch_resource method to return a collection list response
    mock_response = {
        "_embedded": {
            "collections": [
                {"uuid": "collection-uuid-1", "name": "Collection 1"},
                {"uuid": "collection-uuid-2", "name": "Collection 2"},
            ]
        }
    }
    mocker.patch.object(client, "fetch_resource", return_value=mock_response)

    # Call the method with a valid community
    collections = client.get_collections(community=mock_community)

    # Assert that fetch_resource was called with the correct URL
    client.fetch_resource.assert_called_once_with(
        "http://example.com/server/api/core/collections", params={"page": 0, "size": 20}
    )

    # Assert that the method returns a list of collections
    assert len(collections) == 2
    assert collections[0].uuid == "collection-uuid-1"
    assert collections[1].uuid == "collection-uuid-2"


def test_get_collections_with_sort(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the API response with a valid list of collections
    mock_json_response = {
        "_embedded": {
            "collections": [
                {"uuid": "collection-uuid-1", "name": "Collection 1"},
                {"uuid": "collection-uuid-2", "name": "Collection 2"},
            ]
        }
    }

    # Mock the fetch_resource method to return the mock JSON response
    mocker.patch.object(client, "fetch_resource", return_value=mock_json_response)

    # Call the method with a sort parameter
    result = client.get_collections(page=0, size=20, sort="name,asc")

    # Assert that fetch_resource was called with the correct URL and parameters, including sort
    client.fetch_resource.assert_called_once_with(
        "http://example.com/core/collections",
        params={"page": 0, "size": 20, "sort": "name,asc"},
    )

    # Assert that the correct collections were returned
    assert len(result) == 2
    assert result[0].uuid == "collection-uuid-1"
    assert result[1].uuid == "collection-uuid-2"


def test_get_single_collection(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the fetch_resource method to return a single collection response
    mock_response = {"uuid": "collection-uuid-1", "name": "Single Collection"}
    mocker.patch.object(client, "fetch_resource", return_value=mock_response)

    # Call the method
    collections = client.get_collections()

    # Assert that fetch_resource was called with the correct URL
    client.fetch_resource.assert_called_once_with(
        "http://example.com/core/collections", params={"page": 0, "size": 20}
    )

    # Assert that the method returns a list with a single collection
    assert len(collections) == 1
    assert collections[0].uuid == "collection-uuid-1"
    assert collections[0].name == "Single Collection"


def test_get_collections_for_community(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com/server/api",
        username="admin",
        password="admin",
    )
    mock_community = Community({"uuid": "community-uuid"})
    mock_community.links = {
        "collections": {
            "href": "http://example.com/server/api/core/communities/community-uuid/collections"
        }
    }
    mock_collections_data = {
        "_embedded": {
            "collections": [
                {"uuid": "collection-uuid-1", "name": "Collection 1"},
                {"uuid": "collection-uuid-2", "name": "Collection 2"},
            ]
        }
    }
    mocker.patch.object(client, "fetch_resource", return_value=mock_collections_data)

    collections = client.get_collections(community=mock_community)

    assert len(collections) == 2
    assert all(isinstance(collection, Collection) for collection in collections)
    assert collections[0].uuid == "collection-uuid-1"
    assert collections[1].uuid == "collection-uuid-2"


def test_create_collection_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )
    data = {"name": "New Collection"}
    parent_uuid = "parent-community-uuid"
    response_data = {"uuid": "new-collection-uuid", "name": "New Collection"}

    mocker.patch("dspace_rest_client.client.parse_json", return_value=response_data)
    mocker.patch.object(
        client, "create_dso", return_value=MagicMock(json=lambda: response_data)
    )

    collection = client.create_collection(parent=parent_uuid, data=data)

    assert isinstance(collection, Collection)
    assert collection.uuid == "new-collection-uuid"
    assert collection.name == "New Collection"
    client.create_dso.assert_called_once_with(
        f"{client.API_ENDPOINT}/core/collections", {"parent": parent_uuid}, data
    )


def test_create_user_with_user_object(mocker, mock_user_data):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )
    response_data = {
        "email": "test@example.com",
        "firstName": "Test",
        "lastName": "User",
        "uuid": "user-uuid",
    }

    mocker.patch("dspace_rest_client.client.parse_json", return_value=response_data)
    mocker.patch.object(
        client, "create_dso", return_value=MagicMock(json=lambda: response_data)
    )

    new_user = client.create_user(user=mock_user_data)

    assert isinstance(new_user, User)
    assert new_user.email == "test@example.com"
    assert new_user.uuid == "user-uuid"
    client.create_dso.assert_called_once()


def test_create_user_with_dict(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )
    user_dict = {"email": "test@example.com", "firstName": "Test", "lastName": "User"}
    response_data = {
        "email": "test@example.com",
        "firstName": "Test",
        "lastName": "User",
        "uuid": "user-uuid",
    }

    mocker.patch("dspace_rest_client.client.parse_json", return_value=response_data)
    mocker.patch.object(
        client, "create_dso", return_value=MagicMock(json=lambda: response_data)
    )

    new_user = client.create_user(user=user_dict)

    assert isinstance(new_user, User)
    assert new_user.email == "test@example.com"
    assert new_user.uuid == "user-uuid"
    client.create_dso.assert_called_once_with(
        f"{client.API_ENDPOINT}/eperson/epersons", params=None, data=user_dict
    )


def test_create_user_with_token(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )
    user_dict = {"email": "test@example.com", "firstName": "Test", "lastName": "User"}
    token = "registration-token"
    response_data = {
        "email": "test@example.com",
        "firstName": "Test",
        "lastName": "User",
        "uuid": "user-uuid",
    }

    mocker.patch("dspace_rest_client.client.parse_json", return_value=response_data)
    mocker.patch.object(
        client, "create_dso", return_value=MagicMock(json=lambda: response_data)
    )

    new_user = client.create_user(user=user_dict, token=token)

    assert new_user.uuid == "user-uuid"
    client.create_dso.assert_called_once_with(
        f"{client.API_ENDPOINT}/eperson/epersons",
        params={"token": token},
        data=user_dict,
    )


def test_delete_user_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )
    mock_user = User({"uuid": "user-uuid"})

    mocker.patch.object(client, "delete_dso", return_value=True)

    result = client.delete_user(mock_user)

    assert result is True
    client.delete_dso.assert_called_once_with(mock_user)


def test_delete_user_invalid(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock logging.error without using 'with' context manager
    mocked_log_error = mocker.patch("logging.error")

    # Call the delete_user method with an invalid user object
    result = client.delete_user(user="not a user object")

    # Assert the method returns None on failure
    assert result is None

    # Verify logging.error was called
    mocked_log_error.assert_called()


def test_get_users_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )
    api_response = {
        "_embedded": {
            "epersons": [
                {"uuid": "user-uuid-1", "email": "user1@example.com"},
                {"uuid": "user-uuid-2", "email": "user2@example.com"},
            ]
        }
    }
    mocker.patch.object(
        client,
        "api_get",
        return_value=MagicMock(status_code=200, json=lambda: api_response),
    )
    mocker.patch("dspace_rest_client.client.parse_json", return_value=api_response)

    users = client.get_users()

    assert len(users) == 2
    assert all(isinstance(user, User) for user in users)
    assert users[0].uuid == "user-uuid-1"
    assert users[1].uuid == "user-uuid-2"


def test_get_users_with_sort(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the API response with a valid list of users
    mock_response = MagicMock()
    mock_response.status_code = 200
    mocker.patch.object(client, "api_get", return_value=mock_response)

    # Mock the parse_json function to return a valid JSON response
    mock_json_response = {
        "_embedded": {
            "epersons": [
                {"uuid": "user-uuid-1", "name": "User 1"},
                {"uuid": "user-uuid-2", "name": "User 2"},
            ]
        }
    }
    mocker.patch(
        "dspace_rest_client.client.parse_json", return_value=mock_json_response
    )

    # Call the method with a sort parameter
    result = client.get_users(page=0, size=20, sort="name,asc")

    # Assert that the api_get was called with the correct parameters, including sort
    client.api_get.assert_called_once_with(
        "http://example.com/eperson/epersons",
        params={"page": 0, "size": 20, "sort": "name,asc"},
    )

    # Assert that the correct users were returned
    assert len(result) == 2
    assert result[0].uuid == "user-uuid-1"
    assert result[1].uuid == "user-uuid-2"


def test_create_group_with_group_object(mocker, mock_group):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )
    response_data = {"name": "New Group", "uuid": "group-uuid"}

    mocker.patch("dspace_rest_client.client.parse_json", return_value=response_data)
    mocker.patch.object(
        client, "create_dso", return_value=MagicMock(json=lambda: response_data)
    )

    new_group = client.create_group(group=mock_group)

    assert isinstance(new_group, Group)
    assert new_group.name == "New Group"
    assert new_group.uuid == "group-uuid"


def test_update_token(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )
    response = MagicMock(headers={"DSPACE-XSRF-TOKEN": "new-token"})

    # Mock logging.debug without using 'with' context manager
    mocked_log_debug = mocker.patch("logging.debug")

    # Call the update_token method with the mocked response
    client.update_token(r=response)

    # Assert the XSRF token is correctly set in session headers and cookies
    assert client.session.headers["X-XSRF-Token"] == "new-token"
    assert client.session.cookies.get("X-XSRF-Token") == "new-token"

    # Optionally verify that logging.debug was called
    mocked_log_debug.assert_called()


def test_update_token_no_session(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Set client.session to None to simulate missing session
    client.session = None

    # Mock the response object with headers containing the CSRF token
    mock_response = MagicMock()
    mock_response.headers = {"DSPACE-XSRF-TOKEN": "new-token"}

    # Mock the logging.debug to capture the session initialization log
    mocked_log_debug = mocker.patch("logging.debug")

    # Call the update_token method with the mocked response
    client.update_token(r=mock_response)

    # Assert that the session was initialized
    assert isinstance(client.session, requests.Session)

    # Assert that the XSRF token was correctly updated in the session headers and cookies
    assert client.session.headers["X-XSRF-Token"] == "new-token"
    assert client.session.cookies.get("X-XSRF-Token") == "new-token"

    # Verify that the logging.debug was called for session initialization and token update
    mocked_log_debug.assert_any_call("Session state not found, setting...")
    mocked_log_debug.assert_any_call("Updating XSRF token to new-token")


def test_start_workflow(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )
    workspace_item = "workspaceitem-uuid"
    response_data = {"message": "Workflow started"}  # Simulate expected response

    mocker.patch.object(
        client, "api_post_uri", return_value=MagicMock(json=lambda: response_data)
    )
    mocker.patch("dspace_rest_client.client.parse_json", return_value=response_data)

    # Assuming you want to do something with the response in the method eventually
    client.start_workflow(workspace_item=workspace_item)
    client.api_post_uri.assert_called_once_with(
        f"{client.API_ENDPOINT}/workflow/workflowitems",
        params=None,
        uri_list=workspace_item,
    )


def test_get_short_lived_token_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )
    response_data = {"token": "short-lived"}

    mock_response = MagicMock()
    mock_response.json.return_value = response_data
    mocker.patch.object(client, "api_post", return_value=mock_response)

    token = client.get_short_lived_token()

    assert token == "short-lived"


def test_get_short_lived_token_failure(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the response to simulate a 403 Forbidden error
    mock_response = MagicMock()
    mock_response.status_code = 403
    mock_response.json.return_value = {"message": "Forbidden"}

    # Patch the api_post method to return the mocked response
    mocker.patch.object(client, "api_post", return_value=mock_response)

    # Mock logging.error without using 'with' context manager
    mocked_log_error = mocker.patch("logging.error")

    # Call the get_short_lived_token method
    token = client.get_short_lived_token()

    # Assert the method returns None due to failure
    assert token is None

    # Optionally verify that logging.error was called
    mocked_log_error.assert_called()


def test_get_short_lived_token_no_session(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Set client.session to None to simulate missing session
    client.session = None

    # Mock the response from the api_post method
    mock_response = MagicMock()
    mock_response.json.return_value = {"token": "short-lived"}
    mocker.patch.object(client, "api_post", return_value=mock_response)

    # Mock the logging.debug to capture the session initialization log
    mocked_log_debug = mocker.patch("logging.debug")

    # Call the get_short_lived_token method
    token = client.get_short_lived_token()

    # Assert that the session was initialized
    assert isinstance(client.session, requests.Session)

    # Assert that the token was retrieved correctly
    assert token == "short-lived"

    # Verify that the logging.debug was called for session initialization
    mocked_log_debug.assert_called_with("Session state not found, setting...")


def test_get_config_valid_key(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )
    key = "registration.verification.enabled"
    url = f"{client.API_ENDPOINT}/config/properties/{key}"

    # Mock the response for the GET request to the API
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"enabled": True}

    # Patch the api_get method of the client to return the mocked response
    mocker.patch.object(client, "api_get", return_value=mock_response)

    # Call the get_config method
    result = client.get_config(key)

    # Assert that the api_get method was called with the correct URL and the result is correct
    client.api_get.assert_called_once_with(url)
    assert result == {"enabled": True}


def test_get_config_invalid_key(mocker):
    # Instantiate the DSpaceClient (replace this with your actual client if needed)
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )
    key = "invalid.key"
    result = client.get_config(key)
    assert result is None


def test_solr_query(mocker):
    # Mock the DSpaceClient or your Solr client class
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the response from Solr
    mock_solr_response = MagicMock()
    mock_solr_response.status_code = 200
    mock_solr_response.json.return_value = {"response": {"docs": [{"id": "1"}]}}

    # Patch the solr.search method of the client to return the mocked response
    mocker.patch.object(client.solr, "search", return_value=mock_solr_response)

    # Define test inputs
    query = "test query"
    filters = ["filter1:value1", "filter2:value2"]
    fields = ["id", "name"]
    facets = ["facet_field1", "facet_field2"]
    minfacests = 5
    start = 10
    rows = 100

    # Call the solr_query method
    result = client.solr_query(
        query=query,
        filters=filters,
        fields=fields,
        facets=facets,
        minfacests=minfacests,
        start=start,
        rows=rows,
    )

    # Assert that the solr.search method was called with the correct parameters
    client.solr.search.assert_called_once_with(
        query,
        fq=filters,
        start=start,
        rows=rows,
        facet="true",
        **{"fl": ",".join(fields)},
        **{"facet.mincount": minfacests},
        **{"facet.field": facets},
    )

    # Assert that the result matches the mocked response
    assert result == mock_solr_response


def test_solr_query_defaults_to_empty_lists(mocker):
    # Mock the DSpaceClient or your Solr client class
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the response from Solr
    mock_solr_response = MagicMock()
    mock_solr_response.status_code = 200
    mock_solr_response.json.return_value = {"response": {"docs": [{"id": "1"}]}}

    # Patch the solr.search method of the client to return the mocked response
    mocker.patch.object(client.solr, "search", return_value=mock_solr_response)

    # Define test inputs (fields, filters, and facets are omitted so they default to None)
    query = "test query"

    # Call the solr_query method with default None values for filters, fields, and facets
    result = client.solr_query(query=query)

    # Assert that the solr.search method was called with the correct parameters
    client.solr.search.assert_called_once_with(
        query,
        fq=[],  # filters should default to an empty list
        start=0,  # default start
        rows=999999999,  # default rows
        facet="true",
        **{"fl": ""},  # fields should default to an empty string (no fields)
        **{"facet.mincount": 0},  # default minfacests
        **{"facet.field": []},  # facets should default to an empty list
    )

    # Assert that the result matches the mocked response
    assert result == mock_solr_response


def test_get_special_groups_of_user_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the response from api_get
    mock_response = MagicMock()
    mocker.patch.object(client, "api_get", return_value=mock_response)

    # Mock the parsed JSON response
    mock_json_response = {
        "_embedded": {
            "specialGroups": [
                {"id": "1", "name": "Group 1"},
                {"id": "2", "name": "Group 2"},
            ]
        }
    }
    mocker.patch(
        "dspace_rest_client.client.parse_json", return_value=mock_json_response
    )

    # Mock the Group object initialization
    mock_group = mocker.patch(
        "dspace_rest_client.client.Group", side_effect=lambda x: x
    )

    # Call the method
    groups = client.get_special_groups_of_user()

    # Assert that the api_get method was called with the correct URL
    client.api_get.assert_called_once_with(
        f"{client.API_ENDPOINT}/authn/status/specialGroups"
    )

    # Assert that the Group object was instantiated twice (once for each group in the mock response)
    assert mock_group.call_count == 2

    # Assert that the returned groups list matches the mock response data
    assert groups == [{"id": "1", "name": "Group 1"}, {"id": "2", "name": "Group 2"}]


def test_get_special_groups_of_user_no_groups(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the response from api_get
    mock_response = MagicMock()
    mocker.patch.object(client, "api_get", return_value=mock_response)

    # Mock the parsed JSON response with no special groups
    mock_json_response = {"_embedded": {}}
    mocker.patch(
        "dspace_rest_client.client.parse_json", return_value=mock_json_response
    )

    # Call the method
    result = client.get_special_groups_of_user()

    # Assert that the api_get method was called with the correct URL
    client.api_get.assert_called_once_with(
        f"{client.API_ENDPOINT}/authn/status/specialGroups"
    )

    # Assert that the result is the raw JSON response (no special groups)
    assert result == mock_json_response


from urllib.parse import urlparse
import os


def test_get_eperson_id_of_user(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the response from api_get
    mock_response = MagicMock()
    mocker.patch.object(client, "api_get", return_value=mock_response)

    # Mock the parsed JSON response with the eperson link
    mock_json_response = {
        "_links": {
            "eperson": {"href": "http://example.com/api/epersons/1234-5678-91011"}
        }
    }
    mocker.patch(
        "dspace_rest_client.client.parse_json", return_value=mock_json_response
    )

    # Mock the urlparse and os.path.basename to correctly extract the UUID
    mocker.patch(
        "urllib.parse.urlparse",
        return_value=urlparse("http://example.com/api/epersons/1234-5678-91011"),
    )
    mocker.patch("os.path.basename", return_value="1234-5678-91011")

    # Call the get_eperson_id_of_user method
    user_id = client.get_eperson_id_of_user()

    # Assert that the api_get method was called with the correct URL
    client.api_get.assert_called_once_with(f"{client.API_ENDPOINT}/authn/status")

    # Assert that the returned UUID matches the one from the mock
    assert user_id == "1234-5678-91011"


def test_add_metadata_invalid_input(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock logging.error
    mock_log_error = mocker.patch("logging.error")

    # Call the method with invalid inputs
    result = client.add_metadata(dso=None, field=None, value=None)

    # Assert that logging.error was called
    mock_log_error.assert_called_with(
        "Invalid or missing DSpace object, field or value string"
    )

    # Assert that the method returns self when there are invalid inputs
    assert result == client


def test_add_metadata_invalid_dso(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock logging.error
    mock_log_error = mocker.patch("logging.error")

    # Call the method with an invalid dso (not an instance of DSpaceObject)
    result = client.add_metadata(
        dso="not-a-dspace-object", field="dc.title", value="Test Title"
    )

    # Assert that logging.error was called
    mock_log_error.assert_called_with(
        "Invalid or missing DSpace object, field or value string"
    )

    # Assert that the method returns self when there is an invalid DSO
    assert result == client


def test_add_metadata_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Create a mock DSpaceObject with a self link
    mock_dso = MagicMock(spec=DSpaceObject)
    mock_dso.links = {"self": {"href": "http://example.com/api/dspaceobject/123"}}

    # Mock the api_patch method to return a mock response
    mock_response = MagicMock()
    mocker.patch.object(client, "api_patch", return_value=mock_response)

    # Mock parse_json to return the JSON data from the patch response
    mocker.patch("dspace_rest_client.client.parse_json", return_value={"id": "123"})

    # Call the add_metadata method
    result = client.add_metadata(
        dso=mock_dso,
        field="dc.title",
        value="Test Title",
        language="en",
        authority="auth-id",
        confidence=600,
        place="0",
    )

    # Assert that the api_patch method was called with the correct parameters
    client.api_patch.assert_called_once_with(
        url="http://example.com/api/dspaceobject/123",
        operation=client.PatchOperation.ADD,
        path="/metadata/dc.title/0",
        value={
            "value": "Test Title",
            "language": "en",
            "authority": "auth-id",
            "confidence": 600,
        },
    )

    # Assert that the result is a new instance of the DSpaceObject type (mocked)
    assert isinstance(result, DSpaceObject)


def test_delete_item_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the api_delete method to simulate a successful deletion
    mocker.patch.object(client, "api_delete", return_value=True)

    # Define a valid UUID
    uuid = "1234-5678-91011"

    # Call the delete_item method
    result = client.delete_item(uuid)

    # Assert that the api_delete method was called with the correct URL
    client.api_delete.assert_called_once_with(
        f"http://example.com/core/items/{uuid}", None, None
    )

    # Assert that the method returns True for a successful deletion
    assert result is True


def test_delete_item_invalid_uuid(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the logging.error method to verify the error is logged
    mock_log_error = mocker.patch("logging.error")

    # Simulate an invalid UUID that would raise a ValueError during the deletion
    mocker.patch.object(client, "api_delete", side_effect=ValueError("Invalid UUID"))

    # Define an invalid UUID
    uuid = "invalid-uuid"

    # Call the delete_item method
    result = client.delete_item(uuid)

    # Assert that logging.error was called with the appropriate message
    mock_log_error.assert_called_with(f"Invalid item UUID: {uuid}")

    # Assert that the method returns None for an invalid UUID
    assert result is None


def test_patch_item_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the api_patch method to simulate a successful patch operation
    mocker.patch.object(client, "api_patch", return_value=True)

    # Define test inputs
    uuid = "1234-5678-91011"
    operation = "replace"
    path = "/metadata/dc.title"
    value = {"value": "Updated Title"}

    # Call the patch_item method
    result = client.patch_item(uuid, operation, path, value)

    # Assert that the api_patch method was called with the correct parameters
    client.api_patch.assert_called_once_with(
        f"http://example.com/core/items/{uuid}", operation, path, value, True
    )

    # Assert that the method returns True for a successful patch operation
    assert result is True


def test_patch_item_invalid_uuid(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the logging.error method to verify that the error is logged
    mock_log_error = mocker.patch("logging.error")

    # Simulate a ValueError being raised by the api_patch method
    mocker.patch.object(client, "api_patch", side_effect=ValueError("Invalid UUID"))

    # Define an invalid UUID
    uuid = "invalid-uuid"
    operation = "replace"
    path = "/metadata/dc.title"
    value = {"value": "Updated Title"}

    # Call the patch_item method
    result = client.patch_item(uuid, operation, path, value)

    # Assert that logging.error was called with the appropriate message
    mock_log_error.assert_called_with(f"Invalid item UUID: {uuid}")

    # Assert that the method returns None for an invalid UUID
    assert result is None


def test_update_item_invalid(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock logging.error
    mock_log_error = mocker.patch("logging.error")

    # Call the update_item method with an invalid item (not an instance of Item)
    result = client.update_item("not-an-item")

    # Assert that logging.error was called with the correct message
    mock_log_error.assert_called_with("Need a valid item")

    # Assert that the method returns None when the input is invalid
    assert result is None


def test_update_item_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Create a mock Item object
    mock_item = MagicMock(spec=Item)

    # Mock the update_dso method to return a success value (True)
    mocker.patch.object(client, "update_dso", return_value=True)

    # Call the update_item method with a valid item
    result = client.update_item(mock_item)

    # Assert that update_dso was called with the correct arguments
    client.update_dso.assert_called_once_with(mock_item, params=None)

    # Assert that the method returns the result of update_dso
    assert result is True


def test_create_item_no_parent(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock logging.error
    mock_log_error = mocker.patch("logging.error")

    # Call the create_item method with None as the parent UUID
    result = client.create_item(None, MagicMock(spec=Item))

    # Assert that logging.error was called with the appropriate message
    mock_log_error.assert_called_with("Need a parent UUID!")

    # Assert that the method returns None when the parent UUID is missing
    assert result is None


def test_create_item_invalid_item(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock logging.error
    mock_log_error = mocker.patch("logging.error")

    # Call the create_item method with an invalid item (not an instance of Item)
    result = client.create_item("1234-5678-91011", "not-an-item")

    # Assert that logging.error was called with the appropriate message
    mock_log_error.assert_called_with("Need a valid item")

    # Assert that the method returns None when the item is invalid
    assert result is None


def test_create_item_success(mocker):
    # Create a mock DSpaceClient
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the Item object and its as_dict method
    mock_item = mocker.MagicMock(spec=Item)
    mock_item.as_dict.return_value = {"name": "Test Item"}

    # Mock the create_dso method to simulate an API response
    mock_create_dso_response = {"id": "123", "name": "Test Item"}
    mocker.patch.object(client, "create_dso", return_value=mock_create_dso_response)

    # Mock parse_json to return the JSON response as expected
    mock_parse_json = mocker.patch("dspace_rest_client.client.parse_json", return_value=mock_create_dso_response)

    # Call the create_item method with a valid parent and item
    result = client.create_item("1234-5678-91011", mock_item)

    # Assert that create_dso was called with the correct parameters
    client.create_dso.assert_called_once_with(
        f"http://example.com/core/items",
        params={"owningCollection": "1234-5678-91011"},
        data=mock_item.as_dict(),
    )

    # Assert that parse_json was called to parse the API response
    mock_parse_json.assert_called_once_with(mock_create_dso_response)

    # Assert that the result is an Item object constructed from the API response
    assert isinstance(result, Item)
    assert result.id == "123"


def test_get_items_no_items(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock fetch_resource to return an empty JSON response (no items)
    mocker.patch.object(client, "fetch_resource", return_value={})

    # Call the get_items method
    result = client.get_items()

    # Assert that fetch_resource was called with the correct URL
    client.fetch_resource.assert_called_once_with(f"http://example.com/core/items")

    # Assert that the result is an empty list when no items are present
    assert result == []


def test_get_items_multiple_items(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the JSON response with multiple items
    mock_json_response = {
        "_embedded": {
            "items": [
                {"uuid": "1234", "name": "Item 1"},
                {"uuid": "5678", "name": "Item 2"},
            ]
        }
    }
    mocker.patch.object(client, "fetch_resource", return_value=mock_json_response)

    # Mock the Item object to simulate its instantiation
    mock_item = mocker.patch("dspace_rest_client.client.Item", side_effect=lambda x: x)

    # Call the get_items method
    result = client.get_items()

    # Assert that fetch_resource was called with the correct URL
    client.fetch_resource.assert_called_once_with(f"http://example.com/core/items")

    # Assert that the Item constructor was called twice (once for each item)
    assert mock_item.call_count == 2

    # Assert that the result contains the expected items
    assert result == [
        {"uuid": "1234", "name": "Item 1"},
        {"uuid": "5678", "name": "Item 2"},
    ]


def test_get_items_single_item(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the JSON response with a single item
    mock_json_response = {"uuid": "1234", "name": "Single Item"}
    mocker.patch.object(client, "fetch_resource", return_value=mock_json_response)

    # Mock the Item object to simulate its instantiation
    mock_item = mocker.patch("dspace_rest_client.client.Item", side_effect=lambda x: x)

    # Call the get_items method
    result = client.get_items()

    # Assert that fetch_resource was called with the correct URL
    client.fetch_resource.assert_called_once_with(f"http://example.com/core/items")

    # Assert that the Item constructor was called once (for the single item)
    mock_item.assert_called_once_with(mock_json_response)

    # Assert that the result contains the single item
    assert result == [{"uuid": "1234", "name": "Single Item"}]


def test_get_item_relationships_invalid_uuid(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Call the get_item_relationships method with None as the UUID
    result = client.get_item_relationships(None)

    # Assert that the method returns None when the UUID is None
    assert result is None


def test_get_item_relationships_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the API response with a status code of 200
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"relationships": [{"type": "isPartOf"}]}

    # Patch the api_get method to return the mock response
    mocker.patch.object(client, "api_get", return_value=mock_response)

    # Mock the parse_json function to return the parsed JSON
    mocker.patch(
        "dspace_rest_client.client.parse_json",
        return_value={"relationships": [{"type": "isPartOf"}]},
    )

    # Call the get_item_relationships method with a valid UUID
    result = client.get_item_relationships("1234-5678-91011")

    # Assert that the api_get method was called with the correct URL
    client.api_get.assert_called_once_with(
        f"http://example.com/core/items/1234-5678-91011/relationships"
    )

    # Assert that the result matches the parsed JSON
    assert result == {"relationships": [{"type": "isPartOf"}]}


def test_get_item_relationships_failure(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the API response with a status code other than 200 (e.g., 404)
    mock_response = MagicMock()
    mock_response.status_code = 404

    # Patch the api_get method to return the mock response
    mocker.patch.object(client, "api_get", return_value=mock_response)

    # Call the get_item_relationships method with a valid UUID
    result = client.get_item_relationships("1234-5678-91011")

    # Assert that the api_get method was called with the correct URL
    client.api_get.assert_called_once_with(
        f"http://example.com/core/items/1234-5678-91011/relationships"
    )

    # Assert that the method returns None when the API call fails
    assert result is None


def test_get_item_mapped_collections_invalid_uuid(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Call the get_item_mapped_collections method with None as the UUID
    result = client.get_item_mapped_collections(None)

    # Assert that the method returns None when the UUID is None
    assert result is None


def test_get_item_mapped_collections_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the API response with a status code of 200
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "mappedCollections": [{"name": "Collection 1"}, {"name": "Collection 2"}]
    }

    # Patch the api_get method to return the mock response
    mocker.patch.object(client, "api_get", return_value=mock_response)

    # Mock parse_json to return the parsed JSON
    mocker.patch(
        "dspace_rest_client.client.parse_json",
        return_value={
            "mappedCollections": [{"name": "Collection 1"}, {"name": "Collection 2"}]
        },
    )

    # Call the get_item_mapped_collections method with a valid UUID
    result = client.get_item_mapped_collections("1234-5678-91011")

    # Assert that the api_get method was called with the correct URL
    client.api_get.assert_called_once_with(
        f"http://example.com/core/items/1234-5678-91011/mappedCollections"
    )

    # Assert that the result matches the parsed JSON
    assert result == {
        "mappedCollections": [{"name": "Collection 1"}, {"name": "Collection 2"}]
    }


def test_get_item_mapped_collections_failure(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the API response with a status code other than 200 (e.g., 404)
    mock_response = MagicMock()
    mock_response.status_code = 404

    # Patch the api_get method to return the mock response
    mocker.patch.object(client, "api_get", return_value=mock_response)

    # Call the get_item_mapped_collections method with a valid UUID
    result = client.get_item_mapped_collections("1234-5678-91011")

    # Assert that the api_get method was called with the correct URL
    client.api_get.assert_called_once_with(
        f"http://example.com/core/items/1234-5678-91011/mappedCollections"
    )

    # Assert that the method returns None when the API call fails
    assert result is None


def test_update_item_owning_collection_missing_uuids(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock logging.error
    mock_log_error = mocker.patch("logging.error")

    # Call the method with missing item_uuid and collection_uuid
    result = client.update_item_owning_collection(None, None)

    # Assert that logging.error was called with the appropriate message
    mock_log_error.assert_called_with("Item UUID or Collection UUID is missing.")

    # Assert that the method returns False when UUIDs are missing
    assert result is False


def test_update_item_owning_collection_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock a successful response with status code 204
    mock_response = MagicMock()
    mock_response.status_code = 204

    # Mock the session.put method to return the mock response
    mocker.patch.object(client.session, "put", return_value=mock_response)

    # Mock update_token to simulate token update
    mocker.patch.object(client, "update_token")

    # Mock logging.info to verify the success log message
    mock_log_info = mocker.patch("logging.info")

    # Call the method with valid item_uuid and collection_uuid
    result = client.update_item_owning_collection("item-uuid", "collection-uuid")

    # Assert that session.put was called with the correct URL and parameters
    client.session.put.assert_called_once_with(
        "http://example.com/core/items/item-uuid/owningCollection",
        data="http://example.com/core/collections/collection-uuid",
        params={"inheritPolicies": "false"},
        headers={"Content-Type": "text/uri-list", **client.request_headers},
    )

    # Assert that the method returns True on success
    assert result is True

    # Assert that logging.info was called with the correct message
    mock_log_info.assert_called_with(
        "Item item-uuid successfully moved to Collection collection-uuid."
    )


def test_update_item_owning_collection_csrf_token_issue(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock a response with status code 403 and CSRF token issue
    mock_response = MagicMock()
    mock_response.status_code = 403
    mock_response.text = "CSRF token issue"

    # Mock the session.put method to return the mock response
    mocker.patch.object(client.session, "put", return_value=mock_response)

    # Mock the update_token method to simulate token update
    mocker.patch.object(client, "update_token")

    # Mock logging.warning to verify the CSRF token warning
    mock_log_warning = mocker.patch("logging.warning")

    # Call the method with valid UUIDs
    result = client.update_item_owning_collection("item-uuid", "collection-uuid")

    # Assert that session.put was called once initially
    client.session.put.assert_called_once()

    # Assert that the method retries due to the CSRF token issue
    mock_log_warning.assert_called_with(
        "CSRF token issue encountered, retrying with updated token."
    )


def test_update_item_owning_collection_failed_update(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock a failed response with a status code other than 204 or 403 (e.g., 500)
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = "Internal server error"

    # Mock the session.put method to return the mock response
    mocker.patch.object(client.session, "put", return_value=mock_response)

    # Mock logging.error to verify the error message
    mock_log_error = mocker.patch("logging.error")

    # Call the method with valid UUIDs
    result = client.update_item_owning_collection("item-uuid", "collection-uuid")

    # Assert that session.put was called once
    client.session.put.assert_called_once()

    # Assert that the method returns False on failure
    assert result is False

    # Assert that logging.error was called with the correct error message
    mock_log_error.assert_called_with(
        "Failed to update owning collection: 500: Internal server error (http://example.com/core/items/item-uuid/owningCollection)"
    )


def test_get_item_owning_collection_invalid_uuid(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Call the get_item_owning_collection method with None as the UUID
    result = client.get_item_owning_collection(None)

    # Assert that the method returns None when the UUID is None
    assert result is None


def test_get_item_owning_collection_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the API response with a status code of 200
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "id": "collection-uuid",
        "name": "Test Collection",
    }

    # Patch the api_get method to return the mock response
    mocker.patch.object(client, "api_get", return_value=mock_response)

    # Mock the parse_json function to return parsed JSON
    mocker.patch(
        "dspace_rest_client.client.parse_json",
        return_value={"id": "collection-uuid", "name": "Test Collection"},
    )

    # Mock the Collection constructor
    mock_collection = mocker.patch(
        "dspace_rest_client.client.Collection", return_value="Mocked Collection"
    )

    # Call the get_item_owning_collection method with a valid UUID
    result = client.get_item_owning_collection("item-uuid")

    # Assert that api_get was called with the correct URL
    client.api_get.assert_called_once_with(
        f"http://example.com/core/items/item-uuid/owningCollection"
    )

    # Assert that the Collection constructor was called with the correct parsed JSON
    mock_collection.assert_called_once_with(
        api_resource={"id": "collection-uuid", "name": "Test Collection"}
    )

    # Assert that the method returns the mocked Collection object
    assert result == "Mocked Collection"


def test_get_item_owning_collection_failure(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the API response with a status code other than 200 (e.g., 404)
    mock_response = MagicMock()
    mock_response.status_code = 404

    # Patch the api_get method to return the mock response
    mocker.patch.object(client, "api_get", return_value=mock_response)

    # Call the get_item_owning_collection method with a valid UUID
    result = client.get_item_owning_collection("item-uuid")

    # Assert that api_get was called with the correct URL
    client.api_get.assert_called_once_with(
        f"http://example.com/core/items/item-uuid/owningCollection"
    )

    # Assert that the method returns None when the API call fails
    assert result is None


def test_get_item_thumbnail_invalid_uuid(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock logging.error
    mock_log_error = mocker.patch("logging.error")

    # Mock api_get to raise a ValueError (simulating an invalid UUID)
    mocker.patch.object(client, "api_get", side_effect=ValueError("Invalid UUID"))

    # Call the method with an invalid UUID
    result = client.get_item_thumbnail("invalid-uuid")

    # Assert that logging.error was called with the appropriate message
    mock_log_error.assert_called_with("Invalid item UUID: invalid-uuid")

    # Assert that the method returns None for an invalid UUID
    assert result is None


def test_get_item_thumbnail_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the API response with status code 200
    mock_response = MagicMock()
    mock_response.status_code = 200

    # Patch the api_get method to return the mock response
    mocker.patch.object(client, "api_get", return_value=mock_response)

    # Call the method with a valid UUID
    result = client.get_item_thumbnail("1234-5678-91011")

    # Assert that api_get was called twice with the correct URL
    client.api_get.assert_called_with(
        f"http://example.com/core/items/1234-5678-91011/thumbnail", None, None
    )

    # Assert that the method returns the raw response when the status code is 200
    assert result == mock_response


def test_get_item_thumbnail_no_thumbnail(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the API response with status code 204
    mock_response = MagicMock()
    mock_response.status_code = 204

    # Patch the api_get method to return the mock response
    mocker.patch.object(client, "api_get", return_value=mock_response)

    # Call the method with a valid UUID
    result = client.get_item_thumbnail("1234-5678-91011")

    # Assert that api_get was called twice with the correct URL
    client.api_get.assert_called_with(
        f"http://example.com/core/items/1234-5678-91011/thumbnail", None, None
    )

    # Assert that the method returns the appropriate message for status code 204
    assert result == "No thumbnail available for this item"


def test_get_item_thumbnail_other_status_code(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the API response with a status code other than 200 or 204 (e.g., 404)
    mock_response = MagicMock()
    mock_response.status_code = 404

    # Patch the api_get method to return the mock response
    mocker.patch.object(client, "api_get", return_value=mock_response)

    # Call the method with a valid UUID
    result = client.get_item_thumbnail("1234-5678-91011")

    # Assert that api_get was called twice with the correct URL
    client.api_get.assert_called_with(
        f"http://example.com/core/items/1234-5678-91011/thumbnail", None, None
    )

    # Assert that the method returns None for other status codes
    assert result is None


def test_get_item_metrics_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the API response with status code 200
    mock_response = MagicMock()
    mock_response.status_code = 200

    # Patch the 'api_get' method directly in the DSpaceClient class
    mocker.patch.object(client, "api_get", return_value=mock_response)

    # Call the method with a valid UUID
    result = client.get_item_metrics("1234-5678-91011")

    # Assert that 'api_get' was called once with the correct URL
    client.api_get.assert_called_once_with(
        "http://example.com/core/items/1234-5678-91011/metrics", None, None
    )

    # Assert that the method returns the mocked response
    assert result == mock_response


def test_get_item_metrics_invalid_uuid(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock logging error
    mock_logging_error = mocker.patch("logging.error")

    # Call the method with an invalid UUID
    result = client.get_item_metrics("invalid-uuid")

    # Assert that logging.error was called with the appropriate message
    mock_logging_error.assert_called_once_with("Invalid item UUID: invalid-uuid")

    # Assert that the method returns None
    assert result is None


def test_get_item_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock a valid UUID check (the UUID constructor)
    mocker.patch("dspace_rest_client.client.UUID", return_value=MagicMock(version=4))

    # Mock the API response with status code 200
    mock_response = MagicMock()
    mock_response.status_code = 200

    # Patch the `api_get` method to return the mock response
    mocker.patch.object(client, "api_get", return_value=mock_response)

    # Call the method with a valid UUID
    result = client.get_item("1234-5678-91011")

    # Assert that api_get was called with the correct URL
    client.api_get.assert_called_once_with(
        "http://example.com/core/items/1234-5678-91011", None, None
    )

    # Assert that the method returns the raw response
    assert result == mock_response


def test_get_item_invalid_uuid(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock logging.error
    mock_log_error = mocker.patch("logging.error")

    # Call the method with an invalid UUID (simulate ValueError)
    result = client.get_item("invalid-uuid")

    # Assert that logging.error was called with the appropriate message
    mock_log_error.assert_called_with("Invalid item UUID: invalid-uuid")

    # Assert that the method returns None for an invalid UUID
    assert result is None


def test_get_collection_parent_community_invalid_uuid(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Call the get_collection_parent_community method with None as the UUID
    result = client.get_collection_parent_community(None)

    # Assert that the method returns None when the UUID is None
    assert result is None


def test_get_collection_parent_community_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the API response with a status code of 200
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"id": "community-uuid", "name": "Test Community"}

    # Patch the api_get method to return the mock response
    mocker.patch.object(client, "api_get", return_value=mock_response)

    # Mock the parse_json function to return parsed JSON
    mocker.patch(
        "dspace_rest_client.client.parse_json",
        return_value={"id": "community-uuid", "name": "Test Community"},
    )

    # Mock the Community constructor
    mock_community = mocker.patch(
        "dspace_rest_client.client.Community", return_value="Mocked Community"
    )

    # Call the get_collection_parent_community method with a valid UUID
    result = client.get_collection_parent_community("collection-uuid")

    # Assert that api_get was called with the correct URL
    client.api_get.assert_called_once_with(
        f"http://example.com/core/collections/collection-uuid/parentCommunity"
    )

    # Assert that the Community constructor was called with the correct parsed JSON
    mock_community.assert_called_once_with(
        api_resource={"id": "community-uuid", "name": "Test Community"}
    )

    # Assert that the method returns the mocked Community object
    assert result == "Mocked Community"


def test_get_collection_parent_community_failure(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the API response with a status code other than 200 (e.g., 404)
    mock_response = MagicMock()
    mock_response.status_code = 404

    # Patch the api_get method to return the mock response
    mocker.patch.object(client, "api_get", return_value=mock_response)

    # Call the get_collection_parent_community method with a valid UUID
    result = client.get_collection_parent_community("collection-uuid")

    # Assert that api_get was called with the correct URL
    client.api_get.assert_called_once_with(
        f"http://example.com/core/collections/collection-uuid/parentCommunity"
    )

    # Assert that the method returns None when the API call fails
    assert result is None


def test_get_collection_parent_community_invalid_uuid(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Call the get_collection_parent_community method with None as the UUID
    result = client.get_collection_parent_community(None)

    # Assert that the method returns None when the UUID is None
    assert result is None


def test_get_collection_parent_community_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the API response with a status code of 200
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"id": "community-uuid", "name": "Test Community"}

    # Patch the api_get method to return the mock response
    mocker.patch.object(client, "api_get", return_value=mock_response)

    # Mock the parse_json function to return parsed JSON
    mocker.patch(
        "dspace_rest_client.client.parse_json",
        return_value={"id": "community-uuid", "name": "Test Community"},
    )

    # Mock the Community constructor
    mock_community = mocker.patch(
        "dspace_rest_client.client.Community", return_value="Mocked Community"
    )

    # Call the get_collection_parent_community method with a valid UUID
    result = client.get_collection_parent_community("collection-uuid")

    # Assert that api_get was called with the correct URL
    client.api_get.assert_called_once_with(
        f"http://example.com/core/collections/collection-uuid/parentCommunity"
    )

    # Assert that the Community constructor was called with the correct parsed JSON
    mock_community.assert_called_once_with(
        api_resource={"id": "community-uuid", "name": "Test Community"}
    )

    # Assert that the method returns the mocked Community object
    assert result == "Mocked Community"


def test_get_collection_parent_community_failure(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the API response with a status code other than 200 (e.g., 404)
    mock_response = MagicMock()
    mock_response.status_code = 404

    # Patch the api_get method to return the mock response
    mocker.patch.object(client, "api_get", return_value=mock_response)

    # Call the get_collection_parent_community method with a valid UUID
    result = client.get_collection_parent_community("collection-uuid")

    # Assert that api_get was called with the correct URL
    client.api_get.assert_called_once_with(
        f"http://example.com/core/collections/collection-uuid/parentCommunity"
    )

    # Assert that the method returns None when the API call fails
    assert result is None


def test_search_objects_admin_missing_uri(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock logging.error
    mock_log_error = mocker.patch("logging.error")

    # Call the method with None as the URI
    result = client.search_objects_admin()

    # Assert that logging.error was called with the appropriate message
    mock_log_error.assert_called_with("Missing required URI argument")

    # Assert that the method returns an empty list when the URI is missing
    assert result == []


def test_search_objects_admin_valid_uri(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the API response with a valid list of authorizations
    mock_json_response = {
        "_embedded": {
            "authorizations": [
                {"id": "auth1", "name": "Authorization 1"},
                {"id": "auth2", "name": "Authorization 2"},
            ]
        }
    }

    # Patch fetch_resource to return the mock response
    mocker.patch.object(client, "fetch_resource", return_value=mock_json_response)

    # Call the method with a valid URI
    result = client.search_objects_admin(uri="http://example.com/test")

    # Assert that fetch_resource was called with the correct URL and parameters
    client.fetch_resource.assert_called_once_with(
        url="http://example.com/authz/authorizations/search/object",
        params={"uri": "http://example.com/test"},
    )

    # Assert that the method returns the expected list of authorizations
    assert result == [
        {"id": "auth1", "name": "Authorization 1"},
        {"id": "auth2", "name": "Authorization 2"},
    ]


def test_search_objects_admin_with_embed_and_feature(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the API response with a valid list of authorizations
    mock_json_response = {
        "_embedded": {
            "authorizations": [
                {"id": "auth1", "name": "Authorization 1"},
                {"id": "auth2", "name": "Authorization 2"},
            ]
        }
    }

    # Patch fetch_resource to return the mock response
    mocker.patch.object(client, "fetch_resource", return_value=mock_json_response)

    # Call the method with a valid URI, embed, and feature
    result = client.search_objects_admin(
        uri="http://example.com/test", embed="embedParam", feature="featureParam"
    )

    # Assert that fetch_resource was called with the correct URL and parameters
    client.fetch_resource.assert_called_once_with(
        url="http://example.com/authz/authorizations/search/object",
        params={
            "uri": "http://example.com/test",
            "embed": "embedParam",
            "feature": "featureParam",
        },
    )

    # Assert that the method returns the expected list of authorizations
    assert result == [
        {"id": "auth1", "name": "Authorization 1"},
        {"id": "auth2", "name": "Authorization 2"},
    ]


def test_search_objects_admin_json_parsing_error(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock logging.error
    mock_log_error = mocker.patch("logging.error")

    # Mock the API response with a malformed JSON structure that raises a TypeError or KeyError
    mock_json_response = {}

    # Patch fetch_resource to return the malformed JSON response
    mocker.patch.object(client, "fetch_resource", return_value=mock_json_response)

    # Call the method with a valid URI
    result = client.search_objects_admin(uri="http://example.com/test")

    # Assert that logging.error was called with an appropriate error message
    mock_log_error.assert_called_once_with(
        "error parsing search result json 'NoneType' object is not subscriptable"
    )

    # Assert that the method returns an empty list when a JSON parsing error occurs
    assert result == []


def test_search_object_detail_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock response with a successful search result
    mock_response = {
        "_embedded": {
            "searchResult": {
                "_embedded": {
                    "objects": [
                        {"_embedded": {"indexableObject": {"uuid": "obj1", "name": "Object 1"}}},
                        {"_embedded": {"indexableObject": {"uuid": "obj2", "name": "Object 2"}}}
                    ]
                },
                "page": {"size": 2, "totalElements": 2, "totalPages": 1, "number": 0},
                "facets": []
            }
        }
    }

    # Mock fetch_resource to return the mocked response
    mocker.patch.object(client, "fetch_resource", return_value=mock_response)

    # Call the search_object_detail method with query and sorting
    dsos, page_data, facets = client.search_object_detail(query="test", sort="name,asc")

    # Assert the results
    assert len(dsos) == 2
    assert dsos[0].uuid == "obj1"
    assert dsos[1].uuid == "obj2"
    assert page_data["totalElements"] == 2
    assert facets == []
    
    # Verify that fetch_resource was called with correct parameters
    client.fetch_resource.assert_called_once_with(
        url="http://example.com/discover/search/objects",
        params={"query": "test", "sort": "name,asc", "page": 0, "size": 20}
    )


def test_search_object_detail_no_results(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock response with no search results
    mock_response = {
        "_embedded": {
            "searchResult": {
                "_embedded": {"objects": []},
                "page": {"size": 0, "totalElements": 0, "totalPages": 0, "number": 0},
                "facets": []
            }
        }
    }

    # Mock fetch_resource to return the mocked response
    mocker.patch.object(client, "fetch_resource", return_value=mock_response)

    # Call the search_object_detail method with no results
    dsos, page_data, facets = client.search_object_detail(query="empty", sort="name,asc")

    # Assert the results
    assert len(dsos) == 0
    assert page_data["totalElements"] == 0
    assert facets == []
    
    # Verify fetch_resource was called with correct parameters
    client.fetch_resource.assert_called_once_with(
        url="http://example.com/discover/search/objects",
        params={"query": "empty", "sort": "name,asc", "page": 0, "size": 20}
    )


def test_search_object_detail_error_handling(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock response with missing keys (malformed response)
    mock_response = {}

    # Mock fetch_resource to return the mocked malformed response
    mocker.patch.object(client, "fetch_resource", return_value=mock_response)

    # Mock logging.error to capture any error messages
    mock_log_error = mocker.patch("logging.error")

    # Call the search_object_detail method expecting it to handle the error
    dsos, page_data, facets = client.search_object_detail(query="malformed")

    # Assert that no results are returned due to error
    assert len(dsos) == 0
    assert page_data is None
    assert facets is None

    # Verify that the error log was triggered
    mock_log_error.assert_called_once_with("error parsing search result json 'NoneType' object is not subscriptable")


def test_search_object_detail_with_filters(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock response with a successful search result
    mock_response = {
        "_embedded": {
            "searchResult": {
                "_embedded": {
                    "objects": [
                        {"_embedded": {"indexableObject": {"uuid": "obj1", "name": "Object 1"}}}
                    ]
                },
                "page": {"size": 1, "totalElements": 1, "totalPages": 1, "number": 0},
                "facets": []
            }
        }
    }

    # Mock fetch_resource to return the mocked response
    mocker.patch.object(client, "fetch_resource", return_value=mock_response)

    # Call the search_object_detail method with filters
    filters = {"f.entityType": "Publication,equals"}
    result = client.search_object_detail(query="test", filters=filters, page=1, size=10)

    # Assert that fetch_resource was called with correct URL and parameters
    client.fetch_resource.assert_called_once_with(
        url="http://example.com/discover/search/objects",
        params={"query": "test", "page": 1, "size": 10, **filters}
    )


def test_download_bitstream_missing_uuid(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock logging.error to capture error logs (if any)
    mock_log_error = mocker.patch("logging.error")

    # Call the method with None as the UUID
    result = client.download_bitstream(uuid=None)

    # Assert that the method does not proceed with the API request and returns None
    assert result is None


def test_download_bitstream_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock a valid response object with status code 200
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = b"bitstream content"
    mock_response.headers = {"Content-Type": "application/octet-stream"}

    # Patch the api_get method to return the mock response
    mocker.patch.object(client, "api_get", return_value=mock_response)

    # Patch the get_short_lived_token method to return a mock token
    mocker.patch.object(client, "get_short_lived_token", return_value="Bearer token123")

    # Call the method with a valid UUID
    result = client.download_bitstream("bitstream-uuid")

    # Assert that api_get was called with the correct URL and headers
    client.api_get.assert_called_once_with(
        "http://example.com/core/bitstreams/bitstream-uuid/content",
        headers={
            "User-Agent": client.USER_AGENT,
            "Authorization": "Bearer token123",
        },
    )

    # Assert that the method returns the full response object
    assert result.status_code == 200
    assert result.content == b"bitstream content"
    assert result.headers == {"Content-Type": "application/octet-stream"}


def test_download_bitstream_failed(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock a response object with a failed status code (e.g., 404)
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_response.content = b"not found"
    mock_response.headers = {"Content-Type": "text/plain"}

    # Patch the api_get method to return the mock response
    mocker.patch.object(client, "api_get", return_value=mock_response)

    # Patch the get_short_lived_token method to return a mock token
    mocker.patch.object(client, "get_short_lived_token", return_value="Bearer token123")

    # Call the method with a valid UUID
    result = client.download_bitstream("bitstream-uuid")

    # Assert that api_get was called with the correct URL and headers
    client.api_get.assert_called_once_with(
        "http://example.com/core/bitstreams/bitstream-uuid/content",
        headers={
            "User-Agent": client.USER_AGENT,
            "Authorization": "Bearer token123",
        },
    )

    # Assert that the method handles non-200 status code appropriately (returns None)
    assert result is None


def test_get_sub_communities_missing_uuid(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Call the method with None as the UUID
    result = client.get_sub_communities(uuid=None)

    # Assert that the method returns None when the UUID is missing
    assert result is None


def test_get_sub_communities_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the API response with a valid list of sub-communities
    mock_json_response = {
        "_embedded": {
            "subcommunities": [
                {"id": "subcommunity1", "name": "Subcommunity 1"},
                {"id": "subcommunity2", "name": "Subcommunity 2"},
            ]
        }
    }

    # Patch fetch_resource to return the mock response
    mocker.patch.object(client, "fetch_resource", return_value=mock_json_response)

    # Call the method with a valid UUID
    result = client.get_sub_communities(
        uuid="community-uuid", page=1, size=10, sort="name,asc"
    )

    # Assert that fetch_resource was called with the correct URL and parameters
    client.fetch_resource.assert_called_once_with(
        "http://example.com/core/communities/community-uuid/subcommunities",
        {"page": 1, "size": 10, "sort": "name,asc"},
    )

    # Assert that the method returns the expected list of sub-communities
    assert len(result) == 2
    assert result[0]["id"] == "subcommunity1"
    assert result[1]["id"] == "subcommunity2"


def test_get_sub_communities_no_subcommunities(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the API response with an empty list of sub-communities
    mock_json_response = {"_embedded": {"subcommunities": []}}

    # Patch fetch_resource to return the mock response
    mocker.patch.object(client, "fetch_resource", return_value=mock_json_response)

    # Call the method with a valid UUID
    result = client.get_sub_communities(uuid="community-uuid")

    # Assert that the method returns an empty list when no sub-communities are found
    assert result == []


def test_get_sub_communities_invalid_response(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the API response without the expected '_embedded' or 'subcommunities' keys
    mock_json_response = {}

    # Patch fetch_resource to return the mock response
    mocker.patch.object(client, "fetch_resource", return_value=mock_json_response)

    # Call the method with a valid UUID
    result = client.get_sub_communities(uuid="community-uuid")

    # Assert that the method returns None when the expected keys are not present
    assert result is None


def test_get_parent_community_missing_uuid(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Call the method with None as the UUID
    result = client.get_parent_community(uuid=None)

    # Assert that the method returns None when UUID is missing
    assert result is None


def test_get_parent_community_success(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the API response with status code 200
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "id": "parent-community-uuid",
        "name": "Parent Community",
    }

    # Patch the api_get method to return the mock response
    mocker.patch.object(client, "api_get", return_value=mock_response)

    # Mock parse_json to return parsed JSON
    mocker.patch(
        "dspace_rest_client.client.parse_json",
        return_value={"id": "parent-community-uuid", "name": "Parent Community"},
    )

    # Mock the Community constructor
    mock_community = mocker.patch(
        "dspace_rest_client.client.Community", return_value="Mocked Community"
    )

    # Call the method with a valid UUID
    result = client.get_parent_community(uuid="community-uuid")

    # Assert that api_get was called with the correct URL
    client.api_get.assert_called_once_with(
        "http://example.com/core/communities/community-uuid/parentCommunity"
    )

    # Assert that the Community constructor was called with the correct parsed JSON
    mock_community.assert_called_once_with(
        api_resource={"id": "parent-community-uuid", "name": "Parent Community"}
    )

    # Assert that the method returns the mocked Community object
    assert result == "Mocked Community"


def test_get_parent_community_failure(mocker):
    client = DSpaceClient(
        api_endpoint="http://example.com", username="admin", password="admin"
    )

    # Mock the API response with a failed status code (e.g., 404)
    mock_response = MagicMock()
    mock_response.status_code = 404

    # Patch the api_get method to return the mock response
    mocker.patch.object(client, "api_get", return_value=mock_response)

    # Call the method with a valid UUID
    result = client.get_parent_community(uuid="community-uuid")

    # Assert that api_get was called with the correct URL
    client.api_get.assert_called_once_with(
        "http://example.com/core/communities/community-uuid/parentCommunity"
    )

    # Assert that the method returns None when the API call fails
    assert result is None
