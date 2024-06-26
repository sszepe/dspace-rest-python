import json
import logging
import os
import pytest
import requests
import requests_mock

from faker import Faker
from dotenv import dotenv_values
from unittest.mock import MagicMock, patch, call

from ..client import parse_json, DSpaceClient, DSpaceObject, SimpleDSpaceObject, Bitstream, Bundle, Item, Community, Collection, User, Group

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

def test_dspace_client_session_property():
    """Test that the session property is a requests.Session object"""
    d = DSpaceClient("https://example.com", "username", "password")
    assert isinstance(d.session, requests.Session)


def test_dspace_client_initialization_defaults(monkeypatch, mocker):
    # Load .env values if .env file exists
    env_path = '.env'
    env_values = {}
    if os.path.exists(env_path):
        env_values = dotenv_values(env_path)
    
    # Mock environment variables (or use values from .env if present)
    api_endpoint = env_values.get("DSPACE_API_ENDPOINT", "http://localhost:8080/server/api")
    username = env_values.get("DSPACE_API_USERNAME", "admin")
    password = env_values.get("DSPACE_API_PASSWORD", "admin")
    solr_endpoint = env_values.get("SOLR_ENDPOINT", "http://localhost:8983/solr")
    solr_auth = env_values.get("SOLR_AUTH", None)
    
    # Apply mocked environment variables
    monkeypatch.setenv("DSPACE_API_ENDPOINT", api_endpoint)
    monkeypatch.setenv("DSPACE_API_USERNAME", username)
    monkeypatch.setenv("DSPACE_API_PASSWORD", password)
    monkeypatch.setenv("SOLR_ENDPOINT", solr_endpoint)
    monkeypatch.setenv("SOLR_AUTH", solr_auth)
    
    # Mock external dependencies
    mocker.patch('requests.Session')
    mocker.patch('pysolr.Solr')
    
    # Initialization
    client = DSpaceClient()
    
    # Assertions using either the .env values or the default test values
    assert client.API_ENDPOINT == api_endpoint
    assert client.USERNAME == username
    assert client.PASSWORD == password
    assert client.SOLR_ENDPOINT == solr_endpoint
    assert client.SOLR_AUTH == solr_auth

def test_dspace_client_initialization_custom_args(monkeypatch, mocker):
    # Mock environment variables as a fallback
    monkeypatch.setenv("DSPACE_API_ENDPOINT", "http://fallback:8080/server/api")
    monkeypatch.setenv("DSPACE_API_USERNAME", "fallbackUser")
    monkeypatch.setenv("DSPACE_API_PASSWORD", "fallbackPass")
    monkeypatch.setenv("SOLR_ENDPOINT", "http://fallback:8983/solr")
    monkeypatch.setenv("SOLR_AUTH", None)

    # Mock external dependencies
    mocker.patch('requests.Session')
    mocker.patch('pysolr.Solr')
    
    # Custom arguments for initialization
    custom_args = {
        "api_endpoint": "http://custom:8080/server/api",
        "username": "customUser",
        "password": "customPass",
        "solr_endpoint": "http://custom:8983/solr",
        "solr_auth": None,
        "fake_user_agent": True
    }
    client = DSpaceClient(**custom_args)
    
    # Assertions to verify custom arguments are used
    assert client.API_ENDPOINT == custom_args["api_endpoint"]
    assert client.USERNAME == custom_args["username"]
    assert client.PASSWORD == custom_args["password"]
    assert client.SOLR_ENDPOINT == custom_args["solr_endpoint"]
    assert client.SOLR_AUTH == custom_args["solr_auth"]

def test_authenticate_success():
    with requests_mock.Mocker() as m:
        login_url = 'http://localhost:8080/server/api/authn/login'
        status_url = 'http://localhost:8080/server/api/authn/status'

        # Mock the POST to the login URL to return a successful status code
        m.post(login_url, status_code=200, headers={"Authorization": "Bearer token123"})
        # Mock the GET to the auth status URL to return authenticated status
        m.get(status_url, json={"authenticated": True}, status_code=200)

        client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
        result = client.authenticate()

        assert result is True

def test_authenticate_invalid_credentials():
    with requests_mock.Mocker() as m:
        login_url = 'http://localhost:8080/server/api/authn/login'

        # Mock the POST to return a 401 Unauthorized
        m.post(login_url, status_code=401)

        client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='wrong', password='wrong')
        result = client.authenticate()

        assert result is False

def test_authenticate_csrf_failure_then_success():
    with requests_mock.Mocker() as m:
        login_url = 'http://localhost:8080/server/api/authn/login'
        status_url = 'http://localhost:8080/server/api/authn/status'

        # First POST attempt returns 403 Forbidden (simulating CSRF failure)
        m.post(login_url, [{'status_code': 403}, {'status_code': 200, 'headers': {'Authorization': 'Bearer token123'}}])
        # Subsequent GET to the auth status URL returns authenticated status
        m.get(status_url, json={"authenticated": True}, status_code=200)

        client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
        result = client.authenticate()

        assert result is True

def test_authenticate_too_many_retries(mocker):
    client = DSpaceClient(api_endpoint='http://example.com', username='admin', password='admin')
    
    # Mock the session.post method to simulate a 403 Forbidden response
    mocked_post = mocker.patch.object(client.session, 'post', side_effect=[
        MagicMock(status_code=403, text="CSRF token invalid"),
        MagicMock(status_code=403, text="CSRF token invalid")
    ])

    # Mock logging.error to assert it gets called with the expected message
    with mocker.patch('logging.error') as mocked_error_log:
        result = client.authenticate()
        
        # Verify that the method returns False after too many retries
        assert result is False
        
        # Verify that the session.post method was called twice (initial call + retry)
        assert mocked_post.call_count == 2

def test_refresh_token(mocker):
    # Mock the api_post method to simulate a successful POST request with a CSRF token
    mock_response = MagicMock()
    mock_response.headers = {'DSPACE-XSRF-TOKEN': 'new-csrf-token'}
    mocker.patch.object(DSpaceClient, 'api_post', return_value=mock_response)

    # Mock the update_token method to verify it's called with the correct response
    mock_update_token = mocker.patch.object(DSpaceClient, 'update_token')

    # Initialize the DSpaceClient and call refresh_token
    client = DSpaceClient()
    client.refresh_token()

    # Assert the update_token was called with the response from api_post
    mock_update_token.assert_called_once_with(mock_response)

def test_logout_success(mocker):
    # Setup API endpoint and username for the test
    api_endpoint = "http://localhost:8080/server/api"
    username = "testuser"
    
    # Initialize the DSpaceClient
    client = DSpaceClient(api_endpoint=api_endpoint, username=username, password="password")
    
    # Mock the POST request to the logout endpoint to return 204 No Content
    logout_url = f"{api_endpoint}/authn/logout"
    with requests_mock.Mocker() as m:
        m.post(logout_url, status_code=204)

        # Mock logging to verify the logout message
        mock_logger = mocker.patch.object(logging, 'info')

        # Call the logout method
        result = client.logout()

        # Verify the logout was successful
        assert result is True, "Logout should return True on success"
        
        # Verify logging was called with the correct message
        mock_logger.assert_called_once_with(f"User {username} logged out successfully")

def test_api_get_success():
    with requests_mock.Mocker() as m:
        url = 'http://localhost:8080/server/api/test'
        m.get(url, json={"key": "value"}, status_code=200)

        client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
        response = client.api_get(url)

        assert response.status_code == 200
        assert response.json() == {"key": "value"}

@pytest.fixture
def dspace_client():
    # Setup DSpaceClient with mocked session
    client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
    client.session = MagicMock()
    return client

def test_api_post_uri_success():
    # Define the API endpoint, URI list, and test client setup
    api_endpoint = 'http://localhost:8080/server/api'
    url = f'{api_endpoint}/test'
    uri_list = "http://localhost:8080/server/api/other/object\nhttp://localhost:8080/server/api/another/object"
    
    # Initialize DSpaceClient
    client = DSpaceClient(api_endpoint=api_endpoint, username='admin', password='admin')

    # Use requests_mock to mock the specific POST request
    with requests_mock.Mocker() as m:
        m.post(url, text='success', status_code=200)

        # Invoke the api_post_uri method
        response = client.api_post_uri(url, None, uri_list)
        
        # Check if the response status code is as expected
        assert response.status_code == 200

def test_api_post_uri_unauthorized():
    url = 'http://localhost:8080/server/api/test'
    uri_list = "http://localhost:8080/server/api/other/object"
    
    with requests_mock.Mocker() as m:
        m.post(url, status_code=401)

        client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
        response = client.api_post_uri(url, None, uri_list)
        
        assert response.status_code == 401

def test_api_post_uri_csrf_retry():
    url = 'http://localhost:8080/server/api/test'
    uri_list = "http://localhost:8080/server/api/other/object"

    with requests_mock.Mocker() as m:
        m.post(url, [{'status_code': 403, 'json': {'message': 'CSRF token invalid'}}, {'text': 'success', 'status_code': 200}])

        client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
        response = client.api_post_uri(url, None, uri_list, retry=True)
        
        assert response.status_code == 200

def test_api_post_retry_on_csrf_failure(mocker):
    client = DSpaceClient(api_endpoint='http://example.com', username='admin', password='admin')
    url = "http://example.com/api/test"
    params = {"test": "param"}
    json_data = {"key": "value"}
    csrf_failure_response = MagicMock(status_code=403, text='CSRF token invalid')
    success_response = MagicMock(status_code=200, json=lambda: {"success": True})

    # Mock session.post to simulate CSRF token failure followed by a successful retry
    mocked_post = mocker.patch.object(client.session, 'post', side_effect=[csrf_failure_response, success_response])
    
    # Mock parse_json to return a simulated response indicating CSRF token failure
    mocker.patch('dspace_rest_client.client.parse_json', side_effect=[{"message": "CSRF token invalid"}, {"success": True}])
    
    # Mock logging.debug to assert it gets called with the expected message
    with mocker.patch('logging.debug') as mock_log_debug:
        response = client.api_post(url, params=params, json=json_data)
        
        # Verify that the method returns the success response after retrying
        assert response.json() == {"success": True}
        
        # Verify that session.post was called twice
        assert mocked_post.call_count == 2
        
        # Verify the first call to session.post was with the initial parameters
        mocked_post.assert_has_calls([
            call(url, json=json_data, params=params, headers=client.request_headers),
            call(url, json=json_data, params=params, headers=client.request_headers)
        ])
                
def test_api_post_success():
    url = 'http://localhost:8080/server/api/test'
    json_data = {"key": "value"}

    with requests_mock.Mocker() as m:
        m.post(url, json=json_data, status_code=200)

        client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
        response = client.api_post(url, None, json_data)
        
        assert response.status_code == 200
        assert response.json() == json_data

def test_api_post_unauthorized():
    url = 'http://localhost:8080/server/api/test'
    json_data = {"key": "value"}

    with requests_mock.Mocker() as m:
        m.post(url, status_code=401)

        client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
        response = client.api_post(url, None, json_data)
        
        assert response.status_code == 401

def test_api_post_csrf_retry():
    url = 'http://localhost:8080/server/api/test'
    json_data = {"key": "value"}

    with requests_mock.Mocker() as m:
        m.post(url, [{'status_code': 403, 'json': {'message': 'CSRF token invalid'}}, {'json': json_data, 'status_code': 200}])

        client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
        response = client.api_post(url, None, json_data, retry=True)
        
        assert response.status_code == 200
        assert response.json() == json_data

def test_api_post_uri_retry_on_csrf_failure(mocker):
    client = DSpaceClient(api_endpoint='http://example.com', username='admin', password='admin')
    url = "http://example.com/api/test"
    params = {"test": "param"}
    uri_list = "http://example.com/api/item/1"
    csrf_failure_response = MagicMock(status_code=403, json=lambda: {"message": "CSRF token invalid"})
    success_response = MagicMock(status_code=200, json=lambda: {"success": True})

    # Mock session.post to simulate CSRF token failure followed by a successful retry
    mocked_post = mocker.patch.object(client.session, 'post', side_effect=[csrf_failure_response, success_response])
    
    # Mock logging.debug to assert it gets called with the expected message
    with mocker.patch('logging.debug') as mock_log_debug:
        response = client.api_post_uri(url, params=params, uri_list=uri_list)
        
        # Verify that the method returns the success response after retrying
        assert response.json() == {"success": True}
        
        # Verify that session.post was called twice (initial call + retry)
        assert mocked_post.call_count == 2
        
        # Verify the first call to session.post was with the initial parameters
        mocked_post.assert_has_calls([
            call(url, data=uri_list, params=params, headers=client.list_request_headers),
            call(url, data=uri_list, params=params, headers=client.list_request_headers)
        ])

def test_api_put_success():
    url = 'http://localhost:8080/server/api/test'
    json_data = {"key": "updated value"}

    with requests_mock.Mocker() as m:
        m.put(url, json=json_data, status_code=200)

        client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
        response = client.api_put(url, params=None, json=json_data)
        
        assert response.status_code == 200
        assert response.json() == json_data

def test_api_put_csrf_retry():
    url = 'http://localhost:8080/server/api/test'
    json_data = {"key": "value for retry"}

    with requests_mock.Mocker() as m:
        # Simulate CSRF failure on first request, then success on retry
        m.put(url, [
            {'json': {'message': 'CSRF token invalid'}, 'status_code': 403},
            {'json': json_data, 'status_code': 200}
        ])

        client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
        response = client.api_put(url, params=None, json=json_data, retry=False)
        
        assert response.status_code == 200
        assert response.json() == json_data

def test_api_put_retry_limit():
    url = 'http://localhost:8080/server/api/test'
    json_data = {"key": "retry limit test"}

    with requests_mock.Mocker() as m, patch.object(logging, 'warning') as mock_warning:
        m.put(url, json={'message': 'CSRF token invalid'}, status_code=403)

        client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
        response = client.api_put(url, params=None, json=json_data, retry=True)
        
        assert response.status_code == 403
        mock_warning.assert_called_once()

def test_api_delete_success():
    url = 'http://localhost:8080/server/api/test'
    
    with requests_mock.Mocker() as m:
        m.delete(url, status_code=204)  # 204 No Content is common for successful DELETE operations

        client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
        response = client.api_delete(url, params={})
        
        assert response.status_code == 204

def test_api_delete_csrf_retry():
    url = 'http://localhost:8080/server/api/test'

    with requests_mock.Mocker() as m:
        # First DELETE attempt triggers CSRF failure; second attempt succeeds
        m.delete(url, [
            {'json': {'message': 'CSRF token invalid'}, 'status_code': 403},
            {'status_code': 204}
        ])

        client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
        response = client.api_delete(url, params={}, retry=False) 
        
        assert response.status_code == 204

def test_api_delete_retry_limit():
    url = 'http://localhost:8080/server/api/test'

    with requests_mock.Mocker() as m, patch.object(logging, 'warning') as mock_warning:
        m.delete(url, json={'message': 'CSRF token invalid'}, status_code=403)

        client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
        response = client.api_delete(url, params={}, retry=True) 
        
        assert response.status_code == 403
        mock_warning.assert_called_once()

def test_api_patch_success():
    url = 'http://localhost:8080/server/api/items/1234'
    operation = "replace"
    path = "/metadata/dc.title/0/value"
    value = "Updated Title"
    
    with requests_mock.Mocker() as m:
        m.patch(url, json={"type": "item", "id": "1234"}, status_code=200)

        client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
        response = client.api_patch(url, operation, path, value)
        
        assert response.status_code == 200
        assert response.json() == {"type": "item", "id": "1234"}

def test_api_patch_csrf_retry():
    url = 'http://localhost:8080/server/api/items/1234'
    operation = "add"
    path = "/metadata/dc.contributor.author/-"
    value = "New Author"
    
    with requests_mock.Mocker() as m:
        # Simulate CSRF failure on first attempt and success on retry
        m.patch(url, [
            {'json': {'message': 'CSRF token invalid'}, 'status_code': 403},
            {'json': {"type": "item", "id": "1234"}, 'status_code': 200}
        ])

        client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
        response = client.api_patch(url, operation, path, value, retry=False)  # Initially without retry
        
        assert response.status_code == 200

def test_api_patch_missing_arguments():
    with patch.object(DSpaceClient, 'update_token'), \
         patch.object(logging, 'error') as mock_log_error:
        
        client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
        response = client.api_patch(url=None, operation=None, path=None, value=None)
        
        # Ensure that no request is made and logging.error is called
        assert response is None
        assert mock_log_error.called

def test_api_patch_invalid_path(mocker):
    client = DSpaceClient(api_endpoint='http://example.com', username='admin', password='admin')
    
    # Mock logging.error to capture the log message
    with mocker.patch('logging.error') as mock_log_error:
        result = client.api_patch(url="http://example.com/api/test", operation="add", path=None, value="test")
        
        # Verify the method returns None
        assert result is None

def test_api_patch_missing_value(mocker):
    client = DSpaceClient(api_endpoint='http://example.com', username='admin', password='admin')
    
    # Mock logging.error for capturing log messages
    with mocker.patch('logging.error') as mock_log_error:
        result = client.api_patch(url="http://example.com/api/test", operation="add", path="/metadata/dc.title", value=None)
        
        # Verify the method returns None
        assert result is None

def test_api_patch_move_operation(mocker):
    client = DSpaceClient(api_endpoint='http://example.com', username='admin', password='admin')
    original_path = "/original/path"
    new_path = "/new/path"
    
    # Mock session.patch to prevent actual HTTP calls
    mocked_patch = mocker.patch.object(client.session, 'patch', return_value=MagicMock(status_code=200))
    
    client.api_patch(url="http://example.com/api/test", operation="move", path=new_path, value=original_path)
    
    # Extract the json data sent to session.patch
    called_args, called_kwargs = mocked_patch.call_args
    sent_data = called_kwargs["json"][0]
    
    # Verify the 'from' and 'path' values in data
    assert sent_data["from"] == original_path
    assert sent_data["path"] == new_path

def test_api_patch_retry_warning():
    # Create an instance of DSpaceClient
    client = DSpaceClient(api_endpoint='http://example.com', username='admin', password='admin')
    
    # Mock the session.patch method to return a 403 response
    with patch.object(client.session, 'patch', return_value=MagicMock(status_code=403, text='Forbidden')) as mock_patch:
        # Mock the parse_json method to return a JSON-like response
        with patch('dspace_rest_client.client.parse_json', return_value={'message': 'CSRF token expired'}) as mock_parse_json:
            # Mock the logging.warning method
            with patch('dspace_rest_client.client.logging.warning') as mock_warning:
                # Call the api_patch method with retry set to True
                client.api_patch(url="http://example.com/api/test", operation="add", path="/metadata/dc.title", value="test", retry=True)
                
@pytest.fixture
def dspace_client_dso(mocker):
    client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
    mocker.patch.object(client, 'fetch_resource', return_value={
        "_embedded": {
            "searchResult": {
                "_embedded": {
                    "objects": [
                        {"_embedded": {"indexableObject": {"id": "123", "name": "Test DSO 1"}}},
                        {"_embedded": {"indexableObject": {"id": "456", "name": "Test DSO 2"}}},
                    ]
                }
            }
        }
    })
    return client

def test_search_objects_success(dspace_client_dso):
    dsos = dspace_client_dso.search_objects(query="test", dso_type="collection", scope="123456789/1", size=10, page=0, sort="name,asc")
    
    assert len(dsos) == 2
    assert all(isinstance(dso, DSpaceObject) for dso in dsos)
    assert dsos[0].id == "123" and dsos[1].id == "456"

def test_search_objects_failure(dspace_client_dso):
    dspace_client_dso.fetch_resource.return_value = None
    dsos = dspace_client_dso.search_objects(query="test")
    
    assert dsos == []

def test_fetch_resource_success(mocker):
    client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"key": "value"}
    mocker.patch.object(client, 'api_get', return_value=mock_response)

    result = client.fetch_resource("http://localhost:8080/server/api/resource", {})
    assert result == {"key": "value"}

def test_fetch_resource_failure(mocker):
    client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_response.text = "Resource not found"
    mocker.patch.object(client, 'api_get', return_value=mock_response)

    with mocker.patch('logging.error') as mock_log_error:
        result = client.fetch_resource("http://localhost:8080/server/api/nonexistent", {})
        
        assert result is None

def test_fetch_resource_json_parse_error(mocker):
    client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.side_effect = ValueError("Mock JSON parse error")
    mocker.patch.object(client, 'api_get', return_value=mock_response)

    mocker.patch('logging.error')
    result = client.fetch_resource("http://localhost:8080/server/api/badjson", {})
    
    assert result is None

def test_get_dso_valid_uuid():
    client = DSpaceClient(api_endpoint='http://example.com', username='admin', password='admin')
    
    # Mock the UUID method to return a valid UUID version
    with patch('dspace_rest_client.client.UUID', return_value=MagicMock(version=4)) as mock_uuid:
        with patch.object(client, 'api_get', return_value={'uuid': '12345678-1234-5678-1234-567812345678'}) as mock_api_get:
            # Call the get_dso method with a valid UUID
            result = client.get_dso(url="http://example.com/api/test", uuid="12345678-1234-5678-1234-567812345678")
            
            mock_api_get.assert_called_once_with("http://example.com/api/test/12345678-1234-5678-1234-567812345678", None, None)
            assert result == {'uuid': '12345678-1234-5678-1234-567812345678'}

def test_get_dso_invalid_uuid():
    # Create an instance of DSpaceClient
    client = DSpaceClient(api_endpoint='http://example.com', username='admin', password='admin')
    
    # Mock the UUID method to raise a ValueError (simulate invalid UUID)
    with patch('dspace_rest_client.client.UUID', side_effect=ValueError("Invalid UUID")) as mock_uuid:
        result = client.get_dso(url="http://example.com/api/test", uuid="invalid_uuid")
        
        assert result is None 

def test_create_dso_success(mocker):
    client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
    success_response = MagicMock(status_code=201, json=lambda: {"type": "item", "uuid": "1234-5678"})
    mocker.patch.object(client, 'api_post', return_value=success_response)

    with patch.object(logging, 'info') as mock_info_log:
        response = client.create_dso("http://localhost:8080/server/api/items", None, {"name": "New DSO"})
        
        assert response.status_code == 201
        mock_info_log.assert_called_with('item 1234-5678 created successfully!')

def test_create_dso_failure(mocker):
    client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
    failure_response = MagicMock(status_code=400, text="Bad request error")
    mocker.patch.object(client, 'api_post', return_value=failure_response)

    with patch.object(logging, 'error') as mock_error_log:
        response = client.create_dso("http://localhost:8080/server/api/items", None, {"invalid": "data"})
        
        assert response.status_code == 400
        mock_error_log.assert_called_with("create operation failed: 400: Bad request error (http://localhost:8080/server/api/items)")

@pytest.fixture
def mock_dso():
    dso = SimpleDSpaceObject()
    dso.links = {"self": {"href": "http://localhost:8080/server/api/core/items/123"}}
    dso.uuid = "123"
    dso.type = "item"
    dso.as_dict = MagicMock(return_value={"name": "Updated DSO"})
    return dso

def test_update_dso_success(mocker, mock_dso):
    client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
    success_response = MagicMock(status_code=200, json=lambda: {"uuid": mock_dso.uuid, "type": mock_dso.type})
    mocker.patch.object(client, 'api_put', return_value=success_response)

    with mocker.patch('logging.info') as mock_info_log:
        updated_dso = client.update_dso(mock_dso)
        
        assert updated_dso is not None
        assert updated_dso.uuid == "123"

def test_update_dso_invalid_type(mocker, mock_dso):
    client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
    non_simple_dso = MagicMock()  # Simulate a non-SimpleDSpaceObject
    non_simple_dso.links = mock_dso.links

    with mocker.patch('logging.error') as mock_error_log:
        result = client.update_dso(non_simple_dso)
        
        assert result == non_simple_dso

def test_update_dso_failure(mocker, mock_dso):
    client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
    failed_response = MagicMock(status_code=400, text="Bad request")
    mocker.patch.object(client, 'api_put', return_value=failed_response)

    with mocker.patch('logging.error') as mock_error_log:
        result = client.update_dso(mock_dso)
        
        assert result is None

def test_update_dso_with_none_dso(mocker):
    client = DSpaceClient(api_endpoint='http://example.com', username='admin', password='admin')
    
    result = client.update_dso(dso=None)
    
    assert result is None

def test_delete_dso_success(mocker, mock_dso):
    client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
    mocker.patch.object(client, 'api_delete', return_value=MagicMock(status_code=204))

    with mocker.patch('logging.info') as mock_info_log:
        response = client.delete_dso(dso=mock_dso)
        
        assert response.status_code == 204

def test_delete_dso_no_dso_or_url(mocker):
    client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')

    with mocker.patch('logging.error') as mock_error_log:
        response = client.delete_dso()
        
        assert response is None

def test_delete_dso_api_error(mocker, mock_dso):
    client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
    mocker.patch.object(client, 'api_delete', return_value=MagicMock(status_code=400, text="Bad request"))

    with mocker.patch('logging.error') as mock_error_log:
        response = client.delete_dso(dso=mock_dso)
        
        assert response is None

@pytest.fixture
def mock_item():
    item = Item()
    item.uuid = "item-uuid"
    return item

def test_get_bundles_for_item(mocker, mock_item):
    client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
    mock_bundles_data = {
        "_embedded": {
            "bundles": [
                {"uuid": "bundle-uuid-1", "name": "ORIGINAL"},
                {"uuid": "bundle-uuid-2", "name": "LICENSE"}
            ]
        }
    }
    mocker.patch.object(client, 'fetch_resource', return_value=mock_bundles_data)

    bundles = client.get_bundles(parent=mock_item)
    
    assert len(bundles) == 2
    assert all(isinstance(bundle, Bundle) for bundle in bundles)
    assert bundles[0].uuid == "bundle-uuid-1"
    assert bundles[1].uuid == "bundle-uuid-2"

def test_get_single_bundle(mocker):
    client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
    mock_bundle_data = {"uuid": "bundle-uuid-1", "name": "ORIGINAL"}
    mocker.patch.object(client, 'fetch_resource', return_value=mock_bundle_data)

    bundles = client.get_bundles(uuid="bundle-uuid-1")
    
    assert len(bundles) == 1
    assert isinstance(bundles[0], Bundle)
    assert bundles[0].uuid == "bundle-uuid-1"

def test_get_bundles_no_parent_or_uuid(mocker):
    client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
    mocker.patch.object(client, 'fetch_resource')

    bundles = client.get_bundles()
    
    assert bundles == []
    client.fetch_resource.assert_not_called()  # Ensure fetch_resource was never called

def test_get_bitstreams_for_bundle(mocker):
    client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
    mock_bundle = Bundle({"uuid": "bundle-uuid"})
    mock_bundle.links = {"bitstreams": {"href": "http://localhost:8080/server/api/core/bundles/bundle-uuid/bitstreams"}}
    mock_bitstreams_data = {
        "_embedded": {
            "bitstreams": [
                {"uuid": "bitstream-uuid-1", "name": "Bitstream 1"},
                {"uuid": "bitstream-uuid-2", "name": "Bitstream 2"}
            ]
        }
    }
    mocker.patch.object(client, 'fetch_resource', return_value=mock_bitstreams_data)

    bitstreams = client.get_bitstreams(bundle=mock_bundle)
    
    assert len(bitstreams) == 2
    assert all(isinstance(bitstream, Bitstream) for bitstream in bitstreams)
    assert bitstreams[0].uuid == "bitstream-uuid-1"
    assert bitstreams[1].uuid == "bitstream-uuid-2"

@pytest.fixture
def mock_bundle():
    bundle = Bundle({"uuid": "bundle-uuid", "name": "ORIGINAL"})
    return bundle

def test_create_bitstream_success(mocker, mock_bundle, tmp_path):
    client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
    # Create a temporary file to simulate an actual file upload
    tmp_file = tmp_path / "testfile.txt"
    tmp_file.write_text("Test file content")
    
    mocker.patch.object(client.session, 'send', return_value=MagicMock(status_code=201, json=lambda: {"uuid": "bitstream-uuid"}))

    bitstream = client.create_bitstream(bundle=mock_bundle, name="testfile.txt", path=str(tmp_file), mime="text/plain")
    
    assert bitstream.uuid == "bitstream-uuid"

# def test_download_bitstream_success(mocker):
#     client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
#     mocker.patch.object(client, 'api_get', return_value=MagicMock(status_code=200, content=b"Bitstream content"))

#     response = client.download_bitstream(uuid="bitstream-uuid")
    
#     assert response.status_code == 200
#     assert response.content == b"Bitstream content"

def test_get_communities_top(mocker):
    client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
    mock_communities_data = {
        "_embedded": {
            "communities": [
                {"uuid": "community-uuid-1", "name": "Community 1"},
                {"uuid": "community-uuid-2", "name": "Community 2"}
            ]
        }
    }
    mocker.patch.object(client, 'fetch_resource', return_value=mock_communities_data)

    communities = client.get_communities(top=True)
    
    assert len(communities) == 2
    assert all(isinstance(community, Community) for community in communities)
    assert communities[0].uuid == "community-uuid-1"
    assert communities[1].uuid == "community-uuid-2"

def test_create_community_success(mocker):
    client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
    mocker.patch('dspace_rest_client.client.parse_json', return_value={"uuid": "community-uuid", "name": "New Community"})
    mocker.patch.object(client, 'create_dso', return_value=MagicMock(status_code=201, json=lambda: {"uuid": "community-uuid", "name": "New Community"}))

    community = client.create_community(parent="parent-uuid", data={"name": "New Community"})
    
    assert isinstance(community, Community)
    assert community.uuid == "community-uuid"
    assert community.name == "New Community"

def test_get_collections_for_community(mocker):
    client = DSpaceClient(api_endpoint='http://localhost:8080/server/api', username='admin', password='admin')
    mock_community = Community({"uuid": "community-uuid"})
    mock_community.links = {"collections": {"href": "http://localhost:8080/server/api/core/communities/community-uuid/collections"}}
    mock_collections_data = {
        "_embedded": {
            "collections": [
                {"uuid": "collection-uuid-1", "name": "Collection 1"},
                {"uuid": "collection-uuid-2", "name": "Collection 2"}
            ]
        }
    }
    mocker.patch.object(client, 'fetch_resource', return_value=mock_collections_data)

    collections = client.get_collections(community=mock_community)
    
    assert len(collections) == 2
    assert all(isinstance(collection, Collection) for collection in collections)
    assert collections[0].uuid == "collection-uuid-1"
    assert collections[1].uuid == "collection-uuid-2"

def test_create_collection_success(mocker):
    client = DSpaceClient(api_endpoint='http://example.com', username='admin', password='admin')
    data = {"name": "New Collection"}
    parent_uuid = "parent-community-uuid"
    response_data = {"uuid": "new-collection-uuid", "name": "New Collection"}
    
    mocker.patch('dspace_rest_client.client.parse_json', return_value=response_data)
    mocker.patch.object(client, 'create_dso', return_value=MagicMock(json=lambda: response_data))

    collection = client.create_collection(parent=parent_uuid, data=data)
    
    assert isinstance(collection, Collection)
    assert collection.uuid == "new-collection-uuid"
    assert collection.name == "New Collection"
    client.create_dso.assert_called_once_with(f"{client.API_ENDPOINT}/core/collections", {"parent": parent_uuid}, data)
        
@pytest.fixture
def mock_user_data():
    return User({"email": "test@example.com", "firstName": "Test", "lastName": "User"})

def test_create_user_with_user_object(mocker, mock_user_data):
    client = DSpaceClient(api_endpoint='http://example.com', username='admin', password='admin')
    response_data = {"email": "test@example.com", "firstName": "Test", "lastName": "User", "uuid": "user-uuid"}
    
    mocker.patch('dspace_rest_client.client.parse_json', return_value=response_data)
    mocker.patch.object(client, 'create_dso', return_value=MagicMock(json=lambda: response_data))

    new_user = client.create_user(user=mock_user_data)
    
    assert isinstance(new_user, User)
    assert new_user.email == "test@example.com"
    assert new_user.uuid == "user-uuid"
    client.create_dso.assert_called_once()

def test_create_user_with_dict(mocker):
    client = DSpaceClient(api_endpoint='http://example.com', username='admin', password='admin')
    user_dict = {"email": "test@example.com", "firstName": "Test", "lastName": "User"}
    response_data = {"email": "test@example.com", "firstName": "Test", "lastName": "User", "uuid": "user-uuid"}
    
    mocker.patch('dspace_rest_client.client.parse_json', return_value=response_data)
    mocker.patch.object(client, 'create_dso', return_value=MagicMock(json=lambda: response_data))

    new_user = client.create_user(user=user_dict)
    
    assert isinstance(new_user, User)
    assert new_user.email == "test@example.com"
    assert new_user.uuid == "user-uuid"
    client.create_dso.assert_called_once_with(f"{client.API_ENDPOINT}/eperson/epersons", params=None, data=user_dict)

def test_create_user_with_token(mocker):
    client = DSpaceClient(api_endpoint='http://example.com', username='admin', password='admin')
    user_dict = {"email": "test@example.com", "firstName": "Test", "lastName": "User"}
    token = "registration-token"
    response_data = {"email": "test@example.com", "firstName": "Test", "lastName": "User", "uuid": "user-uuid"}
    
    mocker.patch('dspace_rest_client.client.parse_json', return_value=response_data)
    mocker.patch.object(client, 'create_dso', return_value=MagicMock(json=lambda: response_data))

    new_user = client.create_user(user=user_dict, token=token)
    
    assert new_user.uuid == "user-uuid"
    client.create_dso.assert_called_once_with(f"{client.API_ENDPOINT}/eperson/epersons", params={"token": token}, data=user_dict)

def test_delete_user_success(mocker):
    client = DSpaceClient(api_endpoint='http://example.com', username='admin', password='admin')
    mock_user = User({"uuid": "user-uuid"})
    
    mocker.patch.object(client, 'delete_dso', return_value=True)

    result = client.delete_user(mock_user)
    
    assert result is True
    client.delete_dso.assert_called_once_with(mock_user)

def test_delete_user_invalid(mocker):
    client = DSpaceClient(api_endpoint='http://example.com', username='admin', password='admin')
    
    with mocker.patch('logging.error') as mock_log_error:
        result = client.delete_user(user="not a user object")
        
        assert result is None

def test_get_users_success(mocker):
    client = DSpaceClient(api_endpoint='http://example.com', username='admin', password='admin')
    api_response = {
        "_embedded": {
            "epersons": [
                {"uuid": "user-uuid-1", "email": "user1@example.com"},
                {"uuid": "user-uuid-2", "email": "user2@example.com"}
            ]
        }
    }
    mocker.patch.object(client, 'api_get', return_value=MagicMock(status_code=200, json=lambda: api_response))
    mocker.patch('dspace_rest_client.client.parse_json', return_value=api_response)

    users = client.get_users()
    
    assert len(users) == 2
    assert all(isinstance(user, User) for user in users)
    assert users[0].uuid == "user-uuid-1"
    assert users[1].uuid == "user-uuid-2"

@pytest.fixture
def mock_group():
    return Group({"name": "New Group"})

def test_create_group_with_group_object(mocker, mock_group):
    client = DSpaceClient(api_endpoint='http://example.com', username='admin', password='admin')
    response_data = {"name": "New Group", "uuid": "group-uuid"}
    
    mocker.patch('dspace_rest_client.client.parse_json', return_value=response_data)
    mocker.patch.object(client, 'create_dso', return_value=MagicMock(json=lambda: response_data))

    new_group = client.create_group(group=mock_group)
    
    assert isinstance(new_group, Group)
    assert new_group.name == "New Group"
    assert new_group.uuid == "group-uuid"

def test_update_token(mocker):
    client = DSpaceClient(api_endpoint='http://example.com', username='admin', password='admin')
    response = MagicMock(headers={"DSPACE-XSRF-TOKEN": "new-token"})
    
    with mocker.patch('logging.debug') as mock_log_debug:
        client.update_token(r=response)
        
        assert client.session.headers["X-XSRF-Token"] == "new-token"
        assert client.session.cookies.get("X-XSRF-Token") == "new-token"

def test_start_workflow(mocker):
    client = DSpaceClient(api_endpoint='http://example.com', username='admin', password='admin')
    workspace_item = "workspaceitem-uuid"
    response_data = {"message": "Workflow started"}  # Simulate expected response
    
    mocker.patch.object(client, 'api_post_uri', return_value=MagicMock(json=lambda: response_data))
    mocker.patch('dspace_rest_client.client.parse_json', return_value=response_data)

    # Assuming you want to do something with the response in the method eventually
    client.start_workflow(workspace_item=workspace_item)
    client.api_post_uri.assert_called_once_with(f"{client.API_ENDPOINT}/workflow/workflowitems", params=None, uri_list=workspace_item)

def test_get_short_lived_token_success(mocker):
    client = DSpaceClient(api_endpoint='http://example.com', username='admin', password='admin')
    response_data = {"token": "short-lived"}

    mock_response = MagicMock()
    mock_response.json.return_value = response_data
    mocker.patch.object(client, 'api_post', return_value=mock_response)

    token = client.get_short_lived_token()

    assert token == "short-lived"

def test_get_short_lived_token_failure(mocker):
    client = DSpaceClient(api_endpoint='http://example.com', username='admin', password='admin')
    mock_response = MagicMock()
    mock_response.status_code = 403
    mock_response.json.return_value = {"message": "Forbidden"}
    mocker.patch.object(client, 'api_post', return_value=mock_response)

    with mocker.patch('logging.error') as mock_log_error:
        token = client.get_short_lived_token()
        
        assert token is None

# def test_solr_query(mocker):
#     client = DSpaceClient(api_endpoint='http://example.com', username='admin', password='admin')
#     query = "dc.title:Test"
#     response_data = {
#         "response": {
#             "numFound": 1,
#             "docs": [
#                 {"id": "item-1", "dc.title": "Test Item"}
#             ]
#         }
#     }
    
#     mocker.patch.object(client, 'api_get', return_value=MagicMock(status_code=200, json=lambda: response_data))
#     mocker.patch('dspace_rest_client.client.parse_json', return_value=response_data)

#     results = client.solr_query(query=query)
    
#     assert len(results) == 1
#     assert results[0]["id"] == "item-1"
#     assert results[0]["dc.title"] == "Test Item"