# This software is licenced under the BSD 3-Clause licence
# available at https://opensource.org/licenses/BSD-3-Clause
# and described in the LICENSE.txt file in the root of this project

"""
DSpace REST API client library. Intended to make interacting with DSpace in Python 3 easier, particularly
when creating, updating, retrieving and deleting DSpace Objects.
This client library is a work in progress and currently only implements the most basic functionality.
It was originally created to assist with a migration of container structure, items and bistreams from a non-DSpace
system to a new DSpace 7 repository.

It needs a lot of expansion: resource policies and permissions, validation of prepared objects and responses,
better abstracting and handling of HAL-like API responses, plus just all the other endpoints and operations implemented.

@author Kim Shepherd <kim@shepherd.nz>
"""
import json
import logging
import pysolr
import os
import requests

from dotenv import load_dotenv
from urllib.parse import urlparse
from uuid import UUID

from .models import *

__all__ = ["DSpaceClient"]

logging.basicConfig(format="%(asctime)s - %(message)s", level=logging.INFO)


def parse_json(response):
    """
    Simple static method to handle ValueError if JSON is invalid in response body
    @param response: the http response object (which should contain JSON)
    @return: parsed JSON object
    """
    response_json = None
    try:
        if response is not None:
            response_json = response.json()
        else:
            logging.error("Empty response object")
            # return empty json object
            return {}
    except ValueError as err:
        logging.error(f"Error parsing response JSON: {err}. Body text: {response.text}")
    return response_json


class DSpaceClient:
    """
    Main class of the API client itself. This client uses request sessions to connect and authenticate to
    the REST API, maintain XSRF tokens, and all GET, POST, PUT, PATCH operations.
    Low-level api_get, api_post, api_put, api_delete, api_patch functions are defined to handle the requests and do
    retries / XSRF refreshes where necessary.
    Higher level get, create, update, partial_update (patch) functions are implemented for each DSO type.
    """

    # Load .env file if it exists
    if os.path.exists(".env"):
        load_dotenv()

    # Default values
    DEFAULT_API_ENDPOINT = "http://localhost:8080/server/api"
    DEFAULT_SOLR_ENDPOINT = "http://localhost:8983/solr"
    DEFAULT_USER_AGENT = "DSpace Python REST Client"
    verbose = False

    # Simple enum for patch operation types
    class PatchOperation:
        ADD = "add"
        REMOVE = "remove"
        REPLACE = "replace"
        MOVE = "move"

    def __init__(
        self,
        api_endpoint=None,
        username=None,
        password=None,
        solr_endpoint=None,
        solr_auth=None,
        fake_user_agent=False,
        unauthenticated=False,
    ):
        """
        Constructor with optional parameters, using environment variables as defaults.
        """
        # Environment or default for API endpoint
        self.API_ENDPOINT = api_endpoint or os.environ.get(
            "DSPACE_API_ENDPOINT", self.DEFAULT_API_ENDPOINT
        )
        self.LOGIN_URL = f"{self.API_ENDPOINT}/authn/login"

        if not unauthenticated:
            # Environment or explicit values for authentication
            self.USERNAME = username or os.environ.get("DSPACE_API_USERNAME")
            self.PASSWORD = password or os.environ.get("DSPACE_API_PASSWORD")

        # Environment or default for Solr endpoint
        self.SOLR_ENDPOINT = solr_endpoint or os.environ.get(
            "SOLR_ENDPOINT", self.DEFAULT_SOLR_ENDPOINT
        )
        self.SOLR_AUTH = solr_auth or os.environ.get("SOLR_AUTH")

        # User agent setup
        self.USER_AGENT = (
            os.environ.get("USER_AGENT", self.DEFAULT_USER_AGENT)
            if not fake_user_agent
            else "FakeUserAgent"
        )

        # Initialize the session
        self.session = requests.Session()

        # Initialize Solr client
        self.solr = pysolr.Solr(
            url=self.SOLR_ENDPOINT, always_commit=True, timeout=300, auth=self.SOLR_AUTH
        )

        # If fake_user_agent was specified, use this string that is known (as of 2023-12-03) to succeed with
        # requests to Cloudfront-protected API endpoints (tested on demo.dspace.org)
        # Otherwise, the user agent will be the more helpful and accurate default of 'DSpace Python REST Client'
        # To override the user agent to your own string, instead set the USER_AGENT environment variable first
        # eg `export USER_AGENT="My Custom Agent String / 1.0`, and don't specify a value for fake_user_agent
        if fake_user_agent:
            self.USER_AGENT = (
                "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/39.0.2171.95 Safari/537.36"
            )
        # Set headers based on this
        self.auth_request_headers = {"User-Agent": self.USER_AGENT}
        self.request_headers = {
            "Content-type": "application/json",
            "User-Agent": self.USER_AGENT,
        }
        self.list_request_headers = {
            "Content-type": "text/uri-list",
            "User-Agent": self.USER_AGENT,
        }

    def authenticate(self, retry=False):
        """
        Authenticate with the DSpace REST API. As with other operations, perform XSRF refreshes when necessary.
        After POST, check /authn/status and log success if the authenticated json property is true
        @return: response object
        """
        # Set headers for requests made during authentication
        # Get and update CSRF token
        r = self.session.post(
            self.LOGIN_URL,
            data={"user": self.USERNAME, "password": self.PASSWORD},
            headers=self.auth_request_headers,
        )
        self.update_token(r)

        if r.status_code == 403:
            # 403 Forbidden
            # If we had a CSRF failure, retry the request with the updated token
            # After speaking in #dev it seems that these do need occasional refreshes but I suspect
            # it's happening too often for me, so check for accidentally triggering it
            if retry:
                logging.error(
                    f"Too many retries updating token: {r.status_code}: {r.text}"
                )
                return False
            else:
                logging.debug("Retrying request with updated CSRF token")
                return self.authenticate(retry=True)

        if r.status_code == 401:
            # 401 Unauthorized
            # If we get a 401, this means a general authentication failure
            logging.error(
                f"Authentication failure: invalid credentials for user {self.USERNAME}"
            )
            return False

        # Update headers with new bearer token if present
        if "Authorization" in r.headers:
            self.session.headers.update(
                {"Authorization": r.headers.get("Authorization")}
            )

        # Get and check authentication status
        r = self.session.get(
            f"{self.API_ENDPOINT}/authn/status", headers=self.request_headers
        )
        if r.status_code == 200:
            r_json = parse_json(r)
            if "authenticated" in r_json and r_json["authenticated"] is True:
                logging.info(f"Authenticated successfully as {self.USERNAME}")
                return r_json["authenticated"]

        # Default, return false
        return False

    def refresh_token(self):
        """
        If the DSPACE-XSRF-TOKEN appears, we need to update our local stored token and re-send our API request
        @return: None
        """
        r = self.api_post(self.LOGIN_URL, None, None)
        self.update_token(r)

    def get_authn_status(self):
        """
        Get the current authentication status
        @return: response object
        """
        return self.session.get(
            f"{self.API_ENDPOINT}/authn/status", headers=self.request_headers
        )

    def logout(self):
        """
        Logout from the DSpace REST API
        @return: response object
        """
        logout = self.session.post(
            f"{self.API_ENDPOINT}/authn/logout", headers=self.request_headers
        )
        if logout.status_code == 204:
            logging.info(f"User {self.USERNAME} logged out successfully")
            return True

    def api_get(self, url, params=None, data=None, headers=None):
        """
        Perform a GET request. Refresh XSRF token if necessary.
        @param url:     DSpace REST API URL
        @param params:  any parameters to include (eg ?page=0)
        @param data:    any data to supply (typically not relevant for GET)
        @param headers: any override headers (eg. with short-lived token for download)
        @return:        Response from API
        """
        if headers is None:
            headers = self.request_headers
        r = self.session.get(url, params=params, data=data, headers=headers)
        self.update_token(r)
        return r

    def api_post(self, url, params, json, retry=False):
        """
        Perform a POST request. Refresh XSRF token if necessary.
        POSTs are typically used to create objects.
        @param url:     DSpace REST API URL
        @param params:  Any parameters to include (eg ?parent=abbc-....)
        @param json:    Data in json-ready form (dict) to send as POST body (eg. item.as_dict())
        @param retry:   Has this method already been retried? Used if we need to refresh XSRF.
        @return:        Response from API
        """
        r = self.session.post(
            url, json=json, params=params, headers=self.request_headers
        )
        self.update_token(r)

        if r.status_code == 403:
            # 403 Forbidden
            # If we had a CSRF failure, retry the request with the updated token
            # After speaking in #dev it seems that these do need occasional refreshes but I suspect
            # it's happening too often for me, so check for accidentally triggering it
            r_json = parse_json(r)
            if "message" in r_json and "CSRF token" in r_json["message"]:
                if retry:
                    logging.warning(
                        f"Too many retries updating token: {r.status_code}: {r.text}"
                    )
                else:
                    logging.debug("Retrying request with updated CSRF token")
                    return self.api_post(url, params=params, json=json, retry=True)

        return r

    def api_post_uri(self, url, params, uri_list, retry=False):
        """
        Perform a POST request. Refresh XSRF token if necessary.
        POSTs are typically used to create objects.
        @param url:     DSpace REST API URL
        @param params:  Any parameters to include (eg ?parent=abbc-....)
        @param uri_list: One or more URIs referencing objects
        @param retry:   Has this method already been retried? Used if we need to refresh XSRF.
        @return:        Response from API
        """
        r = self.session.post(
            url, data=uri_list, params=params, headers=self.list_request_headers
        )
        self.update_token(r)

        if r.status_code == 403:
            # 403 Forbidden
            # If we had a CSRF failure, retry the request with the updated token
            # After speaking in #dev it seems that these do need occasional refreshes but I suspect
            # it's happening too often for me, so check for accidentally triggering it
            r_json = r.json()
            if "message" in r_json and "CSRF token" in r_json["message"]:
                if retry:
                    logging.warning(
                        f"Too many retries updating token: {r.status_code}: {r.text}"
                    )
                else:
                    logging.debug("Retrying request with updated CSRF token")
                    return self.api_post_uri(
                        url, params=params, uri_list=uri_list, retry=True
                    )

        return r

    def api_put(self, url, params, json, retry=False):
        """
        Perform a PUT request. Refresh XSRF token if necessary.
        PUTs are typically used to update objects.
        @param url:     DSpace REST API URL
        @param params:  Any parameters to include (eg ?parent=abbc-....)
        @param json:    Data in json-ready form (dict) to send as PUT body (eg. item.as_dict())
        @param retry:   Has this method already been retried? Used if we need to refresh XSRF.
        @return:        Response from API
        """
        r = self.session.put(
            url, params=params, json=json, headers=self.request_headers
        )
        self.update_token(r)

        if r.status_code == 403:
            # 403 Forbidden
            # If we had a CSRF failure, retry the request with the updated token
            # After speaking in #dev it seems that these do need occasional refreshes but I suspect
            # it's happening too often for me, so check for accidentally triggering it
            logging.debug(r.text)
            # Parse response
            r_json = parse_json(r)
            if "message" in r_json and "CSRF token" in r_json["message"]:
                if retry:
                    logging.warning(
                        f"Too many retries updating token: {r.status_code}: {r.text}"
                    )
                else:
                    logging.debug("Retrying request with updated CSRF token")
                    return self.api_put(url, params=params, json=json, retry=True)

        return r

    def api_delete(self, url, params, retry=False):
        """
        Perform a DELETE request. Refresh XSRF token if necessary.
        DELETES are typically used to update objects.
        @param url:     DSpace REST API URL
        @param params:  Any parameters to include (eg ?parent=abbc-....)
        @param retry:   Has this method already been retried? Used if we need to refresh XSRF.
        @return:        Response from API
        """
        r = self.session.delete(url, params=params, headers=self.request_headers)
        self.update_token(r)

        if r.status_code == 403:
            # 403 Forbidden
            # If we had a CSRF failure, retry the request with the updated token
            # After speaking in #dev it seems that these do need occasional refreshes but I suspect
            # it's happening too often for me, so check for accidentally triggering it
            logging.debug(r.text)
            # Parse response
            r_json = parse_json(r)
            if "message" in r_json and "CSRF token" in r_json["message"]:
                if retry:
                    logging.warning(
                        f"Too many retries updating token: {r.status_code}: {r.text}"
                    )
                else:
                    logging.debug("Retrying request with updated CSRF token")
                    return self.api_delete(url, params=params, retry=True)

        return r

    def api_patch(self, url, operation, path, value, retry=False):
        """
        @param url: DSpace REST API URL
        @param operation: 'add', 'remove', 'replace', or 'move' (see PatchOperation enumeration)
        @param path: path to perform operation - eg, metadata, withdrawn, etc.
        @param value: new value for add or replace operations, or 'original' path for move operations
        @param retry:   Has this method already been retried? Used if we need to refresh XSRF.
        @return:
        @see https://github.com/DSpace/RestContract/blob/main/metadata-patch.md
        """
        if url is None:
            logging.error("Missing required URL argument")
            return None
        if path is None:
            logging.error(
                "Need valid path eg. /withdrawn or /metadata/dc.title/0/language"
            )
            return None
        if (
            operation == self.PatchOperation.ADD
            or operation == self.PatchOperation.REPLACE
            or operation == self.PatchOperation.MOVE
        ) and value is None:
            # missing value required for add/replace/move operations
            logging.error(
                'Missing required "value" argument for add/replace/move operations'
            )
            return None

        # compile patch data
        data = {"op": operation, "path": path}
        if value is not None:
            if operation == self.PatchOperation.MOVE:
                data["from"] = value
            else:
                data["value"] = value

        # set headers
        # perform patch request
        r = self.session.patch(url, json=[data], headers=self.request_headers)
        self.update_token(r)

        if r.status_code == 403:
            # 403 Forbidden
            # If we had a CSRF failure, retry the request with the updated token
            # After speaking in #dev it seems that these do need occasional refreshes but I suspect
            # it's happening too often for me, so check for accidentally triggering it
            logging.debug(r.text)
            r_json = parse_json(r)
            if "message" in r_json and "CSRF token" in r_json["message"]:
                if retry:
                    logging.warning(
                        f"Too many retries updating token: {r.status_code}: {r.text}"
                    )
                else:
                    logging.debug("Retrying request with updated CSRF token")
                    return self.api_patch(url, operation, path, value, True)
        elif r.status_code == 200:
            # 200 Success
            logging.info(
                f'successful patch update to {r.json()["type"]} {r.json()["id"]}'
            )

        # Return the raw API response
        return r

    # PAGINATION
    def search_objects(
        self,
        query=None,
        scope=None,
        filters=None,
        page=0,
        size=20,
        sort=None,
        dso_type=None,
        configuration=None,
    ):
        """
        Do a basic search with optional query, filters and dsoType params.
        @param query:   query string
        @param scope:   uuid to limit search scope, eg. owning collection, parent community, etc.
        @param filters: discovery filters as dict eg. {'f.entityType': 'Publication,equals', ... }
        @param page: page number (not like 'start' as this is not row number, but page number of size {size})
        @param size: size of page (aka. 'rows'), affects the page parameter above
        @param sort: sort eg. 'title,asc'
        @param dso_type: DSO type to further filter results
        @param configuration: configuration to use for search
        @return:        list of DspaceObject objects constructed from API resources
        """
        dsos = []
        if filters is None:
            filters = {}
        url = f"{self.API_ENDPOINT}/discover/search/objects"
        # we will add params to filters, so
        params = {}
        if query is not None:
            params["query"] = query
        if scope is not None:
            params["scope"] = scope
        if dso_type is not None:
            params["dsoType"] = dso_type
        if size is not None:
            params["size"] = size
        if page is not None:
            params["page"] = page
        if sort is not None:
            params["sort"] = sort
        if configuration is not None:
            params["configuration"] = configuration

        r_json = self.fetch_resource(url=url, params={**params, **filters})

        # instead lots of 'does this key exist, etc etc' checks, just go for it and wrap in a try?
        try:
            results = r_json["_embedded"]["searchResult"]["_embedded"]["objects"]
            for result in results:
                resource = result["_embedded"]["indexableObject"]
                dso = DSpaceObject(resource)
                dsos.append(dso)
        except (TypeError, ValueError) as err:
            logging.error(f"error parsing search result json {err}")

        return dsos

    def search_objects_admin(self, uri=None, embed=None, feature=None):
        """
        Do a basic search with uri, and optional embed and feature params. Focus: authorizations.
        Adapted from Angular UI search service
        @param uri: URI to search
        @param embed: embeds to include in search
        @param feature: feature to search
        @return:        list of DspaceObject objects constructed from API resources
        """
        dsos = []
        url = f"{self.API_ENDPOINT}/authz/authorizations/search/object"
        params = {}

        if uri is None:
            logging.error("Missing required URI argument")
            return dsos
        else:
            params["uri"] = uri
        if embed is not None:
            params["embed"] = embed
        if feature is not None:
            params["feature"] = feature

        r_json = self.fetch_resource(url=url, params=params)

        # instead lots of 'does this key exist, etc etc' checks, just go for it and wrap in a try?
        try:
            results = r_json["_embedded"]["authorizations"]
            for result in results:
                dsos.append(result)
        except (TypeError, ValueError) as err:
            logging.error(f"error parsing search result json {err}")

        return dsos

    def search_object_detail(
        self,
        query=None,
        scope=None,
        filters=None,
        page=0,
        size=20,
        sort=None,
        dso_type=None,
        configuration=None,
    ):
        """
        Do a basic search with optional query, filters and dsoType params.
        @param query:   query string
        @param scope:   uuid to limit search scope, eg. owning collection, parent community, etc.
        @param filters: discovery filters as dict eg. {'f.entityType': 'Publication,equals', ... }
        @param page: page number (not like 'start' as this is not row number, but page number of size {size})
        @param size: size of page (aka. 'rows'), affects the page parameter above
        @param sort: sort eg. 'title,asc'
        @param dso_type: DSO type to further filter results
        @param configuration: configuration to use for search
        @return:        list of DspaceObject objects constructed from API resources, pages_data, facets
        """
        dsos = []
        if filters is None:
            filters = {}
        url = f"{self.API_ENDPOINT}/discover/search/objects"
        # we will add params to filters, so
        params = {}
        if query is not None:
            params["query"] = query
        if scope is not None:
            params["scope"] = scope
        if dso_type is not None:
            params["dsoType"] = dso_type
        if size is not None:
            params["size"] = size
        if page is not None:
            params["page"] = page
        if sort is not None:
            params["sort"] = sort
        if configuration is not None:
            params["configuration"] = configuration

        r_json = self.fetch_resource(url=url, params={**params, **filters})

        # instead lots of 'does this key exist, etc etc' checks, just go for it and wrap in a try?
        try:
            results = r_json["_embedded"]["searchResult"]["_embedded"]["objects"]
            for result in results:
                resource = result["_embedded"]["indexableObject"]
                dso = DSpaceObject(resource)
                dsos.append(dso)
        except (TypeError, ValueError) as err:
            logging.error(f"error parsing search result json {err}")

        return (
            dsos,
            r_json["_embedded"]["searchResult"]["page"],
            r_json["_embedded"]["facets"],
        )

    def fetch_resource(self, url, params=None):
        """
        Simple function for higher-level 'get' functions to use whenever they want
        to retrieve JSON resources from the API
        @param url:     DSpace REST API URL
        @param params:  Optional params
        @return:        JSON parsed from API response or None if error
        """
        r = self.api_get(url, params, None)
        print(url)
        # construct url with params for logging
        if params is not None:
            url = f"{url}?{params}"
        logging.info(f"Fetching resource from {url}")
        print(r.json())
        if r.status_code != 200:
            logging.error(f"Error encountered fetching resource: {r.text}")
            return None
        # ValueError / JSON handling moved to static method
        return parse_json(r)

    def get_dso(self, url, uuid):
        """
        Base 'get DSpace Object' function.
        Uses fetch_resource which itself calls parse_json on the raw response before returning.
        @param url:     DSpace REST API URL
        @param uuid:    UUID of object to retrieve
        @return:        Parsed JSON response from fetch_resource
        """
        try:
            # Try to get UUID version to test validity
            id = UUID(uuid).version
            url = f"{url}/{uuid}"
            return self.api_get(url, None, None)
        except ValueError:
            logging.error(f"Invalid DSO UUID: {uuid}")
            return None

    def create_dso(self, url, params, data):
        """
        Base 'create DSpace Object' function.
        Takes JSON data and some POST parameters and returns the response.
        @param url:     DSpace REST API URL
        @param params:  Any parameters to pass in the request, eg. parentCollection for a new item
        @param data:    JSON data expected by the REST API to create the new resource
        @return:        Raw API response. New DSO *could* be returned but for error checking purposes, raw response
                        is nice too and can always be parsed from this response later.
        """
        r = self.api_post(url, params, data)
        if r.status_code == 201:
            # 201 Created - success!
            new_dso = parse_json(r)
            logging.info(f'{new_dso["type"]} {new_dso["uuid"]} created successfully!')
        else:
            logging.error(f"create operation failed: {r.status_code}: {r.text} ({url})")
        return r

    def update_dso(self, dso, params=None):
        """
        Update DSpaceObject. Takes a DSpaceObject and any optional parameters. Will send a PUT update to the remote
        object and return the updated object, typed correctly.
        :param dso:     DSpaceObject with locally updated data, to send in PUT request
        :param params:  Optional parameters
        :return:

        """
        if dso is None:
            return None
        dso_type = type(dso)
        if not isinstance(dso, SimpleDSpaceObject):
            logging.error(
                "Only SimpleDSpaceObject types (eg Item, Collection, Community) "
                "are supported by generic update_dso PUT."
            )
            return dso
        try:
            # Get self URI from HAL links
            url = dso.links["self"]["href"]
            # Get and clean data - there are some unalterable fields that could cause errors
            data = dso.as_dict()

            if "lastModified" in data:
                data.pop("lastModified")
            """
            if 'id' in data:
                data.pop('id')
            if 'handle' in data:
                data.pop('handle')
            if 'uuid' in data:
                data.pop('uuid')
            if 'type' in data:
                data.pop('type')
            """
            r = self.api_put(url, params=params, json=data)
            if r.status_code == 200:
                # 200 OK - success!
                updated_dso = dso_type(parse_json(r))
                logging.info(
                    f"{updated_dso.type} {updated_dso.uuid} updated sucessfully!"
                )
                return updated_dso
            else:
                logging.error(
                    f"update operation failed: {r.status_code}: {r.text} ({url})"
                )
                return None

        except ValueError as e:
            logging.error("Error parsing DSO response", exc_info=True)
            return None

    def delete_dso(self, dso=None, url=None, params=None):
        """
        Delete DSpaceObject. Takes a DSpaceObject and any optional parameters. Will send a PUT update to the remote
        object and return the updated object, typed correctly.
        :param dso:     DSpaceObject from which to parse self link
        :param params:  Optional parameters
        :param url:     URI if not deleting from DSO
        :return:

        """
        if dso is None:
            if url is None:
                logging.error("Need a DSO or a URL to delete")
                return None
        else:
            if not isinstance(dso, SimpleDSpaceObject):
                logging.error(
                    "Only SimpleDSpaceObject types (eg Item, Collection, Community, EPerson) "
                    "are supported by generic update_dso PUT."
                )
                return dso
            # Get self URI from HAL links
            url = dso.links["self"]["href"]

        try:
            r = self.api_delete(url, params=params)
            if r.status_code == 204:
                # 204 No Content - success!
                logging.info(f"{url} was deleted sucessfully!")
                return r
            else:
                logging.error(
                    f"update operation failed: {r.status_code}: {r.text} ({url})"
                )
                return None
        except ValueError as e:
            logging.error(f"Error deleting DSO {dso.uuid}: {e}")
            return None

    # PAGINATION
    def get_bundles(self, parent=None, uuid=None, page=0, size=20, sort=None):
        """
        Get bundles for an item
        @param parent:  python Item object, from which the UUID will be referenced in the URL.
                        This is mutually exclusive to the 'uuid' argument, returning all bundles for the item.
        @param uuid:    Bundle UUID. This is mutually exclusive to the 'parent' argument, returning just this bundle
        @return:        List of bundles (single UUID bundle result is wrapped in a list before returning)
        """
        # TODO: It is probably wise to allow the parent UUID to be simply passed as an alternative to having the full
        #  python object as constructed by this REST client, for more flexible usage.
        bundles = []
        single_result = False
        if uuid is not None:
            url = f"{self.API_ENDPOINT}/core/bundles/{uuid}"
            single_result = True
        elif parent is not None:
            url = f"{self.API_ENDPOINT}/core/items/{parent.uuid}/bundles"
        else:
            return []
        params = {}
        if size is not None:
            params["size"] = size
        if page is not None:
            params["page"] = page
        if sort is not None:
            params["sort"] = sort
        r_json = self.fetch_resource(url, params=params)
        try:
            if single_result:
                bundles.append(Bundle(r_json))
            if not single_result:
                resources = r_json["_embedded"]["bundles"]
                for resource in resources:
                    bundles.append(Bundle(resource))
        except ValueError as err:
            logging.error(f"error parsing bundle results: {err}")

        return bundles

    def create_bundle(self, parent=None, name="ORIGINAL"):
        """
        Create new bundle in the specified item
        @param parent:  Parent python Item, the UUID of which will be used in the URL path
        @param name:    Name of the bundle. Default: ORIGINAL
        @return:        constructed python Bundle object from the response JSON
                        (note: this is a bit inconsistent with create_dso usage where the raw response is returned)
        """
        # TODO: It is probably wise to allow the parent UUID to be simply passed as an alternative to having the full
        #  python object as constructed by this REST client, for more flexible usage.
        try:
            if parent is None:
                return None
            url = f"{self.API_ENDPOINT}/core/items/{parent.uuid}/bundles"
            return Bundle(
                api_resource=parse_json(
                    self.api_post(url, params=None, json={"name": name, "metadata": {}})
                )
            )
        except ValueError as err:
            logging.error(f"error creating bundle: {err}")
            return None

    # PAGINATION
    def get_bitstreams(self, uuid=None, bundle=None, page=0, size=20, sort=None):
        """
        Get a specific bitstream UUID, or all bitstreams for a specific bundle
        @param uuid:    UUID of a specific bitstream to retrieve
        @param bundle:  A python Bundle object to parse for bitstream links to retrieve
        @param page:    Page number, for pagination over large result sets (default: 0)
        @param size:    Size of results per page (default: 20)
        @return:        list of python Bitstream objects
        """
        url = f"{self.API_ENDPOINT}/core/bitstreams/{uuid}"
        if uuid is None and bundle is None:
            return []
        if uuid is None and isinstance(bundle, Bundle):
            if "bitstreams" in bundle.links:
                url = bundle.links["bitstreams"]["href"]
            else:
                url = f"{self.API_ENDPOINT}/core/bundles/{bundle.uuid}/bitstreams"
                logging.warning(
                    f"Cannot find bundle bitstream links, will try to construct manually: {url}"
                )
        # Perform the actual request. By now, our URL and parameter should be properly set
        params = {}
        if size is not None:
            params["size"] = size
        if page is not None:
            params["page"] = page
        if sort is not None:
            params["sort"] = sort
        r_json = self.fetch_resource(url, params=params)
        if "_embedded" in r_json:
            if "bitstreams" in r_json["_embedded"]:
                bitstreams = []
                for bitstream_resource in r_json["_embedded"]["bitstreams"]:
                    bitstreams.append(Bitstream(bitstream_resource))
                return bitstreams

    def create_bitstream(
        self, bundle=None, name=None, path=None, mime=None, metadata=None, retry=False
    ):
        """
        Upload a file and create a bitstream for a specified parent bundle, from the uploaded file and
        the supplied metadata.
        This create method is a bit different to the others, it does not use create_dso or the api_post lower level
        methods, instead it has to use a prepared session POST request which will allow the multi-part upload to work
        successfully with the correct byte size and persist the session data.
        This is also why it directly implements the 'retry' functionality instead of relying on api_post.
        @param bundle:      python Bundle object
        @param name:        Bitstream name
        @param path:        Local filesystem path to the file that will be uploaded
        @param mime:        MIME string of the uploaded file
        @param metadata:    Full metadata JSON
        @param retry:       A 'retried' indicator. If the first attempt fails due to an expired or missing auth
                            token, the request will retry once, after the token is refreshed. (default: False)
        @return:            constructed Bitstream object from the API response, or None if the operation failed.
        """
        if bundle is None or name is None or path is None or mime is None:
            logging.error("Missing required parameters for create_bitstream")
            return None
        if metadata is None:
            metadata = {}
        url = f"{self.API_ENDPOINT}/core/bundles/{bundle.uuid}/bitstreams"

        with open(path, "rb") as file_obj:
            file = (name, file_obj, mime)
            files = {"file": file}
            properties = {"name": name, "metadata": metadata, "bundleName": bundle.name}
            payload = {"properties": json.dumps(properties) + ";application/json"}
            h = self.session.headers
            h.update({"Content-Encoding": "gzip", "User-Agent": self.USER_AGENT})
            req = requests.Request("POST", url, data=payload, headers=h, files=files)
            prepared_req = self.session.prepare_request(req)
            r = self.session.send(prepared_req)

        if "DSPACE-XSRF-TOKEN" in r.headers:
            t = r.headers["DSPACE-XSRF-TOKEN"]
            logging.debug("Updating token to " + t)
            self.session.headers.update({"X-XSRF-Token": t})
            self.session.cookies.update({"X-XSRF-Token": t})
        if r.status_code == 403:
            r_json = parse_json(r)
            if "message" in r_json and "CSRF token" in r_json["message"]:
                if retry:
                    logging.error("Already retried... something must be wrong")
                else:
                    logging.debug("Retrying request with updated CSRF token")
                    return self.create_bitstream(
                        bundle, name, path, mime, metadata, True
                    )

        if r.status_code == 201 or r.status_code == 200:
            # Success
            return Bitstream(api_resource=parse_json(r))
        else:
            logging.error(f"Error creating bitstream: {r.status_code}: {r.text}")
            return None

    def download_bitstream(self, uuid=None):
        """
        Download bitstream and return full response object including headers, and content
        @param uuid:
        @return: full response object including headers, and content
        """
        url = f"{self.API_ENDPOINT}/core/bitstreams/{uuid}/content"
        h = {
            "User-Agent": self.USER_AGENT,
            "Authorization": self.get_short_lived_token(),
        }
        r = self.api_get(url, headers=h)
        if r.status_code == 200:
            return r

    # PAGINATION
    def get_communities(self, uuid=None, page=0, size=20, sort=None, top=False):
        """
        Get communities - either all, for single UUID, or all top-level (ie no sub-communities)
        @param uuid:    string UUID if getting single community
        @param page:    integer page (default: 0)
        @param size:    integer size (default: 20)
        @param top:     whether to restrict search to top communities (default: false)
        @return:        list of communities, or None if error
        """
        url = f"{self.API_ENDPOINT}/core/communities"
        params = {}
        if size is not None:
            params["size"] = size
        if page is not None:
            params["page"] = page
        if sort is not None:
            params["sort"] = sort
        if uuid is not None:
            try:
                # This isn't used, but it'll throw a ValueError if not a valid UUID
                id = UUID(uuid).version
                # Set URL and parameters
                url = f"{url}/{uuid}"
                params = None
            except ValueError:
                logging.error(f"Invalid community UUID: {uuid}")
                return None

        if top:
            # Set new URL
            url = f"{url}/search/top"

        logging.debug(f"Performing get on {url}")
        # Perform actual get
        r_json = self.fetch_resource(url, params)
        # Empty list
        communities = []
        if "_embedded" in r_json:
            if "communities" in r_json["_embedded"]:
                for community_resource in r_json["_embedded"]["communities"]:
                    communities.append(Community(community_resource))
        elif "uuid" in r_json:
            # This is a single communities
            communities.append(Community(r_json))
        # Return list (populated or empty)
        return communities

    def get_parent_community(self, uuid=None):
        """
        Get the parent community of a given community
        @param community: Community object
        @return: Parent Community object
        """
        if uuid is None:
            return None
        url = f"{self.API_ENDPOINT}/core/communities/{uuid}/parentCommunity"
        r_json = self.api_get(url)
        if r_json.status_code == 200:
            return Community(api_resource=parse_json(r_json))
        else:
            return None

    def get_sub_communities(self, uuid=None, page=0, size=20, sort=None):
        """
        Get sub-communities for a given community
        @param community: Community object
        @param page:    integer page (default: 0)
        @param size:    integer size (default: 20)
        @param sort:    sort string (default: None)
        @return:        list of Community objects, or None if error
        """
        if uuid is None:
            return None
        url = f"{self.API_ENDPOINT}/core/communities/{uuid}/subcommunities"
        params = {}
        if size is not None:
            params["size"] = size
        if page is not None:
            params["page"] = page
        if sort is not None:
            params["sort"] = sort
        r_json = self.fetch_resource(url, params)
        if "_embedded" in r_json:
            if "subcommunities" in r_json["_embedded"]:
                sub_communities = []
                for community_resource in r_json["_embedded"]["subcommunities"]:
                    sub_communities.append(community_resource)
                return sub_communities
        return None

    def create_community(self, parent, data):
        """
        Create a community, either top-level or beneath a given parent
        @param parent:  (optional) parent UUID to pass as a parameter to create_dso
        @param data:    Full JSON data for the new community
        @return:        python Community object constructed from the API response
        """
        # TODO: To be consistent with other create methods, this should probably also allow a Community object
        #  to be passed instead of just the UUID as a string
        url = f"{self.API_ENDPOINT}/core/communities"
        params = None
        if parent is not None:
            params = {"parent": parent}
        return Community(api_resource=parse_json(self.create_dso(url, params, data)))

    def get_collections(self, uuid=None, community=None, page=0, size=20, sort=None):
        """
        Get collections - all, or single UUID, or for a specific community
        @param uuid:        UUID string. If present, just a single collection is returned (overrides community arg)
        @param community:   Community object. If present (and no uuid present), collections for a community
        @param page:        Integer for page / offset of results. Default: 0
        @param size:        Integer for page size. Default: 20 (same as REST API default)
        @return:            list of Collection objects, or None if there was an error
                            for consistency of handling results, even the uuid search will be a list of one
        """
        url = f"{self.API_ENDPOINT}/core/collections"
        params = {}
        if size is not None:
            params["size"] = size
        if page is not None:
            params["page"] = page
        if sort is not None:
            params["sort"] = sort
        # First, handle case of UUID. It overrides the other arguments as it is a request for a single collection
        if uuid is not None:
            try:
                id = UUID(uuid).version
                # Update URL and parameters
                url = f"{url}/{uuid}"
                params = None
            except ValueError:
                logging.error(f"Invalid collection UUID: {uuid}")
                return None

        if community is not None:
            if (
                "collections" in community.links
                and "href" in community.links["collections"]
            ):
                # Update URL
                url = community.links["collections"]["href"]

        # Perform the actual request. By now, our URL and parameter should be properly set
        r_json = self.fetch_resource(url, params=params)
        # Empty list
        collections = []
        if "_embedded" in r_json:
            # This is a list of collections
            if "collections" in r_json["_embedded"]:
                for collection_resource in r_json["_embedded"]["collections"]:
                    collections.append(Collection(collection_resource))
        elif "uuid" in r_json:
            # This is a single collection
            collections.append(Collection(r_json))

        # Return list (populated or empty)
        return collections

    def create_collection(self, parent, data):
        """
        Create collection beneath a given parent community.
        @param parent:  UUID of parent community to pass as a parameter to create_dso
        @param data:    Full JSON data for the new collection
        @return:        python Collection object constructed from the API response
        """
        # TODO: To be consistent with other create methods, this should probably also allow a Community object
        #  to be passed instead of just the UUID as a string
        url = f"{self.API_ENDPOINT}/core/collections"
        params = None
        if parent is not None:
            params = {"parent": parent}
        return Collection(api_resource=parse_json(self.create_dso(url, params, data)))

    def get_collection_parent_community(self, uuid=None):
        """
        Get the parent community of a given collection
        @param collection: Collection object
        @return: Parent Community object
        """
        if uuid is None:
            return None
        url = f"{self.API_ENDPOINT}/core/collections/{uuid}/parentCommunity"
        r_json = self.api_get(url)
        if r_json.status_code == 200:
            return Community(api_resource=parse_json(r_json))
        else:
            return None

    def get_item(self, uuid):
        """
        Get an item, given its UUID
        @param uuid:    the UUID of the item
        @return:        the raw API response
        """
        # TODO - return constructed Item object instead, handling errors here?
        url = f"{self.API_ENDPOINT}/core/items"
        try:
            id = UUID(uuid).version
            url = f"{url}/{uuid}"
            return self.api_get(url, None, None)
        except ValueError:
            logging.error(f"Invalid item UUID: {uuid}")
            return None

    def get_item_metrics(self, uuid):
        """
        Get metrics for an item, given its UUID
        @param uuid:    the UUID of the item
        @return:        the raw API response
        """
        url = f"{self.API_ENDPOINT}/core/items"
        try:
            id = UUID(uuid).version
            url = f"{url}/{uuid}/metrics"
            return self.api_get(url, None, None)
        except ValueError:
            logging.error(f"Invalid item UUID: {uuid}")
            return None

    def get_item_thumbnail(self, uuid):
        """
        Get thumbnail for an item, given its UUID
        @param uuid:    the UUID of the item
        @return:        the raw API response
        """
        url = f"{self.API_ENDPOINT}/core/items"
        try:
            url = f"{url}/{uuid}/thumbnail"
            if self.api_get(url, None, None).status_code == 200:
                return self.api_get(url, None, None)
            elif self.api_get(url, None, None).status_code == 204:
                return "No thumbnail available for this item"
            else:
                return None
        except ValueError:
            logging.error(f"Invalid item UUID: {uuid}")
            return None

    def get_item_owning_collection(self, uuid):
        """
        Get the owning collection of a given item
        @param item: Item object
        @return: Owning Collection object
        """
        if uuid is None:
            return None
        url = f"{self.API_ENDPOINT}/core/items/{uuid}/owningCollection"
        r_json = self.api_get(url)
        if r_json.status_code == 200:
            return Collection(api_resource=parse_json(r_json))
        else:
            return None

    def update_item_owning_collection(
        self, item_uuid, collection_uuid, inherit_policies=False
    ):
        """
        Update the owning collection of a given item.
        :param item_uuid: UUID of the item to be moved
        :param collection_uuid: UUID of the target collection
        :param inherit_policies: Boolean flag to inherit policies from the target collection
        :return: True if successful, False otherwise
        """
        if item_uuid is None or collection_uuid is None:
            logging.error("Item UUID or Collection UUID is missing.")
            return False

        # Construct the URL
        url = f"{self.API_ENDPOINT}/core/items/{item_uuid}/owningCollection"

        # Construct the request body
        data = f"{self.API_ENDPOINT}/core/collections/{collection_uuid}"

        # Construct the parameters
        params = {"inheritPolicies": str(inherit_policies).lower()}

        # Perform the PUT request using the custom method
        headers = self.request_headers.copy()
        headers["Content-Type"] = "text/uri-list"

        r = self.session.put(url, data=data, params=params, headers=headers)
        self.update_token(r)

        if r.status_code == 204:
            logging.info(
                f"Item {item_uuid} successfully moved to Collection {collection_uuid}."
            )
            return True
        elif r.status_code == 403 and "CSRF token" in r.text:
            logging.warning(
                "CSRF token issue encountered, retrying with updated token."
            )
            return self.update_item_owning_collection(
                item_uuid, collection_uuid, inherit_policies
            )
        else:
            logging.error(
                f"Failed to update owning collection: {r.status_code}: {r.text} ({url})"
            )
            return False

    def get_item_mapped_collections(self, uuid):
        """
        Get the mapped collections of a given item
        @param item: Item object
        @return: Mapped Collection object
        """
        if uuid is None:
            return None
        url = f"{self.API_ENDPOINT}/core/items/{uuid}/mappedCollections"
        r_json = self.api_get(url)
        if r_json.status_code == 200:
            return parse_json(r_json)
        else:
            return None

    def get_item_relationships(self, uuid):
        """
        Get the relationships of a given item
        @param item: Item object
        @return: Relationships object
        """
        if uuid is None:
            return None
        url = f"{self.API_ENDPOINT}/core/items/{uuid}/relationships"
        r_json = self.api_get(url)
        if r_json.status_code == 200:
            return parse_json(r_json)
        else:
            return None

    def get_items(self):
        """
        Get all archived items for a logged-in administrator. Admin only! Usually you will want to
        use search or browse methods instead of this method
        @return: A list of items, or an error
        """
        url = f"{self.API_ENDPOINT}/core/items"
        # Empty item list
        items = []
        # Perform the actual request
        r_json = self.fetch_resource(url)
        # Empty list
        items = []
        if "_embedded" in r_json:
            # This is a list of items
            if "items" in r_json["_embedded"]:
                for item_resource in r_json["_embedded"]["items"]:
                    items.append(Item(item_resource))
        elif "uuid" in r_json:
            # This is a single item
            items.append(Item(r_json))

        # Return list (populated or empty)
        return items

    def create_item(self, parent, item):
        """
        Create an item beneath the given parent collection
        @param parent:  UUID of parent collection to pass as a parameter to create_dso
        @param item:    python Item object containing all the data and links expected by the REST API
        @return:        Item object constructed from the API response
        """
        url = f"{self.API_ENDPOINT}/core/items"
        if parent is None:
            logging.error("Need a parent UUID!")
            return None
        params = {"owningCollection": parent}
        if not isinstance(item, Item):
            logging.error("Need a valid item")
            return None
        return Item(
            api_resource=parse_json(
                self.create_dso(url, params=params, data=item.as_dict())
            )
        )

    def update_item(self, item):
        """
        Update item. The Item passed to this method contains all the data, identifiers, links necessary to
        perform the update to the API. Note this is a full update, not a patch / partial update operation.
        @param item: python Item object
        @return:
        """
        if not isinstance(item, Item):
            logging.error("Need a valid item")
            return None
        return self.update_dso(item, params=None)

    def patch_item(self, uuid, operation, path, value):
        """
        Patch item. The Item passed to this method contains all the data, identifiers, links necessary to
        perform the patch to the API. Note this is a partial update, not a full update operation.
        @param item: python Item object
        @param data: JSON data to patch
        @return:
        """
        url = f"{self.API_ENDPOINT}/core/items"
        try:
            url = f"{url}/{uuid}"
            return self.api_patch(url, operation, path, value, True)
        except ValueError:
            logging.error(f"Invalid item UUID: {uuid}")
            return None

    def delete_item(self, uuid):
        """
        Delete an item
        @param uuid:    UUID of the item to delete
        @return:        True if successful, False if not
        """
        url = f"{self.API_ENDPOINT}/core/items"
        try:
            url = f"{url}/{uuid}"
            return self.api_delete(url, None, None)
        except ValueError:
            logging.error(f"Invalid item UUID: {uuid}")
            return None

    def add_metadata(
        self, dso, field, value, language=None, authority=None, confidence=-1, place=""
    ):
        """
        Add metadata to a DSO using the api_patch method (PUT, with path and operation and value)
        :param dso:
        :param field:
        :param value:
        :param language:
        :param authority:
        :param confidence:
        :param place:
        :return:
        """
        if (
            dso is None
            or field is None
            or value is None
            or not isinstance(dso, DSpaceObject)
        ):
            # TODO: separate these tests, and add better error handling
            logging.error("Invalid or missing DSpace object, field or value string")
            return self

        dso_type = type(dso)

        # Place can be 0+ integer, or a hyphen - meaning "last"
        path = f"/metadata/{field}/{place}"
        patch_value = {
            "value": value,
            "language": language,
            "authority": authority,
            "confidence": confidence,
        }

        url = dso.links["self"]["href"]

        r = self.api_patch(
            url=url, operation=self.PatchOperation.ADD, path=path, value=patch_value
        )

        return dso_type(api_resource=parse_json(r))

    def create_user(self, user, token=None):
        """
        Create a user
        @param user:    python User object or Python dict containing all the data and links expected by the REST API
        :param token:   Token if creating new user (optional) from the link in a registration email
        @return:        User object constructed from the API response
        """
        url = f"{self.API_ENDPOINT}/eperson/epersons"
        data = user
        if isinstance(user, User):
            data = user.as_dict()
            # TODO: Validation. Note, at least here I will just allow a dict instead of the pointless cast<->cast
            # that you see for other DSO types - still figuring out the best way
        params = None
        if token is not None:
            params = {"token": token}
        return User(
            api_resource=parse_json(self.create_dso(url, params=params, data=data))
        )

    def get_eperson_id_of_user(self):
        """
        Get the EPerson ID of the current user
        authn/status response includes the eperson link
        the uuid can be parsed from the eperson link and returned as text
        @return:        String of the user id
        """
        url = f"{self.API_ENDPOINT}/authn/status"
        r = self.api_get(url)
        r_json = parse_json(response=r)
        if "_links" in r_json:
            eperson_href = r_json["_links"]["eperson"]["href"]
            path = urlparse(eperson_href).path
            uuid = os.path.basename(path)
        return uuid

    def get_special_groups_of_user(self):
        """
        Get the special groups of a user
        authn/status/specialGroups
        """
        url = f"{self.API_ENDPOINT}/authn/status/specialGroups"
        r = self.api_get(url)
        r_json = parse_json(response=r)
        if "_embedded" in r_json:
            if "specialGroups" in r_json["_embedded"]:
                groups = []
                for group_resource in r_json["_embedded"]["specialGroups"]:
                    groups.append(Group(group_resource))
                return groups
        return r_json

    def delete_user(self, user):
        if not isinstance(user, User):
            logging.error("Must be a valid user")
            return None
        return self.delete_dso(user)

    # PAGINATION
    def get_users(self, page=0, size=20, sort=None):
        """
        Get users
        @param page:    integer page (default: 0)
        @param size:    integer size (default: 20)
        @param sort:    sort string (default: None)
        """
        url = f"{self.API_ENDPOINT}/eperson/epersons"
        users = []
        params = {}
        if size is not None:
            params["size"] = size
        if page is not None:
            params["page"] = page
        if sort is not None:
            params["sort"] = sort
        r = self.api_get(url, params=params)
        r_json = parse_json(response=r)
        if "_embedded" in r_json:
            if "epersons" in r_json["_embedded"]:
                for user_resource in r_json["_embedded"]["epersons"]:
                    users.append(User(user_resource))
        return users

    def create_group(self, group):
        """
        Create a group
        @param group:    python Group object or Python dict containing all the data and links expected by the REST API
        @return:         User object constructed from the API response
        """
        url = f"{self.API_ENDPOINT}/eperson/groups"
        data = group
        if isinstance(group, Group):
            data = group.as_dict()
            # TODO: Validation. Note, at least here I will just allow a dict instead of the pointless cast<->cast
            # that you see for other DSO types - still figuring out the best way
        return Group(
            api_resource=parse_json(self.create_dso(url, params=None, data=data))
        )

    def start_workflow(self, workspace_item):
        url = f"{self.API_ENDPOINT}/workflow/workflowitems"
        res = parse_json(self.api_post_uri(url, params=None, uri_list=workspace_item))
        logging.debug(res)
        # TODO: WIP

    def update_token(self, r):
        """
        Refresh / update the XSRF (aka. CSRF) token if DSPACE-XSRF-TOKEN found in response headers
        This is used by all the base methods like api_put,
        See: https://github.com/DSpace/RestContract/blob/main/csrf-tokens.md
        :param r:
        :return:
        """
        if not self.session:
            logging.debug("Session state not found, setting...")
            self.session = requests.Session()
        if "DSPACE-XSRF-TOKEN" in r.headers:
            t = r.headers["DSPACE-XSRF-TOKEN"]
            logging.debug(f"Updating XSRF token to {t}")
            # Update headers and cookies
            self.session.headers.update({"X-XSRF-Token": t})
            self.session.cookies.update({"X-XSRF-Token": t})

    def get_short_lived_token(self):
        """
        Get a short-lived (2 min) token in order to request restricted bitstream downloads
        @return: short lived Authorization token
        """
        if not self.session:
            logging.debug("Session state not found, setting...")
            self.session = requests.Session()

        url = f"{self.API_ENDPOINT}/authn/shortlivedtokens"
        r = self.api_post(url, json=None, params=None)
        r_json = parse_json(r)
        if r_json is not None and "token" in r_json:
            return r_json["token"]

        logging.error("Could not retrieve short-lived token")
        return None

    def solr_query(
        self,
        query,
        filters=None,
        fields=None,
        facets=None,
        sort=None,
        minfacests=0,
        start=0,
        rows=999999999,
    ):
        """
        Perform a Solr query
        @param query:       Solr query string
        @param filters:     List of filter queries
        @param fields:      List of fields to return
        @param facets:      List of facet fields
        @param sort:        Sort string
        @param minfacests:  Minimum count for facets
        @param start:       Start index
        @param rows:        Number of rows to return
        @return:            Solr response
        """
        if fields is None:
            fields = []
        if filters is None:
            filters = []
        if facets is None:
            facets = []
        if sort is None:
            sort = "score desc"
        return self.solr.search(
            query,
            fq=filters,
            start=start,
            rows=rows,
            facet="true",
            **{"fl": ",".join(fields)},
            **{"facet.mincount": minfacests},
            **{"facet.field": facets},
            sort=sort,
        )

    def get_config(self, key):
        """
        Get configuration properties from the REST API
        The Angular UI uses this to get configuration properties (eg. registration.verification.enabled).
        """
        url = f"{self.API_ENDPOINT}/config/properties/{key}"
        if key in ["registration.verification.enabled"]:
            return self.api_get(url).json()
        return None
