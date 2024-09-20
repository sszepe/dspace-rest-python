"""
This script initializes a DSpace REST client to interact with a DSpace instance.
It authenticates using credentials provided via environment variables or defaults
defined in the script, and opens an interactive Python shell for further exploration.

Modules used:
- code: Used to start an interactive interpreter session.
- logging: Logs error messages or information.
- os: Provides access to environment variables.
- sys: Handles system-level operations, like exiting the script.
- dspace_rest_client: Client for interacting with a DSpace instance.

Environment Variables:
- DSPACE_API_ENDPOINT: (Optional) The endpoint for the DSpace API.
- DSPACE_API_USERNAME: (Optional) Username for authentication.
- DSPACE_API_PASSWORD: (Optional) Password for authentication.
"""

import code
import logging
import os
import sys

from dspace_rest_client.client import DSpaceClient


# The DSpace client will look for the same environment variables but we can also look for them here explicitly
# and as an example
url = "http://localhost:8080/server/api"
if "DSPACE_API_ENDPOINT" in os.environ:
    url = os.environ["DSPACE_API_ENDPOINT"]
username = "username@test.system.edu"
if "DSPACE_API_USERNAME" in os.environ:
    username = os.environ["DSPACE_API_USERNAME"]
password = "password"
if "DSPACE_API_PASSWORD" in os.environ:
    password = os.environ["DSPACE_API_PASSWORD"]

# Instantiate DSpace client
d = DSpaceClient(api_endpoint=url, username=username, password=password)

# Authenticate against the DSpace client
authenticated = d.authenticate()
if not authenticated:
    logging.info("Error logging in! Giving up.")
    sys.exit(1)

code.interact(local=locals())
