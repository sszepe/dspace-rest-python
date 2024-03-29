# This software is licenced under the BSD 3-Clause licence
# available at https://opensource.org/licenses/BSD-3-Clause
# and described in the LICENCE file in the root of this project

"""
Connection test for the mdwRepository DSpace CRIS REST API
"""

import logging
import os
import sys

from dotenv import load_dotenv

from dspace_rest_client.client import DSpaceClient
from dspace_rest_client.models import Community, Collection, Item, Bundle, Bitstream, User

# Set up logging
logging.basicConfig(level=logging.INFO)

# Load environment variables from .env file
load_dotenv(override=True)

url = os.getenv('DSPACE_API_ENDPOINT')
username = os.getenv('DSPACE_API_USERNAME')
password = os.getenv('DSPACE_API_PASSWORD')
if not url or not username or not password:
    logging.error(f'Error: DSPACE_API_ENDPOINT, DSPACE_API_USERNAME, or DSPACE_API_PASSWORD not set in .env file')
    sys.exit(1)
else:
    logging.info(f'Connecting to DSpace API at {url} as {username}')

d = DSpaceClient(api_endpoint=url, username=username, password=password, fake_user_agent=True)

# Authenticate against the DSpace client
authenticated = d.authenticate()
if not authenticated:
    logging.error(f'Error logging in! Giving up.')
    sys.exit(1)
else:
    logging.info(f'Logged in as {username}')

# Get the current user information
eperson_id = d.get_eperson_id_of_user()
if eperson_id:
    logging.info(f'User ID: {eperson_id}')
else:
    logging.error(f'Error getting user ID')
special_groups = d.get_special_groups_of_user()
if special_groups:
    logging.info(f'Special groups: {special_groups}')
else:
    logging.error(f'No special groups present')

# Log out
d.logout()